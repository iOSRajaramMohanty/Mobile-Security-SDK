import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { createHash } from 'node:crypto';
import {
  encryptResponseWithDek,
  verifyAndDecryptEnvelopeForForwarding,
  verifyEnvelopeSignature,
} from './secureEnvelope.js';
import { createNonceStore } from './nonceStore.js';
import {
  secureEnvelopeValidator,
  type RequestWithEnvelope,
} from './middleware/secureEnvelopeValidator.js';
import { parseRegisterDeviceInput } from './middleware/registerDeviceValidator.js';
import { createDb } from './db.js';
import { PgDeviceRepository } from './deviceRepo.js';
import { DeviceService } from './deviceService.js';
import { AttestationService } from './attestationService.js';
import {
  httpMetricsMiddleware,
  logEvent,
  metrics,
  metricsHandler,
  requestContextMiddleware,
} from './observability.js';
import { createForwardingConfigFromEnv, forwardToInternalService } from './forwarding.js';
import { createDeviceRateLimiter } from './deviceRateLimiter.js';
import { evaluateTrustPolicy } from './middleware/trustPolicy.js';
import { assertProductionConfig } from './config.js';
import { buildStepUpMessage, createStepUpStore } from './stepUp.js';
import { createStepUpAbuseGate } from './stepUpAbuse.js';

const port = Number(process.env.PORT ?? 8443);

/** Max |now - client timestamp| (default 30s per security spec). */
const TIMESTAMP_SKEW_MS = Number(process.env.TIMESTAMP_SKEW_MS ?? 30_000);

/** How long a nonce is remembered (should cover clock skew both ways). */
const NONCE_TTL_MS = Number(
  process.env.NONCE_TTL_MS ?? 60_000,
);

function optionalHealthAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const token = process.env.HEALTH_TOKEN?.trim();
  if (!token) {
    next();
    return;
  }
  const h = req.headers.authorization;
  if (h !== `Bearer ${token}`) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  next();
}

async function main(): Promise<void> {
  // Fail-fast security checks for production deployments.
  assertProductionConfig();

  const { store: nonceStore, close: closeNonceStore } = await createNonceStore();
  const deviceRateLimiter = await createDeviceRateLimiter();
  const stepUpStore = await createStepUpStore();
  const stepUpAbuseGate = await createStepUpAbuseGate();
  const db = createDb();
  const repo = new PgDeviceRepository(db.pool);
  const deviceService = new DeviceService(repo);
  const attestationService = new AttestationService(repo);
  const forwardCfg = createForwardingConfigFromEnv();
  const prod = (process.env.NODE_ENV ?? '').toLowerCase() === 'production';
  if (prod && !forwardCfg.ok) {
    throw new Error(`forwarding_config_invalid:${forwardCfg.reason}`);
  }

  const deviceRateWindowMs = Number(process.env.DEVICE_RATE_LIMIT_WINDOW_MS ?? 60_000);
  const deviceRateMax = Number(process.env.DEVICE_RATE_LIMIT_MAX ?? 120);
  const registerRateWindowMs = Number(process.env.REGISTER_RATE_LIMIT_WINDOW_MS ?? 60_000);
  const registerRateMax = Number(process.env.REGISTER_RATE_LIMIT_MAX ?? 20);

  const app = express();
  app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS ?? 1));
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(requestContextMiddleware);
  app.use(express.json({ limit: '512kb' }));
  app.use(httpMetricsMiddleware);

  const secureRateLimit = rateLimit({
    windowMs: Number(process.env.SECURE_RATE_LIMIT_WINDOW_MS ?? 60_000),
    max: Number(process.env.SECURE_RATE_LIMIT_MAX ?? 120),
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      const maybe = (req as Partial<RequestWithEnvelope>).validatedEnvelope?.keyId;
      return maybe && typeof maybe === 'string' ? maybe : req.ip || 'unknown';
    },
  });

  app.get('/health', optionalHealthAuth, (_req, res) => {
    res.json({ status: 'ok', service: 'backend-gateway' });
  });

  app.get('/metrics', optionalHealthAuth, async (req, res) => {
    // Optional extra guard (beyond HEALTH_TOKEN): METRICS_TOKEN
    const token = process.env.METRICS_TOKEN?.trim();
    if (token) {
      const h = req.headers.authorization;
      if (h !== `Bearer ${token}`) {
        res.status(401).json({ error: 'unauthorized' });
        return;
      }
    }
    await metricsHandler(req, res);
  });

  app.post('/v1/attestation-challenge', async (req, res) => {
    const parsed = parseRegisterDeviceInput(req.body);
    if (!parsed.ok) {
      res.status(400).json({ ok: false, reason: parsed.reason });
      return;
    }
    try {
      const spkiDer = Buffer.from(parsed.value.devicePublicKey, 'base64');
      const keyId = cryptoKeyIdFromSpkiDer(spkiDer);
      const platform = (parsed.value.platform ?? 'unknown') === 'ios' ? 'ios' : 'android';
      const out = await attestationService.issueChallenge({
        deviceId: parsed.value.deviceId,
        keyId,
        platform,
      });
      res.json({ ok: true, keyId, nonce: out.nonce, expiresAtMs: out.expiresAtMs });
    } catch {
      logEvent('attestation_failure', {
        requestId: req._ctx?.requestId,
        route: '/v1/attestation-challenge',
        reason: 'challenge_failed',
      });
      res.status(400).json({ ok: false, reason: 'challenge_failed' });
    }
  });

  app.post('/v1/register-device', async (req, res) => {
    const parsed = parseRegisterDeviceInput(req.body);
    if (!parsed.ok) {
      res.status(400).json({ ok: false, reason: parsed.reason });
      return;
    }

    try {
      // Rate limit registration attempts per deviceId (stricter).
      {
        const rl = await deviceRateLimiter.check({
          endpoint: 'register-device',
          deviceId: parsed.value.deviceId,
          windowMs: registerRateWindowMs,
          max: registerRateMax,
        });
        if (!rl.ok) {
          res.status(429).json({ ok: false, reason: 'rate_limited' });
          return;
        }
      }

      const spkiDer = Buffer.from(parsed.value.devicePublicKey, 'base64');
      const keyId = cryptoKeyIdFromSpkiDer(spkiDer);

      const out = await deviceService.registerDevice({
        deviceId: parsed.value.deviceId,
        keyId,
        publicKeySpkiDer: spkiDer,
        platform: parsed.value.platform ?? 'unknown',
      });

      const requireAtt = process.env.REQUIRE_ATTESTATION === '1';
      if (!parsed.value.attestationToken) {
        if (requireAtt) {
          logEvent('attestation_failure', {
            requestId: req._ctx?.requestId,
            route: '/v1/register-device',
            keyId,
            reason: 'missing_attestation',
          });
          res.status(401).json({ ok: false, reason: 'missing_attestation' });
          return;
        }
        res.json({ ok: true, status: out.status, keyId, trusted: false });
        return;
      }

      const platform = (parsed.value.platform ?? 'unknown') === 'ios' ? 'ios' : 'android';
      const att = await attestationService.verifyRegistrationAttestation({
        deviceId: parsed.value.deviceId,
        keyId,
        platform,
        attestationToken: parsed.value.attestationToken,
      });
      if (!att.ok) {
        metrics.securityEventsTotal.labels('attestation_failure').inc();
        logEvent('attestation_failure', {
          requestId: req._ctx?.requestId,
          route: '/v1/register-device',
          keyId,
          reason: att.reason,
        });
        res.status(401).json({ ok: false, reason: att.reason });
        return;
      }
      if (att.trusted) {
        await deviceService.setAttestationDetails({
          keyId,
          trusted: true,
          attestationStatus: att.attestationStatus,
          integrityLevel: (att.metadata?.integrityLevel as string | undefined) ?? null,
          verifiedAt: new Date(),
          appAttestPublicKeyPem: (att.metadata?.appAttestPublicKeyPem as string | undefined) ?? null,
          appAttestSignCount:
            typeof att.metadata?.appAttestSignCount === 'number'
              ? BigInt(att.metadata.appAttestSignCount)
              : null,
          metadata: att.metadata,
        });
      }
      res.json({ ok: true, status: out.status, keyId, trusted: att.trusted });
    } catch {
      res.status(400).json({ ok: false, reason: 'invalid_devicePublicKey' });
    }
  });

  app.post('/v1/stepup-verify', async (req, res) => {
    // Defense-in-depth IP throttling (optional).
    const ipMax = Number(process.env.STEPUP_IP_RATE_LIMIT_MAX ?? 60);
    const ipWindowMs = Number(process.env.STEPUP_IP_RATE_LIMIT_WINDOW_MS ?? 60_000);
    // Cheap token-bucket in memory (best effort). Use WAF/LB for real IP throttling.
    // (Using express-rate-limit here would require it in middleware chain; keep it simple.)
    const ip = req.ip || 'unknown';
    (globalThis as any).__stepupIpHits ??= new Map();
    const ipHits: Map<string, number[]> = (globalThis as any).__stepupIpHits;
    const nowIp = Date.now();
    const cutoffIp = nowIp - ipWindowMs;
    const arrIp = (ipHits.get(ip) ?? []).filter((t) => t >= cutoffIp);
    arrIp.push(nowIp);
    ipHits.set(ip, arrIp);
    if (arrIp.length > ipMax) {
      res.status(429).json({ ok: false, reason: 'rate_limited' });
      return;
    }

    const body = req.body as Record<string, unknown>;
    const keyId = typeof body?.keyId === 'string' ? body.keyId : '';
    const deviceId = typeof body?.deviceId === 'string' ? body.deviceId : '';
    const reqPath = typeof body?.path === 'string' ? body.path : '';
    const method = typeof body?.method === 'string' ? body.method : '';
    const payloadHash = typeof body?.payloadHash === 'string' ? body.payloadHash : '';
    const challenge = typeof body?.challenge === 'string' ? body.challenge : '';
    const platform = typeof body?.platform === 'string' ? body.platform : '';
    const attestationToken = typeof body?.attestationToken === 'string' ? body.attestationToken : '';
    const signatureBase64 = typeof body?.signature === 'string' ? body.signature : '';
    if (!keyId || !deviceId || !reqPath || !method || !payloadHash || !challenge || !signatureBase64) {
      res.status(400).json({ ok: false, reason: 'invalid_stepup_request' });
      return;
    }

    metrics.stepupVerifyAttempts.inc();

    // Strict per-deviceId rate limiting (lower threshold than /v1/secure).
    {
      const stepupWindowMs = Number(process.env.STEPUP_VERIFY_RATE_LIMIT_WINDOW_MS ?? 60_000);
      const stepupMax = Number(process.env.STEPUP_VERIFY_RATE_LIMIT_MAX ?? 20);
      const rl = await deviceRateLimiter.check({
        endpoint: 'stepup-verify',
        deviceId,
        windowMs: stepupWindowMs,
        max: stepupMax,
      });
      if (!rl.ok) {
        metrics.stepupVerifyFailures.labels('rate_limited').inc();
        logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'rate_limited' });
        res.status(429).json({ ok: false, reason: 'rate_limited' });
        return;
      }
    }

    // Abuse detection: repeated failures cause temporary blocking.
    if (await stepUpAbuseGate.isBlocked(deviceId)) {
      metrics.stepupVerifyFailures.labels('blocked').inc();
      logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'blocked' });
      res.status(429).json({ ok: false, reason: 'rate_limited' });
      return;
    }

    const rec = await deviceService.verifyDevice(keyId);
    if (!rec) {
      metrics.stepupVerifyFailures.labels('unknown_key').inc();
      await stepUpAbuseGate.recordFailure(deviceId);
      logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'unknown_key' });
      res.status(401).json({ ok: false, reason: 'unknown_key' });
      return;
    }
    if (rec.deviceId !== deviceId) {
      metrics.stepupVerifyFailures.labels('device_mismatch').inc();
      await stepUpAbuseGate.recordFailure(deviceId);
      logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'device_mismatch' });
      res.status(401).json({ ok: false, reason: 'device_mismatch' });
      return;
    }

    const msg = buildStepUpMessage({ keyId, method, path: reqPath, payloadHash, challenge });
    const sig = Buffer.from(signatureBase64.replace(/\s/g, ''), 'base64');
    try {
      const { createPublicKey, verify } = await import('node:crypto');
      const pub = createPublicKey({ key: rec.publicKeySpkiDer, format: 'der', type: 'spki' });
      const okSig = verify('sha256', msg, pub, sig);
      if (!okSig) {
        metrics.stepupVerifyFailures.labels('bad_signature').inc();
        await stepUpAbuseGate.recordFailure(deviceId);
        logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'bad_signature' });
        res.status(401).json({ ok: false, reason: 'bad_signature' });
        return;
      }
    } catch {
      metrics.stepupVerifyFailures.labels('invalid_key').inc();
      await stepUpAbuseGate.recordFailure(deviceId);
      logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'invalid_key' });
      res.status(400).json({ ok: false, reason: 'invalid_key' });
      return;
    }

    // Optional: require attestation for step-up verification (bind to the step-up challenge).
    const requireStepUpAttestation = process.env.STEPUP_REQUIRE_ATTESTATION === '1';
    if (requireStepUpAttestation) {
      if (!attestationToken) {
        metrics.stepupVerifyFailures.labels('missing_attestation').inc();
        await stepUpAbuseGate.recordFailure(deviceId);
        logEvent('step_up_failed', {
          requestId: req._ctx?.requestId,
          route: '/v1/stepup-verify',
          keyId,
          deviceId,
          path: reqPath,
          result: 'missing_attestation',
        });
        res.status(401).json({ ok: false, reason: 'missing_attestation' });
        return;
      }
      const attPlatform = platform === 'ios' ? 'ios' : platform === 'android' ? 'android' : null;
      if (!attPlatform) {
        metrics.stepupVerifyFailures.labels('invalid_platform').inc();
        await stepUpAbuseGate.recordFailure(deviceId);
        logEvent('step_up_failed', {
          requestId: req._ctx?.requestId,
          route: '/v1/stepup-verify',
          keyId,
          deviceId,
          path: reqPath,
          result: 'invalid_platform',
        });
        res.status(400).json({ ok: false, reason: 'invalid_platform' });
        return;
      }

      const att = await attestationService.verifyStepUpAttestation({
        deviceId,
        keyId,
        platform: attPlatform,
        attestationToken,
        expectedChallenge: challenge,
      });
      if (!att.ok || !att.trusted) {
        const reason = !att.ok ? att.reason : 'untrusted_attestation';
        metrics.stepupVerifyFailures.labels(reason).inc();
        await stepUpAbuseGate.recordFailure(deviceId);
        logEvent('step_up_failed', {
          requestId: req._ctx?.requestId,
          route: '/v1/stepup-verify',
          keyId,
          deviceId,
          path: reqPath,
          result: reason,
        });
        res.status(401).json({ ok: false, reason });
        return;
      }
    }

    // Consume challenge LAST so missing/invalid attestation (or bad signature) doesn't burn it.
    const okCh = await stepUpStore.consumeChallenge({ keyId, deviceId, method, path: reqPath, payloadHash, challenge });
    if (!okCh) {
      metrics.stepupVerifyFailures.labels('invalid_or_expired_challenge').inc();
      await stepUpAbuseGate.recordFailure(deviceId);
      logEvent('step_up_failed', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'invalid_or_expired_challenge' });
      res.status(401).json({ ok: false, reason: 'invalid_or_expired_challenge' });
      return;
    }

    const ttlMs = Number(process.env.STEPUP_TOKEN_TTL_MS ?? 5 * 60_000);
    const token = await stepUpStore.issueToken({
      keyId,
      deviceId,
      method,
      path: reqPath,
      payloadHash,
      expiresAtMs: Date.now() + ttlMs,
    });
    logEvent('step_up_verified', { requestId: req._ctx?.requestId, route: '/v1/stepup-verify', keyId, deviceId, path: reqPath, result: 'ok' });
    res.json({ ok: true, stepUpToken: token, expiresInMs: ttlMs });
  });

  app.post(
    '/v1/secure',
    secureEnvelopeValidator,
    secureRateLimit,
    async (req, res) => {
      const pem =
        process.env.SERVER_EC_PRIVATE_PEM_B64
          ? Buffer.from(process.env.SERVER_EC_PRIVATE_PEM_B64, 'base64').toString('utf8')
          : process.env.SERVER_EC_PRIVATE_PEM;
      if (!pem) {
        res.status(503).json({ error: 'SERVER_EC_PRIVATE_PEM not configured' });
        return;
      }

      const env = (req as RequestWithEnvelope).validatedEnvelope;
      const now = Date.now();
      if (Math.abs(now - env.timestampMs) > TIMESTAMP_SKEW_MS) {
        res.status(400).json({ ok: false, reason: 'stale_timestamp' });
        return;
      }

      const accepted = await nonceStore.acceptOnce(env.keyId, env.nonce, NONCE_TTL_MS);
      if (!accepted) {
        metrics.securityEventsTotal.labels('replay_detected').inc();
        metrics.secureRejectionsTotal.labels('replay').inc();
        logEvent('replay_detected', {
          requestId: req._ctx?.requestId,
          route: '/v1/secure',
          keyId: env.keyId,
        });
        res.status(400).json({ ok: false, reason: 'replay' });
        return;
      }

      const rec = await deviceService.verifyDevice(env.keyId);
      if (!rec) {
        metrics.securityEventsTotal.labels('unknown_key').inc();
        metrics.secureRejectionsTotal.labels('unknown_key').inc();
        logEvent('unknown_key', {
          requestId: req._ctx?.requestId,
          route: '/v1/secure',
          keyId: env.keyId,
        });
        res.status(401).json({ ok: false, reason: 'unknown_key' });
        return;
      }

      // Rate limit per deviceId (post-registry lookup). Redis-backed when REDIS_URL is set.
      {
        const rl = await deviceRateLimiter.check({
          endpoint: 'secure',
          deviceId: rec.deviceId,
          windowMs: deviceRateWindowMs,
          max: deviceRateMax,
        });
        if (!rl.ok) {
          metrics.secureRejectionsTotal.labels('device_rate_limited').inc();
          res.status(429).json({ ok: false, reason: 'rate_limited' });
          return;
        }
      }

      // Verify signature before acting on riskScore or decrypting.
      const sigOk = verifyEnvelopeSignature(env, rec.publicKeySpkiDer.toString('base64'));
      if (!sigOk.ok) {
        metrics.securityEventsTotal.labels('signature_failure').inc();
        metrics.secureRejectionsTotal.labels(sigOk.reason).inc();
        logEvent('signature_failure', {
          requestId: req._ctx?.requestId,
          route: '/v1/secure',
          keyId: env.keyId,
          reason: sigOk.reason,
        });
        res.status(400).json({ ok: false, reason: sigOk.reason });
        return;
      }

      metrics.riskScoreHistogram.observe(env.riskScore);

      // riskScore is telemetry only. Trust policy gates sensitive endpoints using server-side state.
      if (env.riskScore >= Number(process.env.RISK_FLAG_THRESHOLD ?? 50)) {
        logEvent('high_risk_device', {
          requestId: req._ctx?.requestId,
          route: '/v1/secure',
          keyId: env.keyId,
          riskScore: env.riskScore,
          trusted: rec.trusted,
          level: env.riskScore >= Number(process.env.RISK_STEPUP_THRESHOLD ?? 80) ? 'high' : 'medium',
        });
      }

      const trust = evaluateTrustPolicy({ env, device: rec, nowMs: Date.now() });
      if (!trust.ok) {
        if (trust.reason === 'step_up_required') {
          // Bind step-up challenge/token to the exact request payload (recommended for POST).
          const outForHash = verifyAndDecryptEnvelopeForForwarding(env, pem, rec.publicKeySpkiDer.toString('base64'));
          if (!outForHash.ok) {
            metrics.secureRejectionsTotal.labels(outForHash.reason).inc();
            res.status(400).json({ ok: false, reason: outForHash.reason });
            return;
          }
          const payloadHash = createHash('sha256').update(outForHash.plaintext, 'utf8').digest()
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');

          const provided = String(req.headers['x-stepup-token'] ?? '').trim();
          if (provided) {
            const okTok = await stepUpStore.consumeToken({
              token: provided,
              keyId: env.keyId,
              deviceId: rec.deviceId,
              method: env.method,
              path: env.path,
              payloadHash,
            });
            if (okTok) {
              logEvent('step_up_token_used', { requestId: req._ctx?.requestId, route: '/v1/secure', keyId: env.keyId, deviceId: rec.deviceId, path: env.path, result: 'ok' });
              // continue (step-up satisfied)
            } else {
              metrics.secureRejectionsTotal.labels('step_up_required').inc();
              const ttl = Number(process.env.STEPUP_CHALLENGE_TTL_MS ?? 2 * 60_000);
              const ch = await stepUpStore.issueChallenge({
                keyId: env.keyId,
                deviceId: rec.deviceId,
                method: env.method,
                path: env.path,
                payloadHash,
                ttlMs: ttl,
              });
              logEvent('step_up_required', { requestId: req._ctx?.requestId, route: '/v1/secure', keyId: env.keyId, deviceId: rec.deviceId, path: env.path, result: 'token_invalid' });
              res.status(403).json({
                ok: false,
                reason: 'step_up_required',
                stepUpRequired: true,
                keyId: env.keyId,
                deviceId: rec.deviceId,
                method: env.method,
                path: env.path,
                payloadHash,
                challenge: ch.challenge,
                expiresAtMs: ch.expiresAtMs,
              });
              return;
            }
          } else {
            metrics.secureRejectionsTotal.labels('step_up_required').inc();
            const ttl = Number(process.env.STEPUP_CHALLENGE_TTL_MS ?? 2 * 60_000);
            const ch = await stepUpStore.issueChallenge({
              keyId: env.keyId,
              deviceId: rec.deviceId,
              method: env.method,
              path: env.path,
              payloadHash,
              ttlMs: ttl,
            });
            logEvent('step_up_required', { requestId: req._ctx?.requestId, route: '/v1/secure', keyId: env.keyId, deviceId: rec.deviceId, path: env.path, result: 'no_token' });
            res.status(403).json({
              ok: false,
              reason: 'step_up_required',
              stepUpRequired: true,
              keyId: env.keyId,
              deviceId: rec.deviceId,
              method: env.method,
              path: env.path,
              payloadHash,
              challenge: ch.challenge,
              expiresAtMs: ch.expiresAtMs,
            });
            return;
          }
        } else {
          metrics.secureRejectionsTotal.labels(trust.reason).inc();
          res.status(trust.status).json({ ok: false, reason: trust.reason });
          return;
        }
      }

      // Decrypt payload (plaintext must never leave the gateway).
      const out = verifyAndDecryptEnvelopeForForwarding(env, pem, rec.publicKeySpkiDer.toString('base64'));
      if (!out.ok) {
        metrics.secureRejectionsTotal.labels(out.reason).inc();
        res.status(400).json({ ok: false, reason: out.reason });
        return;
      }

      if (out.plaintext.length > (forwardCfg.ok ? forwardCfg.value.maxPlaintextBytes * 2 : 256 * 1024 * 2)) {
        res.status(413).json({ ok: false, reason: 'plaintext_too_large' });
        return;
      }
      let payload: unknown;
      try {
        payload = JSON.parse(out.plaintext);
      } catch {
        res.status(400).json({ ok: false, reason: 'invalid_plaintext_json' });
        return;
      }

      // Defense-in-depth: _clientDek must never cross device boundary.
      if (
        typeof payload === 'object' &&
        payload !== null &&
        !Array.isArray(payload) &&
        Object.prototype.hasOwnProperty.call(payload, '_clientDek')
      ) {
        res.status(400).json({ ok: false, reason: 'client_dek_present' });
        return;
      }

      if (!forwardCfg.ok) {
        res.status(503).json({ ok: false, reason: forwardCfg.reason });
        return;
      }

      const fwd = await forwardToInternalService({
        cfg: forwardCfg.value,
        path: env.path,
        payload,
        requestId: req._ctx?.requestId,
        device: {
          keyId: env.keyId,
          deviceId: rec.deviceId,
          trusted: rec.trusted,
          attestationStatus: rec.attestationStatus,
        },
      });
      if (!fwd.ok) {
        res.status(fwd.status ?? 502).json({ ok: false, reason: fwd.reason });
        return;
      }

      const enc = encryptResponseWithDek(out.dekBase64, JSON.stringify(fwd.json));
      if (!enc.ok) {
        res.status(500).json({ ok: false, reason: 'response_encrypt_failed' });
        return;
      }
      res.json({
        ok: true,
        statusCode: fwd.status,
        headers: { 'Content-Type': 'application/json' },
        enc: { aesIv: enc.aesIv, ciphertext: enc.ciphertext, aesTag: enc.aesTag },
      });
    },
  );

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  const server = app.listen(port, () => {
    console.log(`backend-gateway listening on ${port}`);
  });

  const shutdown = async (signal: string) => {
    console.log(`backend-gateway ${signal}, closing`);
    server.close();
    await closeNonceStore();
    await deviceRateLimiter.close();
    await stepUpStore.close();
    await stepUpAbuseGate.close();
    await db.close();
    process.exit(0);
  };
  process.once('SIGINT', () => void shutdown('SIGINT'));
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

function cryptoKeyIdFromSpkiDer(spkiDer: Buffer): string {
  const h = createHash('sha256').update(spkiDer).digest();
  return h
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}
