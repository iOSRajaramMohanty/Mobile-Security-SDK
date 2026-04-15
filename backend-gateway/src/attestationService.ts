import { createHash, createHmac, randomBytes } from 'node:crypto';

import { GoogleAuth } from 'google-auth-library';
import { verifyAssertion as iosVerifyAssertion, verifyAttestation as iosVerifyAttestation } from 'node-app-attest';

import type { DeviceRepository } from './deviceRepo.js';

export type AttestationPlatform = 'android' | 'ios';

export type AttestationVerifyResult =
  | { ok: true; trusted: true; attestationStatus: string; metadata: Record<string, unknown> }
  | { ok: true; trusted: false; attestationStatus: string; metadata: Record<string, unknown> }
  | { ok: false; reason: string };

export class AttestationService {
  constructor(private readonly repo: DeviceRepository) {}

  private hmacTestVerify(input: {
    token: string;
    expectedNonce: string;
    deviceId: string;
    keyId: string;
    platform: AttestationPlatform;
  }): AttestationVerifyResult {
    // Test-only mode to enable deterministic attestation in local/CI without external providers.
    const isTest = (process.env.NODE_ENV ?? '').toLowerCase() === 'test';
    if (!isTest) return { ok: false, reason: 'attestation_mode_not_configured' };
    const secret = process.env.ATTESTATION_HMAC_SECRET?.trim();
    if (!secret) return { ok: false, reason: 'attestation_mode_not_configured' };
    const expected = base64url(
      createHmac('sha256', secret)
        .update(`stepup|${input.platform}|${input.deviceId}|${input.keyId}|${input.expectedNonce}`, 'utf8')
        .digest(),
    );
    if (input.token !== expected) return { ok: false, reason: 'attestation_invalid' };
    return {
      ok: true,
      trusted: true,
      attestationStatus: 'hmac_test_verified',
      metadata: { integrityLevel: 'strong', deviceId: input.deviceId, keyId: input.keyId, platform: input.platform },
    };
  }

  async issueChallenge(input: { deviceId: string; keyId: string; platform: AttestationPlatform }) {
    const nonce = base64url(randomBytes(32));
    const ttlMs = Number(process.env.ATTESTATION_CHALLENGE_TTL_MS ?? 5 * 60_000);
    const expiresAt = new Date(Date.now() + ttlMs);
    await this.repo.insertAttestationChallenge({
      deviceId: input.deviceId,
      keyId: input.keyId,
      platform: input.platform,
      nonce,
      expiresAt,
    });
    return { nonce, expiresAtMs: expiresAt.getTime() };
  }

  async verifyRegistrationAttestation(input: {
    deviceId: string;
    keyId: string;
    platform: AttestationPlatform;
    attestationToken: string;
  }): Promise<AttestationVerifyResult> {
    const mode = (process.env.ATTESTATION_MODE ?? '').toLowerCase();
    if (mode !== 'play_integrity' && mode !== 'app_attest' && mode !== 'hmac') {
      return { ok: false, reason: 'attestation_mode_not_configured' };
    }

    // Consume challenge (nonce binding) — must exist and be unused.
    const challenge = await this.repo.consumeAttestationChallenge({
      deviceId: input.deviceId,
      keyId: input.keyId,
      platform: input.platform,
    });
    if (!challenge) return { ok: false, reason: 'missing_or_expired_challenge' };

    if (mode === 'play_integrity') {
      if (input.platform !== 'android') return { ok: false, reason: 'platform_mismatch' };
      return await this.verifyPlayIntegrity({
        token: input.attestationToken,
        expectedNonce: challenge.nonce,
        keyId: input.keyId,
        deviceId: input.deviceId,
      });
    }

    if (mode === 'app_attest') {
      if (input.platform !== 'ios') return { ok: false, reason: 'platform_mismatch' };
      return await this.verifyAppAttest({
        attestationPayload: input.attestationToken,
        expectedChallenge: challenge.nonce,
        keyId: input.keyId,
        deviceId: input.deviceId,
      });
    }

    if (mode === 'hmac') {
      return this.hmacTestVerify({
        token: input.attestationToken,
        expectedNonce: challenge.nonce,
        deviceId: input.deviceId,
        keyId: input.keyId,
        platform: input.platform,
      });
    }

    return { ok: false, reason: 'unsupported_attestation_mode' };
  }

  async verifyStepUpAttestation(input: {
    deviceId: string;
    keyId: string;
    platform: AttestationPlatform;
    attestationToken: string;
    expectedChallenge: string;
  }): Promise<AttestationVerifyResult> {
    const mode = (process.env.ATTESTATION_MODE ?? '').toLowerCase();
    if (mode !== 'play_integrity' && mode !== 'app_attest' && mode !== 'hmac') {
      return { ok: false, reason: 'attestation_mode_not_configured' };
    }

    if (mode === 'play_integrity') {
      if (input.platform !== 'android') return { ok: false, reason: 'platform_mismatch' };
      return await this.verifyPlayIntegrity({
        token: input.attestationToken,
        expectedNonce: input.expectedChallenge,
        keyId: input.keyId,
        deviceId: input.deviceId,
      });
    }

    if (mode === 'app_attest') {
      if (input.platform !== 'ios') return { ok: false, reason: 'platform_mismatch' };
      return await this.verifyAppAttest({
        attestationPayload: input.attestationToken,
        expectedChallenge: input.expectedChallenge,
        keyId: input.keyId,
        deviceId: input.deviceId,
      });
    }

    if (mode === 'hmac') {
      return this.hmacTestVerify({
        token: input.attestationToken,
        expectedNonce: input.expectedChallenge,
        deviceId: input.deviceId,
        keyId: input.keyId,
        platform: input.platform,
      });
    }

    return { ok: false, reason: 'unsupported_attestation_mode' };
  }

  private async verifyPlayIntegrity(input: {
    token: string;
    expectedNonce: string;
    deviceId: string;
    keyId: string;
  }): Promise<AttestationVerifyResult> {
    const packageName = process.env.PLAY_INTEGRITY_PACKAGE_NAME;
    const allowedCertDigests = (process.env.PLAY_INTEGRITY_CERT_SHA256_DIGESTS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const requireDeviceIntegrity = (process.env.PLAY_INTEGRITY_REQUIRE_DEVICE_INTEGRITY ?? '1') === '1';
    const requireStrongIntegrity = (process.env.PLAY_INTEGRITY_REQUIRE_STRONG_INTEGRITY ?? '1') === '1';

    if (!packageName || allowedCertDigests.length === 0) {
      return { ok: false, reason: 'play_integrity_not_configured' };
    }

    const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    const saPath = process.env.GOOGLE_SERVICE_ACCOUNT_PATH;
    if (!saJson && !saPath) return { ok: false, reason: 'google_service_account_not_configured' };

    const auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/playintegrity'],
      credentials: saJson ? JSON.parse(saJson) : undefined,
      keyFile: saPath || undefined,
    });
    const client = await auth.getClient();
    const accessToken = await client.getAccessToken();
    if (!accessToken?.token) return { ok: false, reason: 'google_auth_failed' };

    const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ integrityToken: input.token }),
    });
    if (!resp.ok) return { ok: false, reason: 'play_integrity_decode_failed' };
    const data = (await resp.json()) as any;
    const payload = data?.tokenPayloadExternal;
    if (!payload) return { ok: false, reason: 'play_integrity_invalid_payload' };

    const nonce = payload?.requestDetails?.nonce;
    if (nonce !== input.expectedNonce) return { ok: false, reason: 'nonce_mismatch' };

    const pkg = payload?.appIntegrity?.packageName;
    if (pkg !== packageName) return { ok: false, reason: 'package_mismatch' };

    const certDigests = payload?.appIntegrity?.certificateSha256Digest ?? [];
    const certOk = Array.isArray(certDigests) && certDigests.some((d: string) => allowedCertDigests.includes(d));
    if (!certOk) return { ok: false, reason: 'cert_digest_mismatch' };

    const deviceVerdicts = payload?.deviceIntegrity?.deviceRecognitionVerdict ?? [];
    const hasDeviceIntegrity = Array.isArray(deviceVerdicts) && deviceVerdicts.includes('MEETS_DEVICE_INTEGRITY');
    const hasStrong = Array.isArray(deviceVerdicts) && deviceVerdicts.includes('MEETS_STRONG_INTEGRITY');
    if (requireDeviceIntegrity && !hasDeviceIntegrity) return { ok: false, reason: 'device_integrity_failed' };
    if (requireStrongIntegrity && !hasStrong) return { ok: false, reason: 'strong_integrity_failed' };

    const integrityLevel = hasStrong ? 'strong' : hasDeviceIntegrity ? 'device' : 'unknown';

    return {
      ok: true,
      trusted: true,
      attestationStatus: 'play_integrity_verified',
      metadata: {
        deviceId: input.deviceId,
        keyId: input.keyId,
        integrityLevel,
        deviceRecognitionVerdict: deviceVerdicts,
      },
    };
  }

  private async verifyAppAttest(input: {
    attestationPayload: string;
    expectedChallenge: string;
    deviceId: string;
    keyId: string;
  }): Promise<AttestationVerifyResult> {
    const teamId = process.env.APP_ATTEST_TEAM_ID;
    const bundleId = process.env.APP_ATTEST_BUNDLE_ID;
    if (!teamId || !bundleId) return { ok: false, reason: 'app_attest_not_configured' };

    // Expect JSON payload containing both attestation and assertion.
    // {
    //   attestationObjectBase64: string,
    //   assertionBase64: string,
    //   payloadBase64: string (should equal base64(challengeBytes)),
    //   previousSignCount?: number
    // }
    let parsed: any;
    try {
      parsed = JSON.parse(input.attestationPayload);
    } catch {
      return { ok: false, reason: 'app_attest_invalid_payload' };
    }
    const attObjB64 = parsed?.attestationObjectBase64;
    const assertionB64 = parsed?.assertionBase64;
    const payloadB64 = parsed?.payloadBase64;
    if (typeof attObjB64 !== 'string' || typeof assertionB64 !== 'string' || typeof payloadB64 !== 'string') {
      return { ok: false, reason: 'app_attest_invalid_payload' };
    }

    // node-app-attest expects the exact challenge bytes used on the client.
    const challenge = Buffer.from(input.expectedChallenge, 'utf8');
    const attObj = Buffer.from(attObjB64, 'base64');
    const assertion = Buffer.from(assertionB64, 'base64');
    const payload = Buffer.from(payloadB64, 'base64');
    if (!payload.equals(challenge)) return { ok: false, reason: 'nonce_mismatch' };

    try {
      const out = await iosVerifyAttestation({
        attestationObject: attObj,
        challenge,
        teamIdentifier: teamId,
        bundleIdentifier: bundleId,
      } as any);

      // Verify assertion to prevent replay and ensure key binding to payload.
      const pem = out?.publicKey;
      if (typeof pem !== 'string' || pem.length < 20) {
        return { ok: false, reason: 'app_attest_missing_public_key' };
      }
      const prev = typeof parsed?.previousSignCount === 'number' ? parsed.previousSignCount : 0;
      const assertionOut = iosVerifyAssertion({
        assertion,
        payload,
        publicKey: pem,
        bundleIdentifier: bundleId,
        teamIdentifier: teamId,
        signCount: prev,
      } as any);

      return {
        ok: true,
        trusted: true,
        attestationStatus: 'app_attest_verified',
        metadata: {
          deviceId: input.deviceId,
          keyId: input.keyId,
          integrityLevel: 'app_attest',
          appAttestKeyId: hashBase64url(out?.keyId ?? Buffer.from('')),
          appAttestSignCount: assertionOut?.signCount ?? null,
          appAttestPublicKeyPem: pem,
        },
      };
    } catch {
      return { ok: false, reason: 'app_attest_verification_failed' };
    }
  }
}

function base64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function hashBase64url(buf: Buffer): string {
  return base64url(createHash('sha256').update(buf).digest());
}

