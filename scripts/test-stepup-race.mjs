#!/usr/bin/env node
/**
 * Concurrency test: a step-up token must be one-time use.
 *
 * Flow:
 * - start local upstream + backend-gateway (NODE_ENV=test)
 * - enroll a device (no attestation required for this test)
 * - trigger step-up (high risk)
 * - obtain ONE step-up token
 * - send 2 concurrent /v1/secure retries with the SAME token
 * Expected: exactly 1 succeeds.
 */

import { spawn } from 'node:child_process';
import { spawnSync } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const backendDir = path.join(root, 'backend-gateway');

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function base64(buf) {
  return Buffer.from(buf).toString('base64');
}

function base64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function runHttpJson(method, url, body, headers = {}) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const data = body ? Buffer.from(JSON.stringify(body), 'utf8') : Buffer.alloc(0);
    const req = http.request(
      {
        method,
        hostname: u.hostname,
        port: Number(u.port || 80),
        path: u.pathname + (u.search || ''),
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(data.length),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = raw ? JSON.parse(raw) : null;
          } catch {
            // ignore
          }
          resolve({ status: res.statusCode || 0, json, raw });
        });
      },
    );
    req.on('error', (e) => resolve({ status: 0, json: null, raw: String(e) }));
    req.end(data);
  });
}

function hkdfDerive(ikm, info, length) {
  const salt = Buffer.alloc(32);
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0);
  let tPrev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const h = crypto.createHmac('sha256', prk);
    h.update(tPrev);
    h.update(Buffer.from(info, 'utf8'));
    h.update(Buffer.from([i]));
    tPrev = h.digest();
    okm = Buffer.concat([okm, tPrev]);
  }
  return okm.subarray(0, length);
}

function aesGcmEncrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: ct, tag };
}

function buildCanonical(env) {
  const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0, 0);
    return b;
  };
  const i64 = (n) => {
    const b = Buffer.alloc(8);
    b.writeBigInt64BE(BigInt(n), 0);
    return b;
  };
  const methodB = Buffer.from(env.method, 'utf8');
  const hostB = Buffer.from(env.host, 'utf8');
  const ctB = Buffer.from(env.contentType, 'utf8');
  const keyIdB = Buffer.from(env.keyId, 'utf8');
  const pathB = Buffer.from(env.path, 'utf8');

  const nonce = Buffer.from(env.nonce, 'base64');
  const pIv = Buffer.from(env.aesIv, 'base64');
  const pCt = Buffer.from(env.ciphertext, 'base64');
  const pTag = Buffer.from(env.aesTag, 'base64');
  const wIv = Buffer.from(env.wrappedDekIv, 'base64');
  const wCt = Buffer.from(env.wrappedDekCipher, 'base64');
  const wTag = Buffer.from(env.wrappedDekTag, 'base64');
  const eph = Buffer.from(env.ephemeralPublicSpki, 'base64');

  const pay = Buffer.concat([pIv, pCt, pTag]);
  const wrap = Buffer.concat([wIv, wCt, wTag]);
  const risk = u32(Math.max(0, Math.min(100, env.riskScore | 0)));

  return Buffer.concat([
    u32(methodB.length),
    methodB,
    u32(hostB.length),
    hostB,
    u32(ctB.length),
    ctB,
    risk,
    u32(keyIdB.length),
    keyIdB,
    u32(pathB.length),
    pathB,
    i64(env.timestampMs),
    u32(nonce.length),
    nonce,
    u32(pay.length),
    pay,
    u32(wrap.length),
    wrap,
    u32(eph.length),
    eph,
  ]);
}

function mustOk(name, cond, detail = '') {
  if (!cond) {
    console.error(`[STEPUP-RACE] FAIL ${name}${detail ? `: ${detail}` : ''}`);
    process.exit(1);
  }
}

async function ensureDatabaseUrl() {
  const url = process.env.DATABASE_URL;
  if (url && !url.includes('...')) return { ok: true, url };
  const name = 'mobile-security-sdk-validate';
  const sh = (cmd) =>
    new Promise((resolve) => {
      const p = spawn('sh', ['-lc', cmd], { stdio: 'ignore' });
      p.on('exit', (c) => resolve(c === 0));
    });
  const dockerOk = await sh('docker ps >/dev/null 2>&1');
  if (!dockerOk) return { ok: false, reason: 'DATABASE_URL missing/placeholder and Docker unavailable' };

  await sh(`docker rm -f ${name} >/dev/null 2>&1 || true`);

  let port = null;
  for (let p = 55432; p <= 55532; p++) {
    const started = await sh(
      `docker run -d --name ${name} -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=mobsec -p ${p}:5432 postgres:16-alpine >/dev/null`,
    );
    if (started) {
      port = p;
      break;
    }
    await sh(`docker rm -f ${name} >/dev/null 2>&1 || true`);
  }
  if (!port) return { ok: false, reason: 'failed to start local Postgres container (no free ports in 55432-55532?)' };
  const ready = await sh(
    `for i in $(seq 1 60); do docker exec ${name} pg_isready -U postgres -d mobsec >/dev/null 2>&1 && exit 0; sleep 0.5; done; exit 1`,
  );
  if (!ready) return { ok: false, reason: 'local Postgres did not become ready' };

  const dbUrl = `postgres://postgres:postgres@127.0.0.1:${port}/mobsec`;
  await sleep(400);

  // migrate with retries
  for (let i = 0; i < 5; i++) {
    const mig = spawnSync('npm', ['run', 'migrate'], {
      cwd: backendDir,
      env: { ...process.env, DATABASE_URL: dbUrl },
      encoding: 'utf8',
      shell: false,
    });
    if (mig.status === 0) return { ok: true, url: dbUrl };
    // eslint-disable-next-line no-await-in-loop
    await sleep(500 * (i + 1));
  }
  return { ok: false, reason: 'failed to run backend-gateway migrations (after retries)' };
}

async function ensureRedisUrl() {
  const url = process.env.REDIS_URL;
  if (url) return { ok: true, url };
  const name = 'mobile-security-sdk-validate-redis';
  const sh = (cmd) =>
    new Promise((resolve) => {
      const p = spawn('sh', ['-lc', cmd], { stdio: 'ignore' });
      p.on('exit', (c) => resolve(c === 0));
    });
  const dockerOk = await sh('docker ps >/dev/null 2>&1');
  if (!dockerOk) return { ok: false, reason: 'REDIS_URL missing and Docker unavailable' };

  await sh(`docker rm -f ${name} >/dev/null 2>&1 || true`);

  let port = null;
  for (let p = 56379; p <= 56479; p++) {
    const started = await sh(`docker run -d --name ${name} -p ${p}:6379 redis:7-alpine >/dev/null`);
    if (started) {
      port = p;
      break;
    }
    await sh(`docker rm -f ${name} >/dev/null 2>&1 || true`);
  }
  if (!port) return { ok: false, reason: 'failed to start local Redis container (no free ports in 56379-56479?)' };

  // Wait until ping works.
  const ready = await sh(
    `for i in $(seq 1 60); do docker exec ${name} redis-cli ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; exit 1`,
  );
  if (!ready) return { ok: false, reason: 'local Redis did not become ready' };

  return { ok: true, url: `redis://127.0.0.1:${port}` };
}

async function startUpstream() {
  const token = 'test-upstream-token';
  const server = http.createServer((req, res) => {
    if (!req.url) {
      res.statusCode = 404;
      res.end();
      return;
    }
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, reason: 'method_not_allowed' }));
      return;
    }
    if (req.headers['x-internal-auth'] !== token) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, reason: 'unauthorized' }));
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let json = {};
      try {
        json = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      } catch {
        // ignore
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, echo: json }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    server,
    upstreamBaseUrl: `http://127.0.0.1:${port}`,
    upstreamAuthToken: token,
  };
}

function makeSecureEnvelope({ serverPublicKey, deviceKeyPair, keyId, deviceId, pathOnly, riskScore, payloadObj }) {
  const method = 'POST';
  const host = '';
  const contentType = 'application/json';
  const timestampMs = Date.now();
  const nonce = crypto.randomBytes(16);

  const eph = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ephPubSpki = eph.publicKey.export({ format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: serverPublicKey });

  const dek = crypto.randomBytes(32);
  const plain = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const payload = aesGcmEncrypt(dek, plain);
  const wrapKey = hkdfDerive(shared, 'banking-sdk-wrap-v1', 32);
  const wrappedDek = aesGcmEncrypt(wrapKey, dek);

  const envObj = {
    v: 1,
    algorithm: 'HYBRID_P256_AES256GCM_ECDSA_SHA256',
    method,
    host,
    contentType,
    riskScore,
    keyId,
    path: pathOnly,
    timestampMs,
    nonce: base64(nonce),
    aesIv: base64(payload.iv),
    ciphertext: base64(payload.ciphertext),
    aesTag: base64(payload.tag),
    wrappedDekIv: base64(wrappedDek.iv),
    wrappedDekCipher: base64(wrappedDek.ciphertext),
    wrappedDekTag: base64(wrappedDek.tag),
    ephemeralPublicSpki: base64(ephPubSpki),
  };

  const canonical = buildCanonical(envObj);
  const sig = crypto.sign('sha256', canonical, deviceKeyPair.privateKey);
  envObj.signature = base64(sig);
  envObj.deviceId = deviceId; // not used by gateway, but useful for debugging
  return envObj;
}

async function main() {
  // Ensure backend is built.
  const b = spawnSync('npm', ['run', 'build'], { cwd: root, encoding: 'utf8', shell: false });
  mustOk('build', b.status === 0, (b.stderr || b.stdout || '').trim());

  const db = await ensureDatabaseUrl();
  mustOk('db', db.ok, db.reason);
  const redis = await ensureRedisUrl();
  mustOk('redis', redis.ok, redis.reason);

  const upstream = await startUpstream();

  const serverKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const serverPrivPem = serverKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString('utf8');

  const device = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const devicePubSpkiDer = device.publicKey.export({ format: 'der', type: 'spki' });
  const devicePubSpkiB64 = base64(devicePubSpkiDer);
  const keyId = base64url(crypto.createHash('sha256').update(devicePubSpkiDer).digest());

  const runId = base64url(crypto.randomBytes(8));
  const port = 18455;
  const env = {
    ...process.env,
    PORT: String(port),
    NODE_ENV: 'test',
    DATABASE_URL: db.url,
    REDIS_URL: redis.url,
    SERVER_EC_PRIVATE_PEM_B64: Buffer.from(serverPrivPem, 'utf8').toString('base64'),
    DEVICE_REGISTRY_DIR: path.join(root, `.tmp-test-stepup-race-${runId}`),
    ATTESTATION_MODE: 'off',
    REQUIRE_ATTESTATION: '0',
    // Only enforce trust policy on an unrelated path so we can focus on step-up behavior.
    TRUST_REQUIRED_PATHS: '/sensitive-only',
    RISK_STEPUP_THRESHOLD: '1',
    // Forwarding config
    INTERNAL_UPSTREAM_BASE_URL: upstream.upstreamBaseUrl,
    INTERNAL_UPSTREAM_AUTH_TOKEN: upstream.upstreamAuthToken,
    FORWARD_ALLOWLIST_PATHS: '/transfer',
  };

  const child = spawn('node', ['dist/index.js'], { cwd: backendDir, env, stdio: 'ignore' });
  await sleep(900);

  const baseUrl = `http://127.0.0.1:${port}`;
  const health = await runHttpJson('GET', `${baseUrl}/health`, null);
  mustOk('backend health', health.status === 200, `${health.status} ${health.raw}`);

  const deviceId = `device-${runId}`;
  const reg = await runHttpJson('POST', `${baseUrl}/v1/register-device`, { deviceId, devicePublicKey: devicePubSpkiB64, platform: 'android' });
  mustOk('register', reg.status === 200 && reg.json?.ok === true && reg.json?.keyId === keyId, `${reg.status} ${reg.raw}`);

  // Trigger step-up.
  const payloadObj = { amount: 1000, currency: 'USD' };
  const env1 = makeSecureEnvelope({
    serverPublicKey: serverKeys.publicKey,
    deviceKeyPair: device,
    keyId,
    deviceId,
    pathOnly: '/transfer',
    riskScore: 99,
    payloadObj,
  });
  const step0 = await runHttpJson('POST', `${baseUrl}/v1/secure`, env1);
  mustOk('stepup required', step0.status === 403 && step0.json?.stepUpRequired === true, `${step0.status} ${step0.raw}`);
  const challenge = String(step0.json?.challenge || '');
  const payloadHash = String(step0.json?.payloadHash || '');
  mustOk('challenge present', Boolean(challenge), 'missing challenge');
  mustOk('payloadHash present', Boolean(payloadHash), 'missing payloadHash');

  // Verify step-up and obtain token.
  const msg = `stepup-v2|${keyId}|POST|/transfer|${payloadHash}|${challenge}`;
  const sig = crypto.sign('sha256', Buffer.from(msg, 'utf8'), device.privateKey);
  const verify = await runHttpJson('POST', `${baseUrl}/v1/stepup-verify`, {
    keyId,
    deviceId,
    platform: 'android',
    method: 'POST',
    path: '/transfer',
    payloadHash,
    challenge,
    signature: base64(sig),
  });
  mustOk('stepup token', verify.status === 200 && verify.json?.ok === true && typeof verify.json?.stepUpToken === 'string', `${verify.status} ${verify.raw}`);
  const token = verify.json.stepUpToken;

  // Two concurrent retries with SAME token.
  const envA = makeSecureEnvelope({
    serverPublicKey: serverKeys.publicKey,
    deviceKeyPair: device,
    keyId,
    deviceId,
    pathOnly: '/transfer',
    riskScore: 99,
    payloadObj,
  });
  const envB = makeSecureEnvelope({
    serverPublicKey: serverKeys.publicKey,
    deviceKeyPair: device,
    keyId,
    deviceId,
    pathOnly: '/transfer',
    riskScore: 99,
    payloadObj,
  });

  const [r1, r2] = await Promise.all([
    runHttpJson('POST', `${baseUrl}/v1/secure`, envA, { 'X-StepUp-Token': token }),
    runHttpJson('POST', `${baseUrl}/v1/secure`, envB, { 'X-StepUp-Token': token }),
  ]);

  const okCount = [r1, r2].filter((r) => r.status === 200 && r.json?.ok === true).length;
  const failCount = 2 - okCount;
  mustOk('exactly one success', okCount === 1, `ok=${okCount}, responses=${JSON.stringify([r1.json, r2.json])}`);
  mustOk('exactly one failure', failCount === 1, `fail=${failCount}`);

  console.log('[STEPUP-RACE] PASS one-time token consumption enforced');

  child.kill('SIGTERM');
  upstream.server.close();
  await sleep(150);
  process.exit(0);
}

main().catch((e) => {
  console.error('[STEPUP-RACE] FAIL', e);
  process.exit(1);
});

