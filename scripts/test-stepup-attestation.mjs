#!/usr/bin/env node
/**
 * Step-up attestation tests.
 *
 * Cases (when STEPUP_REQUIRE_ATTESTATION=1):
 * - missing attestation -> reject
 * - invalid attestation -> reject
 * - valid attestation -> success
 *
 * Ensure:
 * - attestation token is bound to challenge
 * - step-up challenge is single-use (second verify fails)
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

function must(name, cond, detail = '') {
  if (!cond) {
    console.error(`[STEPUP-ATTEST] FAIL ${name}${detail ? `: ${detail}` : ''}`);
    process.exit(1);
  }
  console.log(`[STEPUP-ATTEST] PASS ${name}`);
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
  const ready = await sh(
    `for i in $(seq 1 60); do docker exec ${name} redis-cli ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; exit 1`,
  );
  if (!ready) return { ok: false, reason: 'local Redis did not become ready' };
  return { ok: true, url: `redis://127.0.0.1:${port}` };
}

async function startUpstream() {
  const token = 'test-upstream-token';
  const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.end();
      return;
    }
    if (req.headers['x-internal-auth'] !== token) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, reason: 'unauthorized' }));
      return;
    }
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return { server, upstreamBaseUrl: `http://127.0.0.1:${port}`, upstreamAuthToken: token };
}

function makeEnvelope({ serverPublicKey, deviceKeyPair, keyId, pathOnly, riskScore, payloadObj }) {
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
  return envObj;
}

function hmacAttestationToken({ secret, platform, deviceId, keyId, challenge }) {
  return base64url(
    crypto
      .createHmac('sha256', secret)
      .update(`stepup|${platform}|${deviceId}|${keyId}|${challenge}`, 'utf8')
      .digest(),
  );
}

async function main() {
  const build = spawnSync('npm', ['run', 'build'], { cwd: root, encoding: 'utf8', shell: false });
  must('build', build.status === 0, (build.stderr || build.stdout || '').trim());

  const db = await ensureDatabaseUrl();
  must('db', db.ok, db.reason || '');
  const redis = await ensureRedisUrl();
  must('redis', redis.ok, redis.reason || '');
  const upstream = await startUpstream();

  const serverKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const serverPrivPem = serverKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString('utf8');
  const device = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const devicePubSpkiDer = device.publicKey.export({ format: 'der', type: 'spki' });
  const devicePubSpkiB64 = base64(devicePubSpkiDer);
  const keyId = base64url(crypto.createHash('sha256').update(devicePubSpkiDer).digest());
  const runId = base64url(crypto.randomBytes(8));
  const deviceId = `device-${runId}`;

  const port = 18400 + Math.floor(Math.random() * 500);
  const secret = 'stepup-attest-secret';
  const env = {
    ...process.env,
    PORT: String(port),
    NODE_ENV: 'test',
    DATABASE_URL: db.url,
    REDIS_URL: redis.url,
    SERVER_EC_PRIVATE_PEM_B64: Buffer.from(serverPrivPem, 'utf8').toString('base64'),
    DEVICE_REGISTRY_DIR: path.join(root, `.tmp-test-stepup-attest-${runId}`),
    // test-only attestation mode
    ATTESTATION_MODE: 'hmac',
    ATTESTATION_HMAC_SECRET: secret,
    REQUIRE_ATTESTATION: '0',
    STEPUP_REQUIRE_ATTESTATION: '1',
    // Don't let trust policy block /transfer
    TRUST_REQUIRED_PATHS: '/sensitive-only',
    RISK_STEPUP_THRESHOLD: '1',
    INTERNAL_UPSTREAM_BASE_URL: upstream.upstreamBaseUrl,
    INTERNAL_UPSTREAM_AUTH_TOKEN: upstream.upstreamAuthToken,
    FORWARD_ALLOWLIST_PATHS: '/transfer',
  };

  const child = spawn('node', ['dist/index.js'], { cwd: backendDir, env, stdio: 'ignore' });
  process.on('exit', () => {
    try {
      child.kill('SIGTERM');
    } catch {
      // ignore
    }
    try {
      upstream.server.close();
    } catch {
      // ignore
    }
  });
  await sleep(900);
  const baseUrl = `http://127.0.0.1:${port}`;
  const health = await runHttpJson('GET', `${baseUrl}/health`, null);
  must('backend health', health.status === 200, `${health.status} ${health.raw}`);

  const reg = await runHttpJson('POST', `${baseUrl}/v1/register-device`, {
    deviceId,
    devicePublicKey: devicePubSpkiB64,
    platform: 'android',
  });
  must('register device', reg.status === 200 && reg.json?.ok === true && reg.json?.keyId === keyId, `${reg.status} ${reg.raw}`);

  // Trigger step-up to obtain challenge/payloadHash.
  const envStep = makeEnvelope({
    serverPublicKey: serverKeys.publicKey,
    deviceKeyPair: device,
    keyId,
    pathOnly: '/transfer',
    riskScore: 99,
    payloadObj: { amount: 1000 },
  });
  // Sanity check crypto pipeline in-process (matches backend implementation).
  {
    const { verifyAndDecryptEnvelopeForForwarding } = await import(path.join(backendDir, 'dist', 'secureEnvelope.js'));
    const out = verifyAndDecryptEnvelopeForForwarding(envStep, serverPrivPem, devicePubSpkiB64);
    must('local decrypt ok', out?.ok === true, JSON.stringify(out));
  }
  const step0 = await runHttpJson('POST', `${baseUrl}/v1/secure`, envStep);
  must('step-up required', step0.status === 403 && step0.json?.stepUpRequired === true, `${step0.status} ${step0.raw}`);
  const challenge = String(step0.json?.challenge || '');
  const payloadHash = String(step0.json?.payloadHash || '');
  must('step-up fields', Boolean(challenge) && Boolean(payloadHash), 'missing challenge/payloadHash');

  const msg = `stepup-v2|${keyId}|POST|/transfer|${payloadHash}|${challenge}`;
  const signature = base64(crypto.sign('sha256', Buffer.from(msg, 'utf8'), device.privateKey));

  // missing attestation -> reject
  {
    const r = await runHttpJson('POST', `${baseUrl}/v1/stepup-verify`, {
      keyId,
      deviceId,
      platform: 'android',
      method: 'POST',
      path: '/transfer',
      payloadHash,
      challenge,
      signature,
    });
    must('missing attestation rejected', r.status === 401 && r.json?.reason === 'missing_attestation', `${r.status} ${r.raw}`);
  }

  // invalid attestation -> reject
  {
    const r = await runHttpJson('POST', `${baseUrl}/v1/stepup-verify`, {
      keyId,
      deviceId,
      platform: 'android',
      method: 'POST',
      path: '/transfer',
      payloadHash,
      challenge,
      signature,
      attestationToken: 'bad',
    });
    must('invalid attestation rejected', r.status === 401, `${r.status} ${r.raw}`);
  }

  // valid attestation bound to challenge -> success
  const goodToken = hmacAttestationToken({ secret, platform: 'android', deviceId, keyId, challenge });
  const ok1 = await runHttpJson('POST', `${baseUrl}/v1/stepup-verify`, {
    keyId,
    deviceId,
    platform: 'android',
    method: 'POST',
    path: '/transfer',
    payloadHash,
    challenge,
    signature,
    attestationToken: goodToken,
  });
  must('valid attestation accepted', ok1.status === 200 && ok1.json?.ok === true && typeof ok1.json?.stepUpToken === 'string', `${ok1.status} ${ok1.raw}`);

  // single-use: same challenge cannot be verified again (challenge already consumed).
  {
    const r = await runHttpJson('POST', `${baseUrl}/v1/stepup-verify`, {
      keyId,
      deviceId,
      platform: 'android',
      method: 'POST',
      path: '/transfer',
      payloadHash,
      challenge,
      signature,
      attestationToken: goodToken,
    });
    must(
      'challenge single-use enforced',
      r.status === 401 && r.json?.reason === 'invalid_or_expired_challenge',
      `${r.status} ${r.raw}`,
    );
  }

  // bound to challenge: token for a different challenge must fail (first obtain a new challenge).
  const envStep2 = makeEnvelope({
    serverPublicKey: serverKeys.publicKey,
    deviceKeyPair: device,
    keyId,
    pathOnly: '/transfer',
    riskScore: 99,
    payloadObj: { amount: 1000 },
  });
  const step2 = await runHttpJson('POST', `${baseUrl}/v1/secure`, envStep2);
  must('step-up required (2)', step2.status === 403 && step2.json?.stepUpRequired === true, `${step2.status} ${step2.raw}`);
  const ch2 = String(step2.json?.challenge || '');
  const ph2 = String(step2.json?.payloadHash || '');
  const msg2 = `stepup-v2|${keyId}|POST|/transfer|${ph2}|${ch2}`;
  const sig2 = base64(crypto.sign('sha256', Buffer.from(msg2, 'utf8'), device.privateKey));

  const wrong = hmacAttestationToken({ secret, platform: 'android', deviceId, keyId, challenge: challenge /* old */ });
  const rWrong = await runHttpJson('POST', `${baseUrl}/v1/stepup-verify`, {
    keyId,
    deviceId,
    platform: 'android',
    method: 'POST',
    path: '/transfer',
    payloadHash: ph2,
    challenge: ch2,
    signature: sig2,
    attestationToken: wrong,
  });
  must('attestation bound to challenge', rWrong.status === 401 && rWrong.json?.reason === 'attestation_invalid', `${rWrong.status} ${rWrong.raw}`);

  child.kill('SIGTERM');
  upstream.server.close();
  await sleep(150);
  console.log('\n[STEPUP-ATTEST] PASSED');
  process.exit(0);
}

main().catch((e) => {
  console.error('[STEPUP-ATTEST] FAIL', e);
  process.exit(1);
});

