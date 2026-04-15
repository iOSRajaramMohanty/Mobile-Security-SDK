#!/usr/bin/env node
/**
 * Phase 4: Attestation attack simulations (backend only).
 *
 * Covers:
 * 1) Replayed attestation (challenge reuse)
 * 2) Wrong nonce (App Attest payload mismatch)
 * 3) Token from different app (Play Integrity package mismatch simulation)
 * 4) Token bound to different keyId (challenge lookup mismatch)
 * 5) Expired attestation (challenge expired)
 *
 * This suite avoids calling external Apple/Google services by validating
 * the gateway's pre-verification binding logic and fail-closed behavior.
 */

import { spawn } from 'node:child_process';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const backendDir = process.cwd();

let failed = false;
const fail = (name, msg) => {
  console.error(`[${name}] FAIL: ${msg}`);
  failed = true;
};
const pass = (name) => console.log(`[${name}] PASS`);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function reqJson(method, url, body) {
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

function b64(buf) {
  return Buffer.from(buf).toString('base64');
}

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }

  const port = 18455;
  const baseUrl = `http://127.0.0.1:${port}`;

  const env = {
    ...process.env,
    PORT: String(port),
    NODE_ENV: 'test',
    // Fail-closed attestation paths:
    REQUIRE_ATTESTATION: '1',
    // iOS path: we will test nonce mismatch before verification.
    ATTESTATION_MODE: 'app_attest',
    APP_ATTEST_TEAM_ID: 'TESTTEAMID',
    APP_ATTEST_BUNDLE_ID: 'com.example.app',
    // make expiry test fast
    ATTESTATION_CHALLENGE_TTL_MS: '500',
  };

  const child = spawn('node', ['dist/index.js'], { cwd: backendDir, env, stdio: 'ignore' });
  await sleep(900);

  const health = await reqJson('GET', `${baseUrl}/health`, null);
  if (health.status !== 200) {
    console.error('backend not started');
    child.kill('SIGTERM');
    process.exit(1);
  }

  // Create key material used for challenge issuance.
  const device = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spkiDer = device.publicKey.export({ format: 'der', type: 'spki' });
  const deviceId = `dev-${crypto.randomBytes(6).toString('hex')}`;
  const platform = 'ios';

  // 1) Wrong nonce (App Attest payload mismatch) => reject nonce_mismatch
  {
    const ch = await reqJson('POST', `${baseUrl}/v1/attestation-challenge`, {
      deviceId,
      devicePublicKey: b64(spkiDer),
      platform,
    });
    if (ch.status !== 200 || !ch.json?.nonce) fail('wrong_nonce', `challenge failed: ${ch.status}`);
    else {
      const wrongPayload = Buffer.from('not-the-nonce', 'utf8');
      const att = JSON.stringify({
        attestationObjectBase64: b64(Buffer.from('fake')),
        assertionBase64: b64(Buffer.from('fake')),
        payloadBase64: b64(wrongPayload),
        previousSignCount: 0,
      });
      const reg = await reqJson('POST', `${baseUrl}/v1/register-device`, {
        deviceId,
        devicePublicKey: b64(spkiDer),
        platform,
        attestationToken: att,
      });
      if (reg.status === 401 && reg.json?.reason === 'nonce_mismatch') pass('wrong_nonce');
      else fail('wrong_nonce', `expected 401 nonce_mismatch, got ${reg.status} ${reg.raw}`);
    }
  }

  // 2) Replayed attestation (challenge reuse) => second attempt must be missing_or_expired_challenge
  {
    const ch = await reqJson('POST', `${baseUrl}/v1/attestation-challenge`, {
      deviceId: `${deviceId}-replay`,
      devicePublicKey: b64(spkiDer),
      platform,
    });
    const nonce = ch.json?.nonce;
    if (!nonce) fail('replay', 'no nonce');
    else {
      const payload = Buffer.from(nonce, 'utf8');
      const att = JSON.stringify({
        attestationObjectBase64: b64(Buffer.from('fake')),
        assertionBase64: b64(Buffer.from('fake')),
        payloadBase64: b64(payload),
        previousSignCount: 0,
      });
      const first = await reqJson('POST', `${baseUrl}/v1/register-device`, {
        deviceId: `${deviceId}-replay`,
        devicePublicKey: b64(spkiDer),
        platform,
        attestationToken: att,
      });
      // First will fail at real verification later, but challenge will be consumed.
      const second = await reqJson('POST', `${baseUrl}/v1/register-device`, {
        deviceId: `${deviceId}-replay`,
        devicePublicKey: b64(spkiDer),
        platform,
        attestationToken: att,
      });
      if (second.status === 401 && second.json?.reason === 'missing_or_expired_challenge') pass('replay');
      else fail('replay', `expected missing_or_expired_challenge, got ${second.status} ${second.raw} (first=${first.status})`);
    }
  }

  // 3) Token bound to different keyId (challenge lookup mismatch) => missing_or_expired_challenge
  {
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const otherSpki = other.publicKey.export({ format: 'der', type: 'spki' });

    const ch = await reqJson('POST', `${baseUrl}/v1/attestation-challenge`, {
      deviceId: `${deviceId}-k`,
      devicePublicKey: b64(spkiDer),
      platform,
    });
    const nonce = ch.json?.nonce;
    if (!nonce) fail('keyId_mismatch', 'no nonce');
    else {
      const payload = Buffer.from(nonce, 'utf8');
      const att = JSON.stringify({
        attestationObjectBase64: b64(Buffer.from('fake')),
        assertionBase64: b64(Buffer.from('fake')),
        payloadBase64: b64(payload),
        previousSignCount: 0,
      });
      const reg = await reqJson('POST', `${baseUrl}/v1/register-device`, {
        deviceId: `${deviceId}-k`,
        devicePublicKey: b64(otherSpki), // different key => different keyId => no challenge to consume
        platform,
        attestationToken: att,
      });
      if (reg.status === 401 && reg.json?.reason === 'missing_or_expired_challenge') pass('keyId_mismatch');
      else fail('keyId_mismatch', `expected missing_or_expired_challenge, got ${reg.status} ${reg.raw}`);
    }
  }

  // 4) Expired attestation (challenge expired) => missing_or_expired_challenge
  {
    const ch = await reqJson('POST', `${baseUrl}/v1/attestation-challenge`, {
      deviceId: `${deviceId}-exp`,
      devicePublicKey: b64(spkiDer),
      platform,
    });
    const nonce = ch.json?.nonce;
    if (!nonce) fail('expired', 'no nonce');
    else {
      await sleep(800); // TTL is 500ms
      const payload = Buffer.from(nonce, 'utf8');
      const att = JSON.stringify({
        attestationObjectBase64: b64(Buffer.from('fake')),
        assertionBase64: b64(Buffer.from('fake')),
        payloadBase64: b64(payload),
        previousSignCount: 0,
      });
      const reg = await reqJson('POST', `${baseUrl}/v1/register-device`, {
        deviceId: `${deviceId}-exp`,
        devicePublicKey: b64(spkiDer),
        platform,
        attestationToken: att,
      });
      if (reg.status === 401 && reg.json?.reason === 'missing_or_expired_challenge') pass('expired');
      else fail('expired', `expected missing_or_expired_challenge, got ${reg.status} ${reg.raw}`);
    }
  }

  // 5) Token from different app (Play Integrity package mismatch simulation):
  // We can only test fail-closed behavior without external calls:
  // ensure a token presented under the wrong attestation mode/platform is rejected.
  {
    // Create a challenge under the android platform so the next call reaches platform mismatch.
    await reqJson('POST', `${baseUrl}/v1/attestation-challenge`, {
      deviceId: `${deviceId}-app`,
      devicePublicKey: b64(spkiDer),
      platform: 'android',
    });
    const reg = await reqJson('POST', `${baseUrl}/v1/register-device`, {
      deviceId: `${deviceId}-app`,
      devicePublicKey: b64(spkiDer),
      platform: 'android', // platform mismatch vs ATTESTATION_MODE=app_attest
      attestationToken: 'whatever',
    });
    if (reg.status === 401 && reg.json?.reason === 'platform_mismatch') pass('different_app_sim');
    else fail('different_app_sim', `expected platform_mismatch, got ${reg.status} ${reg.raw}`);
  }

  child.kill('SIGTERM');
  await sleep(150);

  if (failed) {
    console.error('\ntest-attestation-attacks: FAILED');
    process.exit(1);
  }
  console.log('\ntest-attestation-attacks: PASSED');
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

