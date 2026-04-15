#!/usr/bin/env node
/**
 * Production readiness validator — see .cursor/commands/validate-production.md
 *
 * This is a primarily static validator (no external network calls).
 */

import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const backend = path.join(root, 'backend-gateway');

let failed = false;
const fail = (section, msg) => {
  console.error(`[${section}] FAIL: ${msg}`);
  failed = true;
};
const pass = (section, detail = '') => {
  console.log(`[${section}] PASS${detail ? ` ${detail}` : ''}`);
};

function mustRead(rel, section) {
  const p = path.join(root, rel);
  if (!existsSync(p)) {
    fail(section, `missing ${rel}`);
    return '';
  }
  return readFileSync(p, 'utf8');
}

function run(cwd, cmd, args, env = process.env) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', env, shell: false });
  if (r.status !== 0) return { ok: false, out: (r.stderr || '') + (r.stdout || '') };
  return { ok: true, out: r.stdout || '' };
}

// --- Static checks ---
{
  const idx = mustRead('backend-gateway/src/index.ts', 'SECURITY');
  if (!idx.includes("res.json({ ok: true, plaintext")) pass('SECURITY', 'no plaintext response echo');
  else fail('SECURITY', 'plaintext echo still present in /v1/secure');

  if (idx.includes("assertProductionConfig()")) pass('CONFIG', 'prod fail-fast enabled');
  else fail('CONFIG', 'missing assertProductionConfig() call on startup');

  if (idx.includes("client_dek_present")) pass('SECURITY', '_clientDek runtime reject present');
  else fail('SECURITY', 'missing _clientDek runtime reject');

  if (idx.includes("evaluateTrustPolicy")) pass('TRUST', 'trust policy enforced on /v1/secure');
  else fail('TRUST', 'missing trust policy enforcement');
}

{
  const fwd = mustRead('backend-gateway/src/forwarding.ts', 'SECURITY');
  if (fwd.includes('INTERNAL_UPSTREAM_AUTH_TOKEN') && fwd.includes("'X-Internal-Auth'")) pass('SECURITY', 'upstream auth enforced');
  else fail('SECURITY', 'missing upstream auth enforcement');

  if (fwd.includes('upstream_not_private')) pass('SECURITY', 'private upstream enforcement present');
  else fail('SECURITY', 'missing private upstream enforcement');

  if (fwd.includes('UPSTREAM_MTLS_CERT_PEM_B64') && fwd.includes('UPSTREAM_CA_CERT_PEM_B64') && fwd.includes('dispatcher')) {
    pass('SECURITY', 'upstream mTLS support present');
  } else {
    fail('SECURITY', 'missing upstream mTLS support');
  }
}

{
  const nonce = mustRead('backend-gateway/src/nonceStore.ts', 'SCALING');
  if (nonce.includes('REDIS_URL is required in production')) pass('SCALING', 'Redis required for replay in production');
  else fail('SCALING', 'missing Redis required-in-prod for replay');
}

{
  const rl = mustRead('backend-gateway/src/deviceRateLimiter.ts', 'SCALING');
  if (rl.includes('RedisDeviceRateLimiter') && rl.includes('zAdd') && rl.includes('zCard')) pass('SCALING', 'Redis rate limiter present');
  else fail('SCALING', 'missing Redis-backed rate limiter implementation');
}

{
  const cfg = mustRead('backend-gateway/src/config.ts', 'CONFIG');
  if (cfg.includes("REQUIRE_ATTESTATION_must_be_1")) pass('TRUST', 'prod requires attestation for registration');
  else fail('TRUST', 'missing REQUIRE_ATTESTATION prod fail-fast');
}

// Fail if any optional insecure path exists (heuristic).
{
  const p = path.join(root, 'backend-gateway/src/attestation.ts');
  if (existsSync(p)) fail('SECURITY', 'legacy demo attestation helper present');
  else pass('SECURITY', 'no legacy demo attestation helper');
}

// --- Lightweight runtime checks (no DB/Redis connections) ---
// Validate prod config check can pass with required env set.
{
  const r = run(root, 'npm', ['run', 'build']);
  if (!r.ok) fail('BUILD', r.out.trim() || 'build failed');
  else pass('BUILD');

  const env = {
    ...process.env,
    NODE_ENV: 'production',
    // required by config.ts
    REDIS_URL: 'redis://127.0.0.1:6379',
    INTERNAL_UPSTREAM_BASE_URL: 'https://127.0.0.1:8444/',
    INTERNAL_UPSTREAM_AUTH_TOKEN: 'token',
    FORWARD_ALLOWLIST_PATHS: '/x',
    REQUIRE_ATTESTATION: '1',
    SERVER_EC_PRIVATE_PEM_B64: Buffer.from('dummy', 'utf8').toString('base64'),
    UPSTREAM_MTLS_CERT_PEM_B64: Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', 'utf8').toString('base64'),
    UPSTREAM_MTLS_KEY_PEM_B64: Buffer.from('-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n', 'utf8').toString('base64'),
    UPSTREAM_CA_CERT_PEM_B64: Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', 'utf8').toString('base64'),
  };
  const check = spawnSync(
    'node',
    [
      '-e',
      "import('./backend-gateway/dist/config.js').then(m=>{m.assertProductionConfig(); console.log('ok')}).catch(e=>{console.error(String(e)); process.exit(1)})",
    ],
    { cwd: root, env, encoding: 'utf8', shell: false },
  );
  if (check.status === 0 && (check.stdout || '').includes('ok')) pass('CONFIG', 'prod config assertion passes with required env');
  else fail('CONFIG', `prod config assertion failed: ${(check.stderr || check.stdout || '').trim()}`);
}

if (failed) {
  console.error('\nvalidate-production: FAILED');
  process.exit(1);
}
console.log('\nvalidate-production: PASSED');
process.exit(0);

