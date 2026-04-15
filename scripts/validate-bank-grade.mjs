#!/usr/bin/env node
/**
 * Final banking-grade validation — see .cursor/commands/validate-bank-grade.md
 *
 * This is a strict orchestrator that composes:
 * - validate:phase4 (end-to-end project validation)
 * - validate:production (prod readiness checks)
 * plus extra strict static checks ("no optional security paths").
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

let failed = false;
const fail = (section, msg) => {
  console.error(`[${section}] FAIL: ${msg}`);
  failed = true;
};
const pass = (section, detail = '') => {
  console.log(`[${section}] PASS${detail ? ` ${detail}` : ''}`);
};

function run(cwd, cmd, args, env = process.env) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', env, shell: false });
  if (r.status !== 0) return { ok: false, out: (r.stderr || '') + (r.stdout || '') };
  return { ok: true, out: r.stdout || '' };
}

function mustRead(rel, section) {
  const p = path.join(root, rel);
  if (!existsSync(p)) {
    fail(section, `missing ${rel}`);
    return '';
  }
  return readFileSync(p, 'utf8');
}

// --- Strict static checks (FAIL IF any optional security path exists) ---
{
  // Demo attestation must be removed.
  const demo = path.join(root, 'backend-gateway/src/attestation.ts');
  if (existsSync(demo)) fail('SECURITY', 'demo attestation still present');
  else pass('SECURITY', 'no demo attestation');

  // Trust policy must not contain dev escape hatches.
  const trust = mustRead('backend-gateway/src/middleware/trustPolicy.ts', 'TRUST');
  const forbidden = ['TRUST_ALLOW_UNATTESTED', 'ALLOW_HIGH_RISK_IF_TRUSTED', 'ALLOW_UNSAFE'];
  const hit = forbidden.filter((s) => trust.includes(s));
  if (hit.length) fail('TRUST', `optional trust escape hatch present: ${hit.join(', ')}`);
  else pass('TRUST', 'no trust escape hatches');

  // Gateway must not leak plaintext.
  const idx = mustRead('backend-gateway/src/index.ts', 'GATEWAY');
  if (idx.includes('plaintext:')) fail('GATEWAY', 'plaintext field appears in responses');
  else pass('GATEWAY', 'no plaintext leakage');

  // Allowlist must be enforced by forwarding layer.
  const fwd = mustRead('backend-gateway/src/forwarding.ts', 'GATEWAY');
  if (!fwd.includes('allowlistPaths.includes')) fail('GATEWAY', 'forward allowlist not enforced');
  else pass('GATEWAY', 'allowlist enforced');

  // Pinning enforcement gate exists in RN SDK.
  const rnPkg = JSON.parse(mustRead('react-native-sdk/package.json', 'NETWORK') || '{}');
  const build = String(rnPkg?.scripts?.build ?? '');
  if (!build.includes('check-no-fetch.mjs')) fail('NETWORK', 'RN build gate missing (no-fetch)');
  else pass('NETWORK', 'pinning build gate enabled');

  // Upstream mTLS support must exist and be required in production.
  if (!fwd.includes('UPSTREAM_MTLS_CERT_PEM_B64') || !fwd.includes('upstream_mtls_required')) {
    fail('NETWORK', 'upstream mTLS not enforced');
  } else {
    pass('NETWORK', 'mTLS enforced');
  }

  // Logs: ensure structured log warning exists (heuristic).
  const obs = mustRead('backend-gateway/src/observability.ts', 'SECURITY');
  if (!obs.includes('Never include plaintext payloads')) fail('SECURITY', 'missing no-secrets-in-logs guardrail');
  else pass('SECURITY', 'no-secrets-in-logs guardrail present');
}

// --- Command validations ---
{
  const b = run(root, 'npm', ['run', 'build']);
  if (!b.ok) fail('BUILD', b.out.trim() || 'build failed');
  else pass('BUILD');
}
{
  const v4 = run(root, 'npm', ['run', 'validate:phase4']);
  if (!v4.ok) fail('PHASE4', v4.out.trim());
  else pass('PHASE4');
}
{
  const t = run(root, 'npm', ['run', 'test:stepup-race']);
  if (!t.ok) fail('STEPUP', t.out.trim());
  else pass('STEPUP', 'race test passed');
}
{
  const t = run(root, 'npm', ['run', 'test:stepup-attestation']);
  if (!t.ok) fail('STEPUP', t.out.trim());
  else pass('STEPUP', 'attestation test passed');
}
{
  const p = run(root, 'npm', ['run', 'pentest:suite']);
  if (!p.ok) fail('PENTEST', p.out.trim());
  else pass('PENTEST', 'suite passed');
}
{
  const vp = run(root, 'npm', ['run', 'validate:production']);
  if (!vp.ok) fail('PROD', vp.out.trim());
  else pass('PROD');
}

if (failed) {
  console.error('\nvalidate-bank-grade: FAILED');
  process.exit(1);
}
console.log('\nvalidate-bank-grade: PASSED');
process.exit(0);

