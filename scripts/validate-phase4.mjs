#!/usr/bin/env node
/**
 * Phase 4 checks — see .cursor/commands/validate-phase4.md
 *
 * Validates:
 * - Attestation: enforced + hardened (challenge binding + attack suite)
 * - Device trust: unknown keys rejected (Phase 3 validator)
 * - Pinning: RN build gate enabled + no JS fetch fallback + pinned native APIs present
 * - Replay: cross-instance safe (Redis required in prod)
 * - DB: migrations exist and runner available
 * - Observability: security events + /metrics endpoint present in backend
 *
 * This script is mostly static + local-command validation. It does not attempt a full MITM simulation.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

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

function mustExist(relPath, section) {
  const p = path.join(root, relPath);
  if (!existsSync(p)) fail(section, `missing ${relPath}`);
  return p;
}

// --- Static checks ---
const backend = path.join(root, 'backend-gateway');
const rn = path.join(root, 'react-native-sdk');

mustExist('backend-gateway/migrations/001_init.sql', 'DB');
mustExist('backend-gateway/migrations/002_attestation_challenges.sql', 'DB');
mustExist('backend-gateway/migrations/003_attestation_fields.sql', 'DB');
mustExist('backend-gateway/scripts/migrate.mjs', 'DB');
pass('DB', 'migrations present');

{
  const idx = readFileSync(path.join(backend, 'src/index.ts'), 'utf8');
  if (!idx.includes("/v1/attestation-challenge")) fail('ATTESTATION', 'missing /v1/attestation-challenge endpoint');
  else if (!idx.includes('REQUIRE_ATTESTATION')) fail('ATTESTATION', 'missing REQUIRE_ATTESTATION enforcement in registration');
  else pass('ATTESTATION', 'endpoints and enforcement present');

  if (!idx.includes("app.get('/metrics'")) fail('OBS', 'missing /metrics endpoint');
  else pass('OBS', '/metrics endpoint present');
}

{
  const nonceStore = readFileSync(path.join(backend, 'src/nonceStore.ts'), 'utf8');
  if (!nonceStore.includes('REDIS_URL is required in production')) fail('REPLAY', 'Redis required-in-prod not enforced');
  else pass('REPLAY', 'Redis required in production');
}

// Pinning strict gate: RN build must run check-no-fetch
{
  const pkg = JSON.parse(readFileSync(path.join(rn, 'package.json'), 'utf8'));
  const build = pkg?.scripts?.build ?? '';
  if (!String(build).includes('check-no-fetch.mjs')) fail('PINNING', 'RN build does not include strict no-fetch gate');
  else pass('PINNING', 'RN build gate enabled');

  const srcIndex = readFileSync(path.join(rn, 'src/index.ts'), 'utf8');
  if (srcIndex.includes('fetch(')) fail('PINNING', 'fetch() still used in RN SDK');
  else pass('PINNING', 'no fetch() in RN SDK src/index.ts');

  const nativeDts = readFileSync(path.join(rn, 'lib/native.d.ts'), 'utf8');
  const need = ['configurePinning', 'secureRequestPinned', 'pinnedPost'];
  const missing = need.filter((n) => !nativeDts.includes(n));
  if (missing.length) fail('PINNING', `native pinned APIs missing in typings: ${missing.join(', ')}`);
  else pass('PINNING', 'native pinned APIs present in typings');
}

// Demo logic remains? (best-effort heuristic)
{
  const p = path.join(backend, 'src/attestation.ts');
  if (existsSync(p)) {
    fail('DEMO', 'legacy demo attestation helper still present');
  } else {
    pass('DEMO', 'no legacy demo attestation helper');
  }
}

// --- Command validations ---
// Build backend + RN
{
  const b = run(root, 'npm', ['run', 'build']);
  if (!b.ok) fail('BUILD', b.out.trim() || 'npm run build failed');
  else pass('BUILD');
}

// Ensure a usable DATABASE_URL. If missing/placeholder, auto-provision local Postgres via Docker.
const db = await ensureDatabaseUrl(root);
if (!db.ok) {
  fail('DB', db.reason);
} else {
  const env = { ...process.env, DATABASE_URL: db.url };
  const v3 = run(root, 'npm', ['run', 'validate:phase3'], env);
  if (!v3.ok) fail('PHASE3', v3.out.trim());
  else pass('PHASE3', 'validate:phase3 passed');

  const mig = run(backend, 'npm', ['run', 'migrate'], env);
  if (!mig.ok) fail('ATTACKS', `migrate failed: ${mig.out.trim()}`);
  const atk = run(backend, 'npm', ['run', 'test:attestation-attacks'], env);
  if (!atk.ok) fail('ATTACKS', atk.out.trim());
  else pass('ATTACKS', 'attestation attack suite passed');
}

if (failed) {
  console.error('\nvalidate-phase4: FAILED');
  process.exit(1);
}
console.log('\nvalidate-phase4: PASSED');
process.exit(0);

async function ensureDatabaseUrl(rootDir) {
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

  // Small settle delay to avoid transient connection resets right after pg_isready flips.
  await new Promise((r) => setTimeout(r, 400));

  // Run migrations with retries (ECONNRESET happens occasionally on fresh containers).
  let lastOut = '';
  for (let i = 0; i < 5; i++) {
    const mig = spawnSync('npm', ['run', 'migrate'], {
      cwd: path.join(rootDir, 'backend-gateway'),
      env: { ...process.env, DATABASE_URL: dbUrl },
      encoding: 'utf8',
      shell: false,
    });
    if (mig.status === 0) {
      return { ok: true, url: dbUrl };
    }
    lastOut = (mig.stderr || mig.stdout || '').trim();
    await new Promise((r) => setTimeout(r, 500 * (i + 1)));
  }

  // Attach last docker logs to make failures debuggable.
  const logs = spawnSync('docker', ['logs', '--tail', '80', name], { encoding: 'utf8', shell: false });
  const logOut = (logs.stdout || logs.stderr || '').trim();
  return {
    ok: false,
    reason: `failed migrations: ${lastOut}${logOut ? `\n\n[docker logs]\n${logOut}` : ''}`,
  };
}

