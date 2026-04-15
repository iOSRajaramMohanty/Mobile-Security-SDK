#!/usr/bin/env node
/**
 * Phase 1 checks — see .cursor/commands/validate-phase1.md
 * Android Gradle runs only when ANDROID_HOME or android-sdk/local.properties (sdk.dir) is set.
 */

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import http from 'node:http';
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
  if (r.status !== 0) {
    return { ok: false, out: (r.stderr || '') + (r.stdout || '') };
  }
  return { ok: true, out: r.stdout || '' };
}

function hasAndroidSdk() {
  if (process.env.ANDROID_HOME && existsSync(process.env.ANDROID_HOME)) return true;
  const lp = path.join(root, 'android-sdk', 'local.properties');
  if (!existsSync(lp)) return false;
  const text = readFileSync(lp, 'utf8');
  const m = text.match(/^\s*sdk\.dir\s*=\s*(.+)$/m);
  if (!m) return false;
  const dir = m[1].trim().replace(/\\\\/g, '\\');
  return existsSync(dir);
}

function walkTsFiles(dir, onFile) {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    const fp = path.join(dir, name);
    if (statSync(fp).isDirectory()) walkTsFiles(fp, onFile);
    else if (name.endsWith('.ts') || name.endsWith('.tsx')) onFile(fp);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// 1. Structure
const dirs = [
  'android-sdk',
  'ios-sdk',
  'react-native-sdk',
  'backend-gateway',
  'shared-spec',
  'examples',
];
for (const d of dirs) {
  if (!existsSync(path.join(root, d))) {
    fail('STRUCTURE', `missing folder: ${d}`);
  }
}
if (!failed) pass('STRUCTURE', dirs.join(', '));

// 3. RN API surface (source)
const idx = path.join(root, 'react-native-sdk', 'src', 'index.ts');
if (!existsSync(idx)) {
  fail('RN_SDK', 'missing react-native-sdk/src/index.ts');
} else {
  const src = readFileSync(idx, 'utf8');
  const need = ['async init()', 'secureRequest', 'getSecurityStatus'];
  const missing = need.filter((k) => !src.includes(k));
  if (missing.length) fail('RN_SDK', `expected API markers missing: ${missing.join(', ')}`);
  else pass('RN_SDK', 'init, secureRequest, getSecurityStatus on SecureSDK');
}

// Monorepo build (TS)
const b = run(root, 'npm', ['run', 'build']);
if (!b.ok) {
  fail('BUILD', b.out.trim() || 'npm run build failed');
} else pass('BUILD');

// 2. Backend /health
const bg = path.join(root, 'backend-gateway');
const buildBg = run(bg, 'npm', ['run', 'build']);
if (!buildBg.ok) {
  fail('BACKEND', buildBg.out.trim());
} else {
  const child = spawn('node', ['dist/index.js'], {
    cwd: bg,
    env: { ...process.env, PORT: '18443' },
    stdio: 'ignore',
  });
  await sleep(900);
  const okHealth = await new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:18443/health', (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(4000, () => {
      req.destroy();
      resolve(false);
    });
  });
  child.kill('SIGTERM');
  await sleep(100);
  if (!okHealth) fail('BACKEND', '/health did not return 200 on port 18443');
  else pass('BACKEND', '/health 200');
}

// 5. Swift
const sw = run(path.join(root, 'ios-sdk'), 'swift', ['package', 'resolve']);
if (!sw.ok) fail('IOS_SDK', sw.out.trim());
else pass('IOS_SDK', 'swift package resolve');

// 4. Android (optional when SDK missing)
if (hasAndroidSdk()) {
  const javaHome =
    process.env.JAVA_HOME ||
    (existsSync('/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home')
      ? '/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home'
      : '');
  const env = { ...process.env };
  if (javaHome) env.JAVA_HOME = javaHome;
  const gr = run(path.join(root, 'android-sdk'), './gradlew', [':security-sdk:assembleRelease', '--no-daemon'], env);
  if (!gr.ok) fail('ANDROID_SDK', gr.out.trim().slice(-2000));
  else pass('ANDROID_SDK', 'assembleRelease');
} else {
  console.warn(
    '[ANDROID_SDK] SKIP: no ANDROID_HOME and no android-sdk/local.properties sdk.dir — set one to validate Gradle.',
  );
}

// 6. Security baseline — no obvious crypto in JS bridge
const nativeTs = path.join(root, 'react-native-sdk', 'src');
const bad = ['createCipher', 'crypto.subtle', 'pbkdf2'];
walkTsFiles(nativeTs, (fp) => {
  const t = readFileSync(fp, 'utf8');
  for (const b of bad) {
    if (t.includes(b)) fail('SECURITY', `disallowed pattern in ${fp}: ${b}`);
  }
});
if (!failed) pass('SECURITY', 'no disallowed JS crypto patterns in react-native-sdk/src');

if (failed) {
  console.error('\nvalidate-phase1: FAILED');
  process.exit(1);
}
console.log('\nvalidate-phase1: PASSED');
process.exit(0);
