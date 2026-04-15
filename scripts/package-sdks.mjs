#!/usr/bin/env node
/**
 * Build release-ready SDK artifacts (Android AAR + RN npm pack).
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const dist = path.join(root, 'dist');

function rmrf(p) {
  fs.rmSync(p, { recursive: true, force: true });
}
function mkdirp(p) {
  fs.mkdirSync(p, { recursive: true });
}
function run(cwd, cmd, args) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', shell: false });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} failed:\n${(r.stderr || '') + (r.stdout || '')}`);
  }
  return r.stdout || '';
}

function runWithOutput(cwd, cmd, args) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', shell: false });
  return { status: r.status ?? 1, out: (r.stderr || '') + (r.stdout || '') };
}

function sleepMs(ms) {
  spawnSync('sh', ['-lc', `sleep ${Math.max(0, ms / 1000)}`], { encoding: 'utf8', shell: false });
}
function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function hasAndroidSdk(androidRoot) {
  if (process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT) return true;
  const lp = path.join(androidRoot, 'local.properties');
  if (!fs.existsSync(lp)) return false;
  const txt = fs.readFileSync(lp, 'utf8');
  return /^\s*sdk\.dir\s*=.+$/m.test(txt);
}

rmrf(dist);
mkdirp(dist);

// --- Android AAR ---
{
  const androidRoot = path.join(root, 'android-sdk');
  if (!hasAndroidSdk(androidRoot)) {
    throw new Error(
      [
        'Android SDK not configured for Gradle.',
        'Set ANDROID_HOME (or ANDROID_SDK_ROOT) OR create android-sdk/local.properties with:',
        'sdk.dir=/absolute/path/to/Android/sdk',
      ].join('\n'),
    );
  }
  const props = fs.readFileSync(path.join(androidRoot, 'gradle.properties'), 'utf8');
  const version = (props.match(/^\s*VERSION_NAME\s*=\s*(.+)\s*$/m) || [])[1]?.trim() || '0.1.0';

  console.log(`[Android] building AAR (v${version})`);
  run(androidRoot, './gradlew', [':security-sdk:assembleRelease']);

  const aar = path.join(androidRoot, 'security-sdk', 'build', 'outputs', 'aar', 'security-sdk-release.aar');
  if (!fs.existsSync(aar)) throw new Error(`Android AAR not found at ${aar}`);
  const outDir = path.join(dist, 'android');
  mkdirp(outDir);
  const out = path.join(outDir, `security-sdk-${version}.aar`);
  fs.copyFileSync(aar, out);
  console.log(`[Android] wrote ${path.relative(root, out)}`);
}

// --- iOS Swift Package ---
{
  console.log('[iOS] Swift Package is repo-native (Package.swift present)');
  const pkg = path.join(root, 'ios-sdk', 'Package.swift');
  if (!fs.existsSync(pkg)) throw new Error('ios-sdk/Package.swift missing');
  const iosRoot = path.join(root, 'ios-sdk');
  // Ensure it builds. SwiftPM occasionally deadlocks due to a stale lock; retry and kill the lock holder if needed.
  let last = '';
  for (let i = 0; i < 5; i++) {
    const r = runWithOutput(iosRoot, 'swift', ['build', '-c', 'release']);
    if (r.status === 0) {
      console.log('[iOS] swift build -c release OK');
      last = '';
      break;
    }
    last = r.out.trim();
    const m = /Another instance of SwiftPM \(PID:\s*(\d+)\)/.exec(last);
    if (m) {
      const pid = m[1];
      // Best-effort: terminate lock holder then retry.
      spawnSync('sh', ['-lc', `kill -9 ${pid} >/dev/null 2>&1 || true`], { encoding: 'utf8', shell: false });
    }
    sleepMs(400 + 400 * i);
  }
  if (last) throw new Error(`swift build -c release failed:\n${last}`);
}

// --- React Native npm package ---
{
  const rnRoot = path.join(root, 'react-native-sdk');
  const pkg = readJson(path.join(rnRoot, 'package.json'));
  console.log(`[RN] building + packing ${pkg.name}@${pkg.version}`);
  run(rnRoot, 'npm', ['run', 'build']);
  const out = run(rnRoot, 'npm', ['pack']).trim().split('\n').pop();
  if (!out) throw new Error('npm pack produced no output');
  const tgzSrc = path.join(rnRoot, out);
  if (!fs.existsSync(tgzSrc)) throw new Error(`npm pack output missing: ${tgzSrc}`);
  const outDir = path.join(dist, 'react-native');
  mkdirp(outDir);
  const tgzDst = path.join(outDir, out);
  fs.renameSync(tgzSrc, tgzDst);
  console.log(`[RN] wrote ${path.relative(root, tgzDst)}`);
}

console.log('\npackage-sdks: DONE');

