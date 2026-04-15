#!/usr/bin/env node
/**
 * Phase 2 checks — see .cursor/commands/validate-phase2.md
 *
 * Notes:
 * - This is a static validation script (does not require Android/iOS toolchains).
 * - Some checks are heuristic; it prefers failing “closed” when a required security feature
 *   isn't detectably present in the codebase.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
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

function walk(dir, onFile) {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    const fp = path.join(dir, name);
    const st = statSync(fp);
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === 'dist' || name === '.build') continue;
      walk(fp, onFile);
    } else {
      onFile(fp);
    }
  }
}

function readText(fp) {
  return readFileSync(fp, 'utf8');
}

function anyFileContains(globs, needle) {
  let found = false;
  for (const g of globs) {
    walk(path.join(root, g), (fp) => {
      if (found) return;
      if (!/\.(kt|swift|ts|tsx|mjs|js|md)$/.test(fp)) return;
      const t = readText(fp);
      if (t.includes(needle)) found = true;
    });
    if (found) break;
  }
  return found;
}

function anyRegexMatch(globs, re) {
  let found = false;
  for (const g of globs) {
    walk(path.join(root, g), (fp) => {
      if (found) return;
      if (!/\.(kt|swift|ts|tsx|mjs|js|md)$/.test(fp)) return;
      const t = readText(fp);
      if (re.test(t)) found = true;
    });
    if (found) break;
  }
  return found;
}

function findStubMarkers(globs) {
  const hits = [];
  const re = /\b(TODO|STUB|PLACEHOLDER|FIXME)\b/i;
  for (const g of globs) {
    walk(path.join(root, g), (fp) => {
      if (!/\.(kt|swift|ts|tsx|mjs|js|md)$/.test(fp)) return;
      const t = readText(fp);
      if (re.test(t)) hits.push(path.relative(root, fp));
    });
  }
  return Array.from(new Set(hits));
}

// CRYPTO: AES-GCM implemented
{
  const okAndroid = anyRegexMatch(['android-sdk'], /AES\/GCM\/NoPadding/);
  const okIos = anyRegexMatch(['ios-sdk'], /\bAES\.GCM\b/);
  if (okAndroid && okIos) pass('CRYPTO', 'AES-GCM detected (Android + iOS)');
  else fail('CRYPTO', `AES-GCM not detected on ${!okAndroid ? 'Android' : ''}${!okAndroid && !okIos ? ' + ' : ''}${!okIos ? 'iOS' : ''}`);
}

// CRYPTO: Signing present (ECDSA over canonical bytes)
{
  const okAndroid = anyRegexMatch(['android-sdk'], /\bECDSA\b|\bsign\(/);
  const okIos = anyRegexMatch(['ios-sdk'], /\bP256\.Signing\b|\bsign\(/);
  const okBackend = anyRegexMatch(['backend-gateway'], /\bcryptoVerify\b|\bverify\(/);
  if (okAndroid && okIos && okBackend) pass('SIGNING', 'sign/verify markers detected (client + backend)');
  else fail('SIGNING', 'missing signing/verification markers in one or more components');
}

// CRYPTO: No plaintext transmission (JS layer must not do crypto or leak plaintext network calls)
{
  const rnJsOk = !anyRegexMatch(['react-native-sdk/src'], /\bcreateCipher\b|\bcrypto\.subtle\b|\bpbkdf2\b/);
  const obviousHttp = anyRegexMatch(['react-native-sdk/src'], /\bhttp:\/\//i);
  if (rnJsOk && !obviousHttp) pass('PLAINTEXT', 'no JS crypto + no obvious http:// usage in RN SDK');
  else fail('PLAINTEXT', 'RN layer contains disallowed crypto patterns or obvious http:// usage');
}

// KEYS: Hardware-backed, non-exportable
{
  const androidKeystore = anyRegexMatch(['android-sdk'], /\bAndroidKeyStore\b|KeyGenParameterSpec|StrongBox/);
  const iosSecureEnclave = anyRegexMatch(['ios-sdk'], /\bSecureEnclave\b|\bkSecAttrTokenIDSecureEnclave\b/);
  const privateKeyExport = anyRegexMatch(['android-sdk', 'ios-sdk', 'react-native-sdk'], /\bgetEncoded\(\)|\bexport\b.*private/i);
  if (androidKeystore && iosSecureEnclave && !privateKeyExport) pass('KEYS', 'hardware-backed markers detected and no private-key export markers');
  else {
    if (!androidKeystore) fail('KEYS', 'Android hardware-backed key markers not found');
    if (!iosSecureEnclave) fail('KEYS', 'iOS Secure Enclave markers not found');
    if (privateKeyExport) fail('KEYS', 'possible private-key export marker found (review getEncoded/export)');
  }
}

// NETWORK: Certificate pinning enabled
{
  const pinIos = anyRegexMatch(['ios-sdk', 'react-native-sdk/ios'], /\bSecTrustEvaluateWithError\b|\burlSession\(_:didReceive:completionHandler:\)/);
  const pinAndroid = anyRegexMatch(['android-sdk', 'react-native-sdk/android'], /\bCertificatePinner\b|\bX509TrustManager\b|\bHostnameVerifier\b/);
  if (pinIos && pinAndroid) pass('NETWORK', 'certificate pinning markers detected (Android + iOS)');
  else fail('NETWORK', 'certificate pinning not detected (required by validate-phase2)');
}

// BACKEND: Signature verified + replay protection active
{
  const verified = anyRegexMatch(['backend-gateway/src'], /\bcryptoVerify\b|\bverifyAndDecryptEnvelope\b/);
  const replay = anyRegexMatch(['backend-gateway/src'], /\bacceptOnce\b|\bNonceStore\b|\breplay\b/);
  if (verified && replay) pass('BACKEND', 'signature verify + replay protection markers detected');
  else fail('BACKEND', 'missing signature verify or replay protection markers');
}

// FAIL IF: any stub remains / placeholder ID exists
{
  const stubs = findStubMarkers(['android-sdk', 'ios-sdk', 'react-native-sdk', 'backend-gateway', 'shared-spec', 'docs', 'examples']);
  // Only fail on *usage* of raw OS identifiers (not mentions in docs/comments).
  const placeholderId =
    anyRegexMatch(['android-sdk'], /\bSettings\.Secure\.ANDROID_ID\b/) ||
    anyRegexMatch(['ios-sdk'], /\bUIDevice\b.*\bidentifierForVendor\b/);
  if (stubs.length) fail('STUBS', `stub markers found in: ${stubs.slice(0, 12).join(', ')}${stubs.length > 12 ? ' ...' : ''}`);
  else pass('STUBS', 'no obvious TODO/STUB/PLACEHOLDER/FIXME markers found');
  if (placeholderId) fail('IDS', 'placeholder/raw OS identifiers detected (ANDROID_ID / identifierForVendor / PLACEHOLDER)');
  else pass('IDS', 'no placeholder/raw OS id markers detected');
}

if (failed) {
  console.error('\nvalidate-phase2: FAILED');
  process.exit(1);
}
console.log('\nvalidate-phase2: PASSED');
process.exit(0);

