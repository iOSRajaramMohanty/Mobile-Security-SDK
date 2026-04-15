import type { EnvelopeInput } from './secureEnvelope.js';

const B64 = /^[A-Za-z0-9+/]+=*$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const ALGO = 'HYBRID_P256_AES256GCM_ECDSA_SHA256';
const VERSION = 1;

function b64Field(
  v: unknown,
  name: string,
  maxDecodedBytes: number,
): { ok: true; value: string } | { ok: false; reason: string } {
  if (typeof v !== 'string' || v.length === 0) {
    return { ok: false, reason: `invalid_${name}` };
  }
  if (v.length > maxDecodedBytes * 2) {
    return { ok: false, reason: `${name}_too_long` };
  }
  const compact = v.replace(/\s/g, '');
  if (!B64.test(compact)) {
    return { ok: false, reason: `invalid_${name}_encoding` };
  }
  const buf = Buffer.from(compact, 'base64');
  if (buf.length === 0 || buf.length > maxDecodedBytes) {
    return { ok: false, reason: `invalid_${name}_length` };
  }
  return { ok: true, value: compact };
}

function reasonablePath(p: string): boolean {
  if (p.length === 0 || p.length > 2048) return false;
  if (p.includes('\0')) return false;
  return true;
}

/**
 * Structural validation for secure envelope JSON (before crypto).
 */
export function parseEnvelopeInput(
  body: unknown,
): { ok: true; envelope: EnvelopeInput } | { ok: false; reason: string } {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, reason: 'invalid_body' };
  }
  const o = body as Record<string, unknown>;

  const v = o.v;
  if (typeof v !== 'number' || !Number.isFinite(v) || Math.trunc(v) !== VERSION) {
    return { ok: false, reason: 'invalid_version' };
  }
  const algorithm = o.algorithm;
  if (typeof algorithm !== 'string' || algorithm !== ALGO) {
    return { ok: false, reason: 'unsupported_algorithm' };
  }

  const method = o.method;
  if (typeof method !== 'string' || method.length === 0 || method.length > 16) {
    return { ok: false, reason: 'invalid_method' };
  }
  const host = o.host;
  if (typeof host !== 'string' || host.length > 255) {
    return { ok: false, reason: 'invalid_host' };
  }
  const contentType = o.contentType;
  if (typeof contentType !== 'string' || contentType.length === 0 || contentType.length > 200) {
    return { ok: false, reason: 'invalid_contentType' };
  }

  const riskScore = o.riskScore;
  if (
    typeof riskScore !== 'number' ||
    !Number.isFinite(riskScore) ||
    Math.trunc(riskScore) < 0 ||
    Math.trunc(riskScore) > 100
  ) {
    return { ok: false, reason: 'invalid_riskScore' };
  }

  const keyId = o.keyId;
  if (typeof keyId !== 'string' || keyId.length < 10 || keyId.length > 128 || !B64URL.test(keyId)) {
    return { ok: false, reason: 'invalid_keyId' };
  }

  const path = o.path;
  if (typeof path !== 'string' || !reasonablePath(path)) {
    return { ok: false, reason: 'invalid_path' };
  }

  const ts = o.timestampMs;
  if (typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0 || ts > Number.MAX_SAFE_INTEGER) {
    return { ok: false, reason: 'invalid_timestamp' };
  }

  const nonce = b64Field(o.nonce, 'nonce', 128);
  if (!nonce.ok) return nonce;
  const aesIv = b64Field(o.aesIv, 'aesIv', 32);
  if (!aesIv.ok) return aesIv;
  const ciphertext = b64Field(o.ciphertext, 'ciphertext', 256 * 1024);
  if (!ciphertext.ok) return ciphertext;
  const aesTag = b64Field(o.aesTag, 'aesTag', 32);
  if (!aesTag.ok) return aesTag;
  const wrappedDekIv = b64Field(o.wrappedDekIv, 'wrappedDekIv', 32);
  if (!wrappedDekIv.ok) return wrappedDekIv;
  const wrappedDekCipher = b64Field(o.wrappedDekCipher, 'wrappedDekCipher', 512);
  if (!wrappedDekCipher.ok) return wrappedDekCipher;
  const wrappedDekTag = b64Field(o.wrappedDekTag, 'wrappedDekTag', 32);
  if (!wrappedDekTag.ok) return wrappedDekTag;
  const ephemeralPublicSpki = b64Field(o.ephemeralPublicSpki, 'ephemeralPublicSpki', 512);
  if (!ephemeralPublicSpki.ok) return ephemeralPublicSpki;
  const signature = b64Field(o.signature, 'signature', 256);
  if (!signature.ok) return signature;

  const envelope: EnvelopeInput = {
    v: VERSION,
    algorithm: ALGO,
    method,
    host,
    contentType,
    riskScore: Math.trunc(riskScore),
    keyId,
    path,
    timestampMs: Math.trunc(ts),
    nonce: nonce.value,
    aesIv: aesIv.value,
    ciphertext: ciphertext.value,
    aesTag: aesTag.value,
    wrappedDekIv: wrappedDekIv.value,
    wrappedDekCipher: wrappedDekCipher.value,
    wrappedDekTag: wrappedDekTag.value,
    ephemeralPublicSpki: ephemeralPublicSpki.value,
    signature: signature.value,
  };

  return { ok: true, envelope };
}
