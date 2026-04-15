import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes as cryptoRandomBytes,
  verify as cryptoVerify,
} from 'node:crypto';

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function i64be(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(n, 0);
  return b;
}

/** Byte layout must match Android/iOS [CanonicalPayload]. */
export function buildCanonical(
  keyId: string,
  method: string,
  host: string,
  contentType: string,
  riskScore: number,
  path: string,
  timestampMs: bigint,
  nonce: Buffer,
  payloadIv: Buffer,
  payloadCt: Buffer,
  payloadTag: Buffer,
  wrapIv: Buffer,
  wrapCt: Buffer,
  wrapTag: Buffer,
  ephemeralPublicSpki: Buffer,
): Buffer {
  const keyIdB = Buffer.from(keyId, 'utf8');
  const methodB = Buffer.from(method, 'utf8');
  const hostB = Buffer.from(host, 'utf8');
  const contentTypeB = Buffer.from(contentType, 'utf8');
  const pathB = Buffer.from(path, 'utf8');
  const pay = Buffer.concat([payloadIv, payloadCt, payloadTag]);
  const wrap = Buffer.concat([wrapIv, wrapCt, wrapTag]);
  const risk = u32be(Math.max(0, Math.min(100, Math.trunc(riskScore))));
  return Buffer.concat([
    u32be(methodB.length),
    methodB,
    u32be(hostB.length),
    hostB,
    u32be(contentTypeB.length),
    contentTypeB,
    risk,
    u32be(keyIdB.length),
    keyIdB,
    u32be(pathB.length),
    pathB,
    i64be(timestampMs),
    u32be(nonce.length),
    nonce,
    u32be(pay.length),
    pay,
    u32be(wrap.length),
    wrap,
    u32be(ephemeralPublicSpki.length),
    ephemeralPublicSpki,
  ]);
}

export type EnvelopeInput = {
  v: number;
  algorithm: string;
  method: string;
  host: string;
  contentType: string;
  riskScore: number;
  keyId: string;
  path: string;
  timestampMs: number;
  nonce: string;
  aesIv: string;
  ciphertext: string;
  aesTag: string;
  wrappedDekIv: string;
  wrappedDekCipher: string;
  wrappedDekTag: string;
  ephemeralPublicSpki: string;
  signature: string;
};

function b64(s: string): Buffer {
  return Buffer.from(s, 'base64');
}

function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  const s = salt.length ? salt : Buffer.alloc(32);
  return createHmac('sha256', s).update(ikm).digest();
}

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0);
  let tPrev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const h = createHmac('sha256', prk);
    h.update(tPrev);
    h.update(info);
    h.update(Buffer.from([i]));
    tPrev = h.digest();
    okm = Buffer.concat([okm, tPrev]);
  }
  return okm.subarray(0, length);
}

function hkdfDerive(ikm: Buffer, salt: Buffer | null, info: string, length: number): Buffer {
  const saltB = salt ?? Buffer.alloc(32);
  const prk = hkdfExtract(saltB, ikm);
  return hkdfExpand(prk, Buffer.from(info, 'utf8'), length);
}

function aesGcmDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function aesGcmEncrypt(key: Buffer, plaintext: Buffer): { iv: Buffer; ciphertext: Buffer; tag: Buffer } {
  const iv = Buffer.from(cryptoRandomBytes(12));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

/**
 * Verifies ECDSA-SHA256(device) and decrypts payload using server EC private key (ECDH unwrap).
 */
export function verifyAndDecryptEnvelope(
  env: EnvelopeInput,
  serverEcPrivatePem: string,
  deviceSigningPublicSpkiDerBase64: string,
): { ok: true; plaintext: string } | { ok: false; reason: string } {
  try {
    const nonce = b64(env.nonce);
    const payloadIv = b64(env.aesIv);
    const payloadCt = b64(env.ciphertext);
    const payloadTag = b64(env.aesTag);
    const wrapIv = b64(env.wrappedDekIv);
    const wrapCt = b64(env.wrappedDekCipher);
    const wrapTag = b64(env.wrappedDekTag);
    const ephSpki = b64(env.ephemeralPublicSpki);
    const devicePubSpki = b64(deviceSigningPublicSpkiDerBase64);
    const sig = b64(env.signature);

    const canonical = buildCanonical(
      env.keyId,
      env.method,
      env.host,
      env.contentType,
      env.riskScore,
      env.path,
      BigInt(env.timestampMs),
      nonce,
      payloadIv,
      payloadCt,
      payloadTag,
      wrapIv,
      wrapCt,
      wrapTag,
      ephSpki,
    );

    const devicePub = createPublicKey({ key: devicePubSpki, format: 'der', type: 'spki' });
    const okSig = cryptoVerify('sha256', canonical, devicePub, sig);
    if (!okSig) {
      return { ok: false, reason: 'bad_signature' };
    }

    const sk = createPrivateKey({ key: serverEcPrivatePem, format: 'pem' });
    const ephPub = createPublicKey({ key: ephSpki, format: 'der', type: 'spki' });
    const shared = diffieHellman({ privateKey: sk, publicKey: ephPub });

    const wrapKey = hkdfDerive(shared, Buffer.alloc(0), 'banking-sdk-wrap-v1', 32);
    const dek = aesGcmDecrypt(wrapKey, wrapIv, wrapCt, wrapTag);
    const plain = aesGcmDecrypt(dek, payloadIv, payloadCt, payloadTag);
    return { ok: true, plaintext: plain.toString('utf8') };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, reason: msg };
  }
}

export function verifyAndDecryptEnvelopeForForwarding(
  env: EnvelopeInput,
  serverEcPrivatePem: string,
  deviceSigningPublicSpkiDerBase64: string,
): { ok: true; plaintext: string; dekBase64: string } | { ok: false; reason: string } {
  try {
    const nonce = b64(env.nonce);
    const payloadIv = b64(env.aesIv);
    const payloadCt = b64(env.ciphertext);
    const payloadTag = b64(env.aesTag);
    const wrapIv = b64(env.wrappedDekIv);
    const wrapCt = b64(env.wrappedDekCipher);
    const wrapTag = b64(env.wrappedDekTag);
    const ephSpki = b64(env.ephemeralPublicSpki);
    const devicePubSpki = b64(deviceSigningPublicSpkiDerBase64);
    const sig = b64(env.signature);

    const canonical = buildCanonical(
      env.keyId,
      env.method,
      env.host,
      env.contentType,
      env.riskScore,
      env.path,
      BigInt(env.timestampMs),
      nonce,
      payloadIv,
      payloadCt,
      payloadTag,
      wrapIv,
      wrapCt,
      wrapTag,
      ephSpki,
    );

    const devicePub = createPublicKey({ key: devicePubSpki, format: 'der', type: 'spki' });
    const okSig = cryptoVerify('sha256', canonical, devicePub, sig);
    if (!okSig) {
      return { ok: false, reason: 'bad_signature' };
    }

    const sk = createPrivateKey({ key: serverEcPrivatePem, format: 'pem' });
    const ephPub = createPublicKey({ key: ephSpki, format: 'der', type: 'spki' });
    const shared = diffieHellman({ privateKey: sk, publicKey: ephPub });

    const wrapKey = hkdfDerive(shared, Buffer.alloc(0), 'banking-sdk-wrap-v1', 32);
    const dek = aesGcmDecrypt(wrapKey, wrapIv, wrapCt, wrapTag);
    const plain = aesGcmDecrypt(dek, payloadIv, payloadCt, payloadTag);
    return { ok: true, plaintext: plain.toString('utf8'), dekBase64: dek.toString('base64') };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, reason: msg };
  }
}

export function encryptResponseWithDek(
  dekBase64: string,
  plaintextJsonUtf8: string,
): { ok: true; aesIv: string; ciphertext: string; aesTag: string } | { ok: false; reason: string } {
  try {
    const dek = Buffer.from(dekBase64, 'base64');
    if (dek.length !== 32) return { ok: false, reason: 'invalid_dek' };
    const sealed = aesGcmEncrypt(dek, Buffer.from(plaintextJsonUtf8, 'utf8'));
    return {
      ok: true,
      aesIv: sealed.iv.toString('base64'),
      ciphertext: sealed.ciphertext.toString('base64'),
      aesTag: sealed.tag.toString('base64'),
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, reason: msg };
  }
}

export function verifyEnvelopeSignature(
  env: EnvelopeInput,
  deviceSigningPublicSpkiDerBase64: string,
): { ok: true } | { ok: false; reason: 'bad_signature' | 'invalid_key' } {
  try {
    const nonce = b64(env.nonce);
    const payloadIv = b64(env.aesIv);
    const payloadCt = b64(env.ciphertext);
    const payloadTag = b64(env.aesTag);
    const wrapIv = b64(env.wrappedDekIv);
    const wrapCt = b64(env.wrappedDekCipher);
    const wrapTag = b64(env.wrappedDekTag);
    const ephSpki = b64(env.ephemeralPublicSpki);
    const devicePubSpki = b64(deviceSigningPublicSpkiDerBase64);
    const sig = b64(env.signature);

    const canonical = buildCanonical(
      env.keyId,
      env.method,
      env.host,
      env.contentType,
      env.riskScore,
      env.path,
      BigInt(env.timestampMs),
      nonce,
      payloadIv,
      payloadCt,
      payloadTag,
      wrapIv,
      wrapCt,
      wrapTag,
      ephSpki,
    );

    const devicePub = createPublicKey({ key: devicePubSpki, format: 'der', type: 'spki' });
    const okSig = cryptoVerify('sha256', canonical, devicePub, sig);
    return okSig ? { ok: true } : { ok: false, reason: 'bad_signature' };
  } catch {
    return { ok: false, reason: 'invalid_key' };
  }
}
