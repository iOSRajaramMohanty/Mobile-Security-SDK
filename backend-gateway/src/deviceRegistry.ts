import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export type DeviceKeyRecord = {
  deviceId: string;
  keyId: string; // base64url(sha256(spkiDer))
  publicKeySpkiDerBase64: string;
  platform: 'android' | 'ios' | 'unknown';
  trusted: boolean;
  tokenHashHex: string; // sha256(deviceToken)
  createdAtMs: number;
  rotatedAtMs?: number;
  revokedAtMs?: number;
};

export type DeviceRegistry = {
  registerOrRotate(input: {
    deviceId: string;
    publicKeySpkiDerBase64: string;
    platform: DeviceKeyRecord['platform'];
    /** Provided only when rotating. */
    existingDeviceToken?: string | null;
    /** Set true to allow rotation without token (dev only). */
    allowUnsafeRotation?: boolean;
    trusted?: boolean;
  }): { keyId: string; deviceToken: string; status: 'created' | 'unchanged' | 'rotated' };
  setTrusted(keyId: string, trusted: boolean): void;
  getByKeyId(keyId: string): DeviceKeyRecord | null;
  verifyDeviceToken(deviceId: string, token: string): boolean;
};

function sha256(buf: Buffer): Buffer {
  return createHash('sha256').update(buf).digest();
}

function base64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function hashTokenHex(token: string): string {
  return createHash('sha256').update(Buffer.from(token, 'utf8')).digest('hex');
}

function computeKeyIdFromSpkiDerBase64(spkiDerBase64: string): string {
  const der = Buffer.from(spkiDerBase64, 'base64');
  return base64url(sha256(der));
}

type RegistryFile = {
  records: DeviceKeyRecord[];
};

export function createDeviceRegistry(): DeviceRegistry {
  const dir = process.env.DEVICE_REGISTRY_DIR ?? path.join(process.cwd(), 'data');
  const file = process.env.DEVICE_REGISTRY_FILE ?? path.join(dir, 'device-registry.json');
  mkdirSync(dir, { recursive: true });

  let cache: RegistryFile = { records: [] };
  try {
    const raw = readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw) as RegistryFile;
    if (Array.isArray(parsed.records)) cache = parsed;
  } catch {
    // empty/new registry
  }

  const persist = () => {
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, JSON.stringify(cache, null, 2), 'utf8');
    renameSync(tmp, file);
  };

  const getByDeviceId = (deviceId: string) => cache.records.find((r) => r.deviceId === deviceId) ?? null;
  const getByKeyId = (keyId: string) => cache.records.find((r) => r.keyId === keyId) ?? null;

  const verifyDeviceToken = (deviceId: string, token: string): boolean => {
    const rec = getByDeviceId(deviceId);
    if (!rec || rec.revokedAtMs) return false;
    const a = Buffer.from(rec.tokenHashHex, 'hex');
    const b = Buffer.from(hashTokenHex(token), 'hex');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  };

  const registerOrRotate: DeviceRegistry['registerOrRotate'] = (input) => {
    const now = Date.now();
    const keyId = computeKeyIdFromSpkiDerBase64(input.publicKeySpkiDerBase64);
    const existing = getByDeviceId(input.deviceId);

    // Idempotent if device already registered with same key.
    if (existing && !existing.revokedAtMs && existing.keyId === keyId) {
      return { keyId, deviceToken: '', status: 'unchanged' };
    }

    const token = base64url(randomBytes(32));
    const rec: DeviceKeyRecord = {
      deviceId: input.deviceId,
      keyId,
      publicKeySpkiDerBase64: input.publicKeySpkiDerBase64,
      platform: input.platform,
      trusted: Boolean(input.trusted),
      tokenHashHex: hashTokenHex(token),
      createdAtMs: existing ? existing.createdAtMs : now,
      rotatedAtMs: existing ? now : undefined,
      revokedAtMs: undefined,
    };

    if (!existing) {
      cache.records.push(rec);
      persist();
      return { keyId, deviceToken: token, status: 'created' };
    }

    // Rotation: require existing device token unless explicitly allowed (dev).
    const allowUnsafe = Boolean(input.allowUnsafeRotation);
    const hasValidToken = input.existingDeviceToken ? verifyDeviceToken(input.deviceId, input.existingDeviceToken) : false;
    if (!allowUnsafe && !hasValidToken) {
      throw new Error('rotation_requires_device_token');
    }

    // Replace record.
    cache.records = cache.records.map((r) => (r.deviceId === input.deviceId ? rec : r));
    persist();
    return { keyId, deviceToken: token, status: 'rotated' };
  };

  const setTrusted = (keyId: string, trusted: boolean) => {
    cache.records = cache.records.map((r) => (r.keyId === keyId ? { ...r, trusted } : r));
    persist();
  };

  return { registerOrRotate, setTrusted, getByKeyId, verifyDeviceToken };
}

