const B64 = /^[A-Za-z0-9+/]+=*$/;

export type RegisterDeviceInput = {
  deviceId: string;
  devicePublicKey: string; // base64 SPKI DER
  platform?: 'android' | 'ios' | 'unknown';
  attestationToken?: string;
};

export function parseRegisterDeviceInput(
  body: unknown,
): { ok: true; value: RegisterDeviceInput } | { ok: false; reason: string } {
  if (typeof body !== 'object' || body === null) return { ok: false, reason: 'invalid_body' };
  const o = body as Record<string, unknown>;

  const deviceId = o.deviceId;
  if (typeof deviceId !== 'string' || deviceId.length < 8 || deviceId.length > 200) {
    return { ok: false, reason: 'invalid_deviceId' };
  }

  const devicePublicKey = o.devicePublicKey;
  if (typeof devicePublicKey !== 'string' || devicePublicKey.length === 0 || devicePublicKey.length > 8192) {
    return { ok: false, reason: 'invalid_devicePublicKey' };
  }
  const compact = devicePublicKey.replace(/\s/g, '');
  if (!B64.test(compact)) return { ok: false, reason: 'invalid_devicePublicKey_encoding' };
  const der = Buffer.from(compact, 'base64');
  if (der.length < 64 || der.length > 1024) return { ok: false, reason: 'invalid_devicePublicKey_length' };

  const platformRaw = o.platform;
  const platform: RegisterDeviceInput['platform'] =
    platformRaw === 'android' || platformRaw === 'ios' || platformRaw === 'unknown' ? platformRaw : 'unknown';

  const attestationToken = o.attestationToken;
  if (attestationToken != null && (typeof attestationToken !== 'string' || attestationToken.length > 16384)) {
    return { ok: false, reason: 'invalid_attestationToken' };
  }

  return {
    ok: true,
    value: {
      deviceId,
      devicePublicKey: compact,
      platform,
      attestationToken: typeof attestationToken === 'string' ? attestationToken : undefined,
    },
  };
}

