import { getNativeModule } from './native';

const MAX_BODY_BYTES = 256 * 1024; // bridge limit; native may enforce tighter
const MAX_KEY_BYTES = 8 * 1024;

function safeJsonParse<T>(raw: string, what: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`SecureSDK: invalid JSON from native (${what})`);
  }
}

function assertBase64Compact(s: string, what: string): void {
  if (typeof s !== 'string' || s.length === 0) throw new Error(`SecureSDK: invalid ${what}`);
  if (s.length > MAX_KEY_BYTES * 2) throw new Error(`SecureSDK: ${what} too large`);
  const compact = s.replace(/\s/g, '');
  if (!/^[A-Za-z0-9+/]+=*$/.test(compact)) throw new Error(`SecureSDK: invalid ${what} encoding`);
}

export type SecureRequestOptions = {
  url: string;
  body?: Record<string, unknown>;
  /**
   * Optional attestation token to bind step-up verification to a device attestation.
   * When the backend sets STEPUP_REQUIRE_ATTESTATION=1, you must provide this.
   */
  stepUpAttestationToken?: string;
};

export type SecureResponse = {
  statusCode: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
};

export type SecurityStatus = {
  /** 0..100 (higher = riskier runtime). */
  riskScore: number;
  /** Array of stable string codes describing findings. */
  findings: string[];
};

export type DeviceRegistrationPayload = {
  installationId: string;
  signingPublicKeySpki: string;
  platform: string;
};

export type RegisterDeviceOptions = {
  /** Base URL of backend-gateway (e.g. https://api.example.com) */
  baseUrl: string;
  /** Optional attestation token; integrated in Phase 3. */
  attestationToken?: string;
};

export type RegisterDeviceResult =
  | { ok: true; status: 'created' | 'rotated' | 'unchanged'; keyId: string; deviceToken?: string }
  | { ok: false; reason: string };

/**
 * Public JS API: delegates to native code only. No cryptography or private keys in JS.
 */
export const SecureSDK = {
  async init(): Promise<void> {
    await getNativeModule().initialize();
  },

  /** P-256 server ECDH public key (SPKI) as base64 — required before [secureRequest]. */
  async configureServerPublicKey(base64Spki: string): Promise<void> {
    assertBase64Compact(base64Spki, 'server public key');
    await getNativeModule().configureServerPublicKey(base64Spki);
  },

  /**
   * Configure certificate pinning for native HTTP calls.
   *
   * Pins must be **SPKI SHA-256 base64** (without the `sha256/` prefix).
   */
  async configurePinning(host: string, pins: string[]): Promise<void> {
    if (typeof host !== 'string' || host.length === 0) throw new Error('SecureSDK: invalid host');
    if (!Array.isArray(pins) || pins.length === 0) throw new Error('SecureSDK: pins required');
    for (const p of pins) assertBase64Compact(p, 'pin');
    await getNativeModule().configurePinning(JSON.stringify({ host, pins }));
  },

  /** Device ECDSA P-256 signing public key (SPKI) as base64 — for registration. */
  async getPublicKey(): Promise<string> {
    return getNativeModule().getPublicKey();
  },

  /** Rotates hardware-backed signing keys (invalidates prior public key server-side). */
  async rotateKeys(): Promise<void> {
    await getNativeModule().rotateKeys();
  },

  /** Installation id + signing public key + platform for your device-registration API. */
  async getDeviceRegistrationPayload(): Promise<DeviceRegistrationPayload> {
    const raw = await getNativeModule().getDeviceRegistrationPayload();
    return safeJsonParse<DeviceRegistrationPayload>(raw, 'device registration payload');
  },

  /**
   * Convenience helper to enroll device with backend-gateway.
   * Uses native pinned HTTP client (no JS `fetch` fallback).
   */
  async registerDevice(options: RegisterDeviceOptions): Promise<RegisterDeviceResult> {
    if (!options || typeof options.baseUrl !== 'string' || options.baseUrl.length === 0) {
      throw new Error('SecureSDK: invalid baseUrl');
    }
    const payload = await SecureSDK.getDeviceRegistrationPayload();
    const body = {
      deviceId: payload.installationId,
      devicePublicKey: payload.signingPublicKeySpki,
      platform: (payload.platform === 'android' || payload.platform === 'ios' ? payload.platform : 'unknown') as
        | 'android'
        | 'ios'
        | 'unknown',
      attestationToken: options.attestationToken,
    };
    const url = `${options.baseUrl.replace(/\/+$/g, '')}/v1/register-device`;
    const raw = await getNativeModule().pinnedPost(
      url,
      JSON.stringify({ 'Content-Type': 'application/json' }),
      JSON.stringify(body),
    );
    return safeJsonParse<RegisterDeviceResult>(raw, 'registerDevice response');
  },

  async secureRequest(options: SecureRequestOptions): Promise<SecureResponse> {
    if (!options || typeof options.url !== 'string' || options.url.length === 0) {
      throw new Error('SecureSDK: invalid url');
    }
    const bodyJson = JSON.stringify(options.body ?? {});
    if (bodyJson.length > MAX_BODY_BYTES) {
      throw new Error('SecureSDK: body too large');
    }
    const raw = await getNativeModule().secureRequestPinned(options.url, bodyJson, '');
    // Auto-handle step-up if required.
    const parsed = safeJsonParse<any>(raw, 'secureRequest response');
    if (parsed && parsed.ok === false && parsed.stepUpRequired === true && typeof parsed.challenge === 'string') {
      const keyId = String(parsed.keyId || '');
      const deviceId = String(parsed.deviceId || '');
      const reqPath = String(parsed.path || '');
      const method = String(parsed.method || 'POST');
      const payloadHash = String(parsed.payloadHash || '');
      if (!keyId || !deviceId || !reqPath) throw new Error('SecureSDK: step-up missing fields');
      if (!payloadHash) throw new Error('SecureSDK: step-up missing payloadHash');
      const msg = `stepup-v2|${keyId}|${method}|${reqPath}|${payloadHash}|${parsed.challenge}`;
      const signature = await getNativeModule().signStepUp(msg);
      const u = new URL(options.url);
      const verifyUrl = `${u.origin}/v1/stepup-verify`;
      const verifyRaw = await getNativeModule().pinnedPost(
        verifyUrl,
        JSON.stringify({ 'Content-Type': 'application/json' }),
        JSON.stringify({
          keyId,
          deviceId,
          platform: (await SecureSDK.getDeviceRegistrationPayload()).platform,
          method,
          path: reqPath,
          payloadHash,
          challenge: parsed.challenge,
          signature,
          attestationToken: options.stepUpAttestationToken,
        }),
      );
      const verify = safeJsonParse<any>(verifyRaw, 'stepUp verify response');
      if (!verify || verify.ok !== true || typeof verify.stepUpToken !== 'string') {
        throw new Error(`SecureSDK: step-up failed (${verify?.reason ?? 'unknown'})`);
      }
      const retryRaw = await getNativeModule().secureRequestPinned(options.url, bodyJson, verify.stepUpToken);
      return safeJsonParse<SecureResponse>(retryRaw, 'secureRequest retry response');
    }
    return parsed as SecureResponse;
  },

  /** Stable installation identifier (encrypted / Keychain), not raw OS vendor id. */
  async getDeviceId(): Promise<string> {
    return getNativeModule().getDeviceId();
  },

  async getSecurityStatus(): Promise<SecurityStatus> {
    const raw = await getNativeModule().getSecurityStatus();
    return safeJsonParse<SecurityStatus>(raw, 'security status');
  },
};
