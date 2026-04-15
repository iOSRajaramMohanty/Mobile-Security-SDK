import { Agent, fetch as undiciFetch } from 'undici';

export type ForwardingConfig = {
  upstreamBaseUrl: string;
  upstreamAuthToken: string;
  allowlistPaths: string[];
  upstreamTimeoutMs: number;
  maxPlaintextBytes: number;
  maxUpstreamResponseBytes: number;
  enforcePrivateNetwork: boolean;
  mtls: { enabled: boolean };
};

export type ForwardResult =
  | { ok: true; status: number; json: Record<string, unknown> }
  | { ok: false; reason: string; status?: number };

function parseIntEnv(name: string, def: number, min: number, max: number): number {
  const raw = process.env[name];
  const n = raw == null ? def : Number(raw);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

export function createForwardingConfigFromEnv(): { ok: true; value: ForwardingConfig } | { ok: false; reason: string } {
  const upstreamBaseUrl = process.env.INTERNAL_UPSTREAM_BASE_URL?.trim();
  if (!upstreamBaseUrl) return { ok: false, reason: 'internal_upstream_not_configured' };
  const upstreamAuthToken = process.env.INTERNAL_UPSTREAM_AUTH_TOKEN?.trim();
  if (!upstreamAuthToken) return { ok: false, reason: 'internal_upstream_auth_not_configured' };

  let u: URL;
  try {
    u = new URL(upstreamBaseUrl);
  } catch {
    return { ok: false, reason: 'invalid_internal_upstream_base_url' };
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, reason: 'invalid_internal_upstream_base_url' };
  }
  const prod = (process.env.NODE_ENV ?? '').toLowerCase() === 'production';
  if (prod && u.protocol !== 'https:') {
    return { ok: false, reason: 'internal_upstream_https_required' };
  }

  const mtls = mtlsConfigFromEnv(prod);
  if (!mtls.ok) return { ok: false, reason: mtls.reason };

  const allowlistPaths = (process.env.FORWARD_ALLOWLIST_PATHS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (allowlistPaths.length === 0) return { ok: false, reason: 'forward_allowlist_not_configured' };

  return {
    ok: true,
    value: {
      upstreamBaseUrl,
      upstreamAuthToken,
      allowlistPaths,
      upstreamTimeoutMs: parseIntEnv('INTERNAL_UPSTREAM_TIMEOUT_MS', 2_000, 100, 30_000),
      maxPlaintextBytes: parseIntEnv('MAX_DECRYPTED_PLAINTEXT_BYTES', 128 * 1024, 4 * 1024, 512 * 1024),
      maxUpstreamResponseBytes: parseIntEnv('MAX_UPSTREAM_RESPONSE_BYTES', 256 * 1024, 4 * 1024, 1024 * 1024),
      enforcePrivateNetwork: prod || process.env.ENFORCE_PRIVATE_UPSTREAM === '1',
      mtls: { enabled: mtls.enabled },
    },
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null) return false;
  if (Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function validateJsonShape(v: unknown, depth: number, maxDepth: number): boolean {
  if (depth > maxDepth) return false;
  if (v === null) return true;
  const t = typeof v;
  if (t === 'string') return (v as string).length <= 10_000;
  if (t === 'number') return Number.isFinite(v as number);
  if (t === 'boolean') return true;
  if (Array.isArray(v)) {
    if (v.length > 2_000) return false;
    return v.every((x) => validateJsonShape(x, depth + 1, maxDepth));
  }
  if (isPlainObject(v)) {
    const keys = Object.keys(v);
    if (keys.length > 1_000) return false;
    return keys.every((k) => k.length <= 200 && validateJsonShape((v as any)[k], depth + 1, maxDepth));
  }
  return false;
}

function isPrivateIp(ip: string): boolean {
  // Basic IPv4 private ranges + loopback + link-local.
  // This intentionally errs on the side of rejecting unknowns.
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80:');
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

async function enforcePrivateUpstreamHost(upstreamUrl: string): Promise<boolean> {
  const u = new URL(upstreamUrl);
  const host = u.hostname;
  if (host === 'localhost') return true;
  // If host is already an IP literal, check directly.
  if (isPrivateIp(host)) return true;
  // Resolve DNS and ensure all returned addresses are private.
  const dns = await import('node:dns/promises');
  try {
    const addrs = await dns.lookup(host, { all: true, verbatim: true });
    if (!addrs.length) return false;
    return addrs.every((a) => isPrivateIp(a.address));
  } catch {
    return false;
  }
}

type MtlsEnv = { ok: true; enabled: boolean } | { ok: false; reason: string };

function mtlsConfigFromEnv(prod: boolean): MtlsEnv {
  const cert = process.env.UPSTREAM_MTLS_CERT_PEM_B64?.trim();
  const key = process.env.UPSTREAM_MTLS_KEY_PEM_B64?.trim();
  const ca = process.env.UPSTREAM_CA_CERT_PEM_B64?.trim();
  const any = Boolean(cert || key || ca);
  if (!any) {
    if (prod) return { ok: false, reason: 'upstream_mtls_required' };
    return { ok: true, enabled: false };
  }
  if (!cert || !key || !ca) return { ok: false, reason: 'upstream_mtls_incomplete' };
  return { ok: true, enabled: true };
}

let cachedDispatcher: Agent | null = null;
function getMtlsDispatcher(): Agent {
  if (cachedDispatcher) return cachedDispatcher;
  const certPem = Buffer.from(process.env.UPSTREAM_MTLS_CERT_PEM_B64 ?? '', 'base64').toString('utf8');
  const keyPem = Buffer.from(process.env.UPSTREAM_MTLS_KEY_PEM_B64 ?? '', 'base64').toString('utf8');
  const caPem = Buffer.from(process.env.UPSTREAM_CA_CERT_PEM_B64 ?? '', 'base64').toString('utf8');
  cachedDispatcher = new Agent({
    connect: {
      rejectUnauthorized: true,
      cert: certPem,
      key: keyPem,
      ca: caPem,
    },
  });
  return cachedDispatcher;
}

export async function forwardToInternalService(input: {
  cfg: ForwardingConfig;
  path: string;
  payload: unknown;
  requestId: string | undefined;
  device: { keyId: string; deviceId: string; trusted: boolean; attestationStatus: string };
}): Promise<ForwardResult> {
  if (!input.cfg.allowlistPaths.includes(input.path)) {
    return { ok: false, reason: 'unknown_route', status: 404 };
  }
  // Defense-in-depth: _clientDek must never cross device boundary.
  if (isPlainObject(input.payload) && Object.prototype.hasOwnProperty.call(input.payload, '_clientDek')) {
    return { ok: false, reason: 'client_dek_present', status: 400 };
  }
  if (!isPlainObject(input.payload) || !validateJsonShape(input.payload, 0, 6)) {
    return { ok: false, reason: 'invalid_plaintext_schema', status: 400 };
  }

  if (!input.cfg.upstreamAuthToken) {
    return { ok: false, reason: 'internal_upstream_auth_not_configured', status: 503 };
  }
  if (input.cfg.enforcePrivateNetwork) {
    const ok = await enforcePrivateUpstreamHost(input.cfg.upstreamBaseUrl);
    if (!ok) return { ok: false, reason: 'upstream_not_private', status: 503 };
  }

  const upstreamUrl = new URL(input.path, input.cfg.upstreamBaseUrl).toString();
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), input.cfg.upstreamTimeoutMs);
  try {
    const upstream = await undiciFetch(upstreamUrl, {
      method: 'POST',
      signal: ctrl.signal,
      dispatcher: input.cfg.mtls.enabled ? getMtlsDispatcher() : undefined,
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Auth': input.cfg.upstreamAuthToken,
        'X-Request-Id': input.requestId ?? '',
        'X-Device-Key-Id': input.device.keyId,
        'X-Device-Id': input.device.deviceId,
        'X-Device-Trusted': input.device.trusted ? '1' : '0',
        'X-Attestation-Status': input.device.attestationStatus,
      },
      body: JSON.stringify(input.payload),
    });

    const raw = await upstream.text();
    if (raw.length > input.cfg.maxUpstreamResponseBytes * 2) {
      return { ok: false, reason: 'upstream_response_too_large', status: 502 };
    }
    let json: unknown = null;
    try {
      json = raw ? (JSON.parse(raw) as unknown) : {};
    } catch {
      return { ok: false, reason: 'invalid_upstream_response', status: 502 };
    }
    if (!isPlainObject(json) || !validateJsonShape(json, 0, 6)) {
      return { ok: false, reason: 'invalid_upstream_response', status: 502 };
    }
    return { ok: true, status: upstream.status, json };
  } catch (e) {
    const aborted = e instanceof Error && e.name === 'AbortError';
    return { ok: false, reason: aborted ? 'upstream_timeout' : 'upstream_failed', status: 502 };
  } finally {
    clearTimeout(t);
  }
}

