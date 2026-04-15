import { createForwardingConfigFromEnv } from './forwarding.js';

export type ProdConfigCheckResult = { ok: true } | { ok: false; reason: string };

function isProd(): boolean {
  return (process.env.NODE_ENV ?? '').toLowerCase() === 'production';
}

function mustEnv(name: string): string | null {
  const v = process.env[name]?.trim();
  return v ? v : null;
}

export function assertProductionConfig(): void {
  if (!isProd()) return;

  // Never allow test-only attestation in production.
  if ((process.env.ATTESTATION_MODE ?? '').toLowerCase() === 'hmac') {
    throw new Error('config_invalid:ATTESTATION_MODE_hmac_forbidden_in_production');
  }

  // REDIS_URL is required by nonceStore in prod, but we fail fast here too.
  if (!mustEnv('REDIS_URL')) throw new Error('config_invalid:missing_REDIS_URL');

  // Forwarding config must be valid (includes upstream URL/auth/allowlist/private network).
  const fwd = createForwardingConfigFromEnv();
  if (!fwd.ok) throw new Error(`config_invalid:${fwd.reason}`);

  // Secure endpoint must be configured with a server private key.
  const pem = mustEnv('SERVER_EC_PRIVATE_PEM') ?? mustEnv('SERVER_EC_PRIVATE_PEM_B64');
  if (!pem) throw new Error('config_invalid:missing_SERVER_EC_PRIVATE_PEM');

  // Trust policy: in production we should not allow unauthenticated/untrusted access.
  // Require attestation enforcement for registrations.
  if (mustEnv('REQUIRE_ATTESTATION') !== '1') {
    throw new Error('config_invalid:REQUIRE_ATTESTATION_must_be_1');
  }
}

