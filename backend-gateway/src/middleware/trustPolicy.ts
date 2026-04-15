import type { EnvelopeInput } from '../secureEnvelope.js';
import type { DeviceRow } from '../deviceRepo.js';

export type TrustDecision =
  | { ok: true }
  | {
      ok: false;
      status: 401 | 403;
      reason:
        | 'device_not_trusted'
        | 'attestation_missing'
        | 'attestation_stale'
        | 'attestation_invalid'
        | 'step_up_required';
    };

function parseList(name: string): string[] {
  return (process.env[name] ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function evaluateTrustPolicy(input: {
  env: EnvelopeInput;
  device: DeviceRow;
  nowMs: number;
}): TrustDecision {
  const requirePaths = parseList('TRUST_REQUIRED_PATHS');
  const allowedIntegrity = parseList('TRUST_ALLOWED_INTEGRITY_LEVELS');
  const maxAgeMs = Number(process.env.TRUST_MAX_AGE_MS ?? 24 * 60 * 60_000);
  const high = Number(process.env.RISK_STEPUP_THRESHOLD ?? 80);

  const isSensitive = requirePaths.length > 0 ? requirePaths.includes(input.env.path) : true;

  // v2 policy: primary trust signals are server-verified attestation + trusted=true + freshness.
  // For secure forwarding, default to treating all routes as sensitive unless a path allowlist is provided.
  if (isSensitive) {
    if (!input.device.trusted) return { ok: false, status: 403, reason: 'device_not_trusted' };
    if (!input.device.attestationStatus || input.device.attestationStatus === 'none') {
      return { ok: false, status: 401, reason: 'attestation_missing' };
    }
    if (!input.device.verifiedAt) return { ok: false, status: 401, reason: 'attestation_missing' };
    // Attestation integrity is a primary trust signal. Default allowlist is strong/app_attest.
    const allowed = allowedIntegrity.length ? allowedIntegrity : ['strong', 'app_attest'];
    if (!input.device.integrityLevel || !allowed.includes(input.device.integrityLevel)) {
      return { ok: false, status: 401, reason: 'attestation_invalid' };
    }
    if (Number.isFinite(maxAgeMs) && maxAgeMs > 0) {
      const age = input.nowMs - input.device.verifiedAt.getTime();
      if (age > maxAgeMs) return { ok: false, status: 401, reason: 'attestation_stale' };
    }
  }

  // High-risk flow: require step-up auth, do not treat as "untrusted".
  if (input.env.riskScore >= high) {
    return { ok: false, status: 403, reason: 'step_up_required' };
  }

  return { ok: true };
}

