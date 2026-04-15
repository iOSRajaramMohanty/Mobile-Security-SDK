Refine trust policy.

Rules:

Primary trust signals:
- attestation integrity level
- trusted = true
- verified_at freshness

Secondary:
- riskScore (telemetry only)

High-risk flow:
- require step-up auth
- NOT immediate trust rejection

Reject:
- devices without valid attestation