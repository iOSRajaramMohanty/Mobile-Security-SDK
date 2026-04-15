Enforce trust policy on backend.

Rules:

1. Sensitive endpoints require:
   - trusted = true
   - valid attestation
   - recent verified_at (e.g., < 24h)

2. riskScore:
   - used for telemetry only
   - NOT primary trust signal

3. High-risk:
   - trigger step-up auth or reject

4. Reject if:
   - attestation missing
   - device not trusted

Output:
- trust validation middleware