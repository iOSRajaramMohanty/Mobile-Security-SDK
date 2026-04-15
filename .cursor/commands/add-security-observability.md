Add security telemetry.

Log events:
- unknown_key
- replay_detected
- high_risk_device
- attestation_failure
- signature_failure

Metrics:
- request success rate
- rejection reasons
- riskScore distribution

Requirements:
- No sensitive data in logs
- Structured logging (JSON)

Output:
- logging middleware
- metrics hooks