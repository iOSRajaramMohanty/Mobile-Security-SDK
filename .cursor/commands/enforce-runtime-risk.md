Use runtime security signals in backend.

Flow:
- SDK sends riskScore
- Backend evaluates risk

Rules:
- High risk → reject or step-up auth
- Medium risk → flag/log
- Low risk → allow

Note:
- Do NOT trust blindly
- Combine with attestation