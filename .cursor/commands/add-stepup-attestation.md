Enhance step-up verification with attestation.

Add optional field:
- attestationToken

Flow:
1. Client includes attestationToken in /v1/stepup-verify
2. Backend verifies:
   - token validity
   - nonce binding to step-up challenge
   - deviceId + keyId match

Config:
- STEPUP_REQUIRE_ATTESTATION=1

If enabled:
- reject step-up without valid attestation

Goal:
- prevent compromised device replaying step-up