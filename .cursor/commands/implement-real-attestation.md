Replace demo attestation with production-grade verification.

Android:
- Integrate Play Integrity API
- Verify:
  - device integrity
  - app integrity
  - nonce binding

iOS:
- Integrate App Attest
- Verify:
  - challenge-response
  - key binding
  - bundle ID

Backend:
- Validate tokens using official APIs
- Bind attestation to:
  - deviceId
  - keyId

Reject:
- Invalid tokens
- Replayed tokens
- Mismatched app/device

Output:
- Attestation service
- SDK integration
- Verification middleware