Harden attestation verification.

Enforce:

- Nonce must match server-issued challenge
- Nonce must be single-use (store + expire)
- Attestation must match:
  - deviceId
  - keyId
  - package/bundle ID

Android:
- Require strongIntegrity (or configured level)

iOS:
- Verify App Attest key binding
- Verify assertion signature chain

Store:
- attestationStatus
- integrityLevel
- verifiedAt

Reject:
- any mismatch
- replayed attestation