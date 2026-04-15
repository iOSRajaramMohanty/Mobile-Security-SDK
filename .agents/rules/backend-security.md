Backend Security Rules:

REQUEST VALIDATION:
- Verify signature before processing
- Validate nonce uniqueness
- Validate timestamp (expiry window)

CRYPTO:
- Use secure libraries (libsodium/OpenSSL)
- Never store plaintext sensitive data

DEVICE TRUST:
- Bind requests to device public key
- Reject unknown devices

ERROR HANDLING:
- Do not leak internal details
- Return generic errors

LOGGING:
- No sensitive data in logs
- Log only metadata

RATE LIMITING:
- Prevent abuse
- Detect anomalies