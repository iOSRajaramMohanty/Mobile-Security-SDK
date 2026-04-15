Remove or disable demo attestation.

Requirements:

- Delete backend-gateway/src/attestation.ts
OR
- Throw error if used in production

Add:
- Build-time check to fail if imported

Goal:
- Ensure only real attestation exists