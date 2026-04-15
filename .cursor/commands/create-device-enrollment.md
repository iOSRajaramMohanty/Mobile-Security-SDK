Implement device enrollment system.

Flow:

1. App generates device key pair (already exists)
2. App calls:
   POST /v1/register-device

Payload:
- devicePublicKey
- deviceId
- optional attestation token

Backend:
- Store devicePublicKey
- Bind to deviceId/userId
- Return deviceToken

Rules:
- Reject duplicate registrations (or rotate safely)
- Store keys securely

Output:
- Backend API
- DB schema
- SDK integration