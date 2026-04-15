Fix backend signature verification.

Current issue:
- Uses public key from request (INSECURE)

Fix:

1. Extract deviceId or keyId from request
2. Lookup public key from DB
3. Verify signature using stored key ONLY

Reject if:
- Key not registered
- Key mismatch

Remove:
- Trusting client-provided public key