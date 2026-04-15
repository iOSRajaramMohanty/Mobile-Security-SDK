Upgrade backend to secure gateway.

Implement:
- Signature verification
- AES decryption
- Nonce store (Redis or in-memory)
- Timestamp validation (30s window)

Remove:
- req.body echo
- unsecured endpoints

Add:
- request validation middleware