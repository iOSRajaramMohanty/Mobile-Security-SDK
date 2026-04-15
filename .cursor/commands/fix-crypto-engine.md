Replace all stubbed secureRequest implementations.

Implement:

- AES-256-GCM encryption
- Random IV generation
- Authentication tag validation
- ECC key exchange (Curve25519 or P-256)
- ECDSA signing

Flow:
1. Generate AES key
2. Encrypt payload
3. Encrypt AES key using server public key
4. Sign request

Output:
- Android (Kotlin)
- iOS (Swift)
- Unit tests

Remove:
- All "Not implemented"
- All placeholder responses