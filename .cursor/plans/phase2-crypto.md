Goal: Implement Banking-Grade Crypto + Key Management

Scope:
1. AES-256-GCM encryption (payload)
2. ECC key pair generation (hardware-backed)
3. ECDSA signing
4. Hybrid encryption flow
5. Nonce + timestamp system

Platforms:
- Android (Keystore)
- iOS (Secure Enclave)

Constraints:
- No fallback to insecure storage
- No plaintext payload transmission
- All crypto must be native

Deliverables:
- encrypt()
- decrypt()
- sign()
- verify()
- keyManager (secure hardware)
- unit tests

Exit Criteria:
- No stub functions remain
- All requests encrypted + signed