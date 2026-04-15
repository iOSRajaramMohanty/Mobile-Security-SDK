Implement hardware-backed key management.

Android:
- Use Android Keystore
- Generate EC key pair
- Mark as non-exportable

iOS:
- Use Secure Enclave
- Generate key pair with access control

Features:
- getPublicKey()
- rotateKeys()
- secure initialization

Remove:
- Any placeholder device ID logic

Add:
- Device registration flow