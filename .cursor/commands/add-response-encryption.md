Implement response encryption.

Flow:
1. Backend receives internal service response
2. Encrypt response using device public key
3. Sign response (optional)
4. Return encrypted payload

Ensure:
- Same hybrid encryption model
- No plaintext leaves gateway