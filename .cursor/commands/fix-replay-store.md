Enforce production-grade replay protection.

Requirements:
- Redis REQUIRED in production
- No in-memory fallback allowed

Nonce rules:
- Unique per device key
- Expire after short TTL (30–60s)

Reject:
- Duplicate nonce