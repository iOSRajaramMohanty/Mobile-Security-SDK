Harden secure gateway.

Add:
- Rate limiting per deviceId
- Request size limits
- Strict schema validation
- Timeout handling for internal services

Reject:
- Unknown routes
- Invalid schemas
- Oversized payloads