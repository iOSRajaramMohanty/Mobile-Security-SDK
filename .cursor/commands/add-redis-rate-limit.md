Replace in-memory rate limiter with Redis-based limiter.

Requirements:

- Keyed by deviceId
- Sliding window or token bucket
- Shared across instances

Limits:
- configurable per endpoint
- stricter for sensitive actions

Reject:
- excessive requests

Output:
- Redis limiter middleware
- integration with gateway