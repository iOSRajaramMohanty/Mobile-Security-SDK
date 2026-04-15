Enhance step-up token binding.

Bind token to:
- deviceId
- keyId
- path
- HTTP method
- payload hash (optional, recommended for POST)

Reject if mismatch.

Goal:
Prevent token reuse across modified requests