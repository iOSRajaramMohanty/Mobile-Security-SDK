Harden /v1/stepup-verify endpoint.

Add:

1. Strict rate limiting:
- per deviceId
- lower threshold than /v1/secure

2. Abuse detection:
- track repeated failures
- track high frequency requests

3. Monitoring:
- emit metrics:
  - stepup_verify_attempts
  - stepup_verify_failures

4. Optional:
- IP-based throttling (defense-in-depth)

Reject:
- excessive attempts