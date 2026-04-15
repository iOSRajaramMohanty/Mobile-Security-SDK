Add step-up security logs.

Log events:
- step_up_required
- step_up_verified
- step_up_failed
- step_up_token_used

Include:
- deviceId
- keyId
- path
- result

Ensure:
- no sensitive payload logged