Prevent race condition in step-up token consumption.

Use:
- atomic Redis operation

Ensure:
- token can be consumed only once globally
- concurrent requests → only one passes