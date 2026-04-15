Implement step-up authentication flow.

Backend:

1. Detect step-up condition:
   - high risk
   - sensitive endpoint

2. Return:
   {
     stepUpRequired: true,
     challenge: <nonce>
   }

3. Verify step-up:
   - signed challenge
   - optional attestation

4. Issue token:
   - short-lived (e.g. 2–5 minutes)
   - scoped to endpoint/action

Client:

- Handle stepUpRequired
- Perform secure challenge response
- Retry request with token

Security:

- Token must be:
  - device-bound
  - non-reusable
  - short TTL