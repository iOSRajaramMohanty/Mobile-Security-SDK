Enforce strict handling of _clientDek.

Rules:

1. Reject if _clientDek is present in request payload
2. Strip _clientDek before:
   - logging
   - forwarding
   - validation

3. Add validator:
- Fail build if _clientDek appears in logs or API

4. Add runtime assertion:
- If _clientDek detected → reject request

Goal:
- Ensure _clientDek NEVER leaves device boundary