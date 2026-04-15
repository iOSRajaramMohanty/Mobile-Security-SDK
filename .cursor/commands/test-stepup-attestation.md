Add tests for step-up attestation.

Cases:
- missing attestation when required → reject
- invalid attestation → reject
- valid attestation → success

Ensure:
- bound to challenge
- single-use