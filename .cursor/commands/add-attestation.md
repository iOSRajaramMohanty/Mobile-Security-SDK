Add device attestation support.

Android:
- Play Integrity API

iOS:
- App Attest

Flow:
- App sends attestation during registration
- Backend verifies attestation
- Mark device as trusted

Output:
- Attestation verification service
- SDK integration hooks