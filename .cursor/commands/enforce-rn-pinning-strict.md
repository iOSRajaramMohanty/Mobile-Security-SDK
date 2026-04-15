Enforce strict pinning in React Native.

Rules:
- secureRequest MUST use native pinned client
- registerDevice MUST use pinned client
- Disallow fetch for secure endpoints

Fail build if:
- fetch used for secure APIs