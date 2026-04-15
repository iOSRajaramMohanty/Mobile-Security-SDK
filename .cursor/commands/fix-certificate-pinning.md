Enforce certificate pinning integration.

Requirements:

Android:
- OkHttp client with pinned certs

iOS:
- URLSession with pinning delegate

Deliver:
- SDK helper to create pinned client
- Example integration in RN app

Fix:
- Clarify SPKI vs raw key hashing
- Standardize pin format (SPKI SHA-256)