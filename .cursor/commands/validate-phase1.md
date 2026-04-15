Validate Phase 1 (Monorepo Setup)

Checks:

1. PROJECT STRUCTURE
- Ensure folders exist:
  - android-sdk
  - ios-sdk
  - react-native-sdk
  - backend-gateway
  - shared-spec
  - examples

2. BACKEND
- backend-gateway runs without errors
- /health endpoint responds

3. REACT NATIVE SDK
- TypeScript compiles without errors
- Exports correct API:
  - init
  - secureRequest
  - getSecurityStatus

4. ANDROID SDK
- Gradle builds successfully

5. iOS SDK
- Swift package resolves correctly

6. SECURITY BASELINE
- No crypto implemented yet
- No secrets in code
- No sensitive logs

Output:
- PASS / FAIL per section
- Fix suggestions if failed