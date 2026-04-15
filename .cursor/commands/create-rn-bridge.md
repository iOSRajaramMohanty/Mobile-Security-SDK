Build React Native bridge module for the Security SDK.

Requirements:
- Expose native SDK (Android + iOS) to JS
- Use Native Modules (and optionally JSI for performance)
- Use TypeScript definitions

APIs to expose:
- init()
- secureRequest()
- getDeviceId()
- getSecurityStatus()

Constraints:
- NO crypto logic in JS
- NO private key exposure
- All operations must call native SDK

Output:
- index.ts (public API)
- NativeModule bridge (Android/iOS)
- Type definitions
- Error handling