Goal: Build a Banking-Grade Mobile Security SDK with React Native support

Platforms:
- Android SDK (Kotlin)
- iOS SDK (Swift)
- React Native Wrapper (Bridge + optional JSI)
- Backend Secure Gateway (Node.js)

Phases:
1. Monorepo setup
2. Core crypto module
3. Key management module
4. Secure communication layer
5. Runtime protection module
6. Backend secure gateway
7. React Native bridge module
8. SDK packaging (Android/iOS/npm)
9. Developer API design
10. Security testing
11. Documentation + example apps

Constraints:
- NO cryptography in JavaScript layer
- Private keys MUST remain in native secure storage
- RN acts only as a bridge layer
- All requests must be encrypted + signed

Deliverables:
- AAR (Android)
- Swift Package (iOS)
- npm package (React Native SDK)
- Backend gateway
- Example RN app

Now:
Generate updated folder structure including React Native layer.