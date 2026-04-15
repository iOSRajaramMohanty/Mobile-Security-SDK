Create a production-grade monorepo:

/security-sdk
  /android-sdk
  /ios-sdk
  /react-native-sdk
  /backend-gateway
  /shared-spec
  /docs
  /examples
    /react-native-app

Requirements:
- React Native package must be npm-ready
- Use TypeScript for RN layer
- Separate native bindings:
  - android/
  - ios/

Output:
- Folder structure
- package.json (RN + backend)
- Gradle setup
- Swift package setup