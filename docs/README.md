# Mobile Security SDK — docs

This repository follows the layout described in `.cursor/commands/setup-monorepo.md` (packages live at the repo root; there is no extra `security-sdk/` directory).

Monorepo layout:

- `android-sdk` — Kotlin library (AAR) for core controls
- `ios-sdk` — Swift Package for core controls
- `react-native-sdk` — TypeScript bridge + thin native bindings (no crypto in JS)
- `backend-gateway` — Node.js verification / decryption service
- `shared-spec` — API contracts (OpenAPI, schemas)
- `examples/react-native-app` — example host RN application

Run `npm install` at the repository root, then `npm run build:rn` to compile the React Native package TypeScript.

Android (`android-sdk`): use **JDK 17** for the Gradle daemon (`export JAVA_HOME` to a Java 17 install). Then `./gradlew :security-sdk:assembleRelease`.

## Developer guide

Start here:

- `docs/sdk-developer-guide.md`

## Security testing

- `docs/pentest-checklist.md`

Automated checks (from `Mobile-Security-SDK/`):

- `npm run validate:bank-grade` (includes `npm run test:stepup-race`)
