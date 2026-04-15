## SDK Developer Guide

This guide covers **installation**, **setup**, `secureRequest` usage, error handling, and a short **security model** overview for:

- Android (`android-sdk/` AAR)
- iOS (`ios-sdk/` Swift Package)
- React Native (`react-native-sdk/` npm package + native modules)

### Security model (high level)

- **On-device**:
  - A hardware-backed (non-exportable) **ECDSA P‑256 signing key** signs a canonical request envelope.
  - A random per-request **DEK** encrypts payload with **AES‑256‑GCM**.
  - DEK is wrapped using **ECDH P‑256** with the server public key → HKDF → AES‑GCM.
  - Runtime signals produce a `riskScore` and `findings` (telemetry; server makes trust decisions).
- **Backend gateway**:
  - Looks up the device public key by `keyId` from a **DB registry**.
  - Verifies signature **before** decrypting.
  - Enforces **replay protection** (Redis), **device trust**, and **attestation freshness + integrity level**.
  - Forwards decrypted payload to an **internal upstream** via **mTLS + upstream auth**, then encrypts the upstream response so **no plaintext leaves the gateway**.

### React Native (recommended integration)

#### Install

From a published package:

```bash
npm i @banking/mobile-security-sdk
```

From this repo (workspace):

```bash
cd Mobile-Security-SDK
npm i
npm run build:rn
```

#### Setup (required)

```ts
import { SecureSDK } from '@banking/mobile-security-sdk';

await SecureSDK.init();
await SecureSDK.configureServerPublicKey("<base64 SPKI DER of server ECDH P-256 public key>");
await SecureSDK.configurePinning("api.example.com", ["<base64 spki sha256 pin>"]);
```

#### Device enrollment (recommended)

The gateway expects devices to be registered before calling `/v1/secure`.

```ts
const result = await SecureSDK.registerDevice({ baseUrl: "https://api.example.com" });
if (!result.ok) throw new Error(result.reason);
```

If attestation is enabled for registration, pass `attestationToken` as provided by your host app’s attestation integration.

#### `secureRequest` usage

```ts
const res = await SecureSDK.secureRequest({
  url: "https://api.example.com/internal/payments/authorize",
  body: { amount: 1000, currency: "USD" },
});

// res.body is plaintext JSON (decrypted in native code).
console.log(res.statusCode, res.body);
```

#### Step-up authentication (server-driven)

The backend can require step-up when a device is deemed high-risk (e.g. `riskScore` crosses the configured threshold). In that case, `/v1/secure` returns a challenge and the SDK performs an automatic verify-and-retry flow.

- **Backend response**: `{ ok:false, stepUpRequired:true, challenge, payloadHash, method, path, keyId, deviceId, expiresAtMs }`
- **Verify**: SDK signs a step-up message and calls `/v1/stepup-verify`
- **Retry**: SDK retries the original request with `X-StepUp-Token: <token>`

**Developer responsibilities**

- **Keep step-up enabled**: do not bypass the SDK by calling your sensitive upstream endpoints directly from JS.
- **If your backend enables step-up attestation** (`STEPUP_REQUIRE_ATTESTATION=1`): you must provide an attestation token for the step-up verify call (see `stepUpAttestationToken` below).

**React Native example (attested step-up)**

```ts
const res = await SecureSDK.secureRequest({
  url: "https://api.example.com/transfer",
  body: { amount: 1000, currency: "USD" },
  // Required only if backend sets STEPUP_REQUIRE_ATTESTATION=1
  stepUpAttestationToken: "<your attestation token>",
});
```

#### Error handling

- JS errors are **redacted** (no native stacks).
- Backend rejections return `{ ok: false, reason: <code> }` internally; the RN API surfaces failures as thrown errors or error-shaped responses depending on the call.

Common backend rejection reasons you may see:

- `unknown_key`, `bad_signature`, `replay`, `stale_timestamp`
- `device_not_trusted`, `attestation_missing`, `attestation_invalid`, `attestation_stale`
- `step_up_required`

### Android (AAR)

#### Build AAR (from repo)

Android requires an SDK path configured via `ANDROID_HOME` / `ANDROID_SDK_ROOT` or `android-sdk/local.properties`:

```properties
sdk.dir=/absolute/path/to/Android/sdk
```

Build:

```bash
cd Mobile-Security-SDK/android-sdk
./gradlew :security-sdk:assembleRelease
```

The AAR will be at:

- `android-sdk/security-sdk/build/outputs/aar/security-sdk-release.aar`

#### ProGuard / R8

Consumer rules are shipped in:

- `android-sdk/security-sdk/consumer-rules.pro`

### iOS (Swift Package)

#### Add package

Add the Swift Package located at:

- `Mobile-Security-SDK/ios-sdk`

#### Build

```bash
cd Mobile-Security-SDK/ios-sdk
swift build -c release
```

### Backend gateway deployment notes (required for production)

Minimum required env (production):

- **Crypto**: `SERVER_EC_PRIVATE_PEM` or `SERVER_EC_PRIVATE_PEM_B64`
- **DB**: `DATABASE_URL`
- **Replay / rate limit**: `REDIS_URL`
- **Forwarding**: `INTERNAL_UPSTREAM_BASE_URL`, `INTERNAL_UPSTREAM_AUTH_TOKEN`, `FORWARD_ALLOWLIST_PATHS`
- **mTLS**: `UPSTREAM_MTLS_CERT_PEM_B64`, `UPSTREAM_MTLS_KEY_PEM_B64`, `UPSTREAM_CA_CERT_PEM_B64`
- **Trust**: `REQUIRE_ATTESTATION=1`

### Validations

From repo root:

```bash
cd Mobile-Security-SDK
npm run validate:phase4
npm run validate:production
npm run validate:bank-grade
```

