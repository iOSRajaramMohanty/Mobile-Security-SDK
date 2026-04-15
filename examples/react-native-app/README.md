# Example app — certificate pinning integration

This repo’s SDK does **not** perform networking. Certificate pinning must be enforced by the **host app** HTTP client.

## Pin format (standardized)

Use **SPKI SHA-256** pins:

- \(pin\) = `base64( SHA-256(SubjectPublicKeyInfo DER) )`

You can precompute pins from your backend’s leaf certificate public key.

## iOS (URLSession)

Use `PinnedURLSessionDelegate` from `SecuritySDK`:

```swift
import SecuritySDK

let pins = [
  "<base64 spki sha256 pin>",
]

let cfg = URLSessionConfiguration.ephemeral
let session = URLSession(configuration: cfg, delegate: PinnedURLSessionDelegate(allowedSpkiSha256Base64: pins), delegateQueue: nil)
```

## Android (OkHttp)

If you use OkHttp, configure certificate pinning using OkHttp’s `CertificatePinner` with **SPKI pins**.

This SDK provides a low-level `PinnedTrustManager`-style helper for `HttpsURLConnection` (`android-sdk/.../CertificatePinning.kt`),
but for OkHttp you should prefer OkHttp’s built-in pinning primitives.

Pseudo-example:

```kotlin
val pinner = CertificatePinner.Builder()
  .add("api.example.com", "sha256/<base64 spki sha256 pin>")
  .build()
val client = OkHttpClient.Builder().certificatePinner(pinner).build()
```

