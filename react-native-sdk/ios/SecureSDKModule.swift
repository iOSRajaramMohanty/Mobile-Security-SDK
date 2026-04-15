import Foundation
import React
import CryptoKit

/**
 * React Native iOS bridge — **thin wrapper only**.
 *
 * All crypto, keys, and envelopes are implemented in `SecuritySdk` (Swift sources under `ios-sdk/`),
 * compiled into this pod. Do not add business logic here; keep a single source of truth in the SDK.
 *
 * Objective-C (`SecureSDKBridge.m`) declares `RCT_EXTERN_MODULE` only — no duplicate implementations.
 */
@objc(SecureSDK)
final class SecureSDK: NSObject {
    private let maxBodyBytes = 256 * 1024
    private let maxKeyChars = 8 * 1024
    private var pinnedHost: String?
    private var pinnedPins: [String] = []

    @objc static func requiresMainQueueSetup() -> Bool {
        false
    }

    private func rejectSafe(_ reject: RCTPromiseRejectBlock, code: String, _ error: Error?) {
        // Do not pass raw exceptions / stacks to JS.
        let msg = error?.localizedDescription ?? "failed"
        reject(code, msg, nil)
    }

    @objc func initialize(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            try SecuritySdk.initSdk()
            resolve(nil)
        } catch {
            rejectSafe(reject, code: "E_INIT", error)
        }
    }

    @objc func configureServerPublicKey(_ base64: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        if base64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || base64.count > maxKeyChars {
            reject("E_CONFIG", "invalid server public key", nil)
            return
        }
        do {
            try SecuritySdk.configureServerPublicKeyFromBase64(base64)
            resolve(nil)
        } catch {
            rejectSafe(reject, code: "E_CONFIG", error)
        }
    }

    @objc func configurePinning(_ configJson: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        if configJson.count > maxBodyBytes {
            reject("E_PIN", "config too large", nil)
            return
        }
        guard let data = configJson.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let host = obj["host"] as? String,
              let pins = obj["pins"] as? [String],
              !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !pins.isEmpty else {
            reject("E_PIN", "invalid pinning config", nil)
            return
        }
        self.pinnedHost = host
        self.pinnedPins = pins
        resolve(nil)
    }

    @objc func getPublicKey(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            resolve(try SecuritySdk.getPublicKey())
        } catch {
            rejectSafe(reject, code: "E_PUBLIC_KEY", error)
        }
    }

    @objc func rotateKeys(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            try SecuritySdk.rotateKeys()
            resolve(nil)
        } catch {
            rejectSafe(reject, code: "E_ROTATE", error)
        }
    }

    @objc func getDeviceRegistrationPayload(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            let p = try SecuritySdk.getDeviceRegistrationPayload()
            resolve(try Self.jsonString(from: p))
        } catch {
            rejectSafe(reject, code: "E_REG", error)
        }
    }

    @objc func secureRequest(_ path: String, bodyJson: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        if path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            reject("E_REQUEST", "invalid path", nil)
            return
        }
        if let d = bodyJson.data(using: .utf8), d.count > maxBodyBytes {
            reject("E_REQUEST", "body too large", nil)
            return
        }
        do {
            guard let data = bodyJson.data(using: .utf8),
                  let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                reject("E_REQUEST", "Invalid JSON body", nil)
                return
            }
            let res = try SecuritySdk.secureRequest(path: path, body: obj)
            let payload: [String: Any] = [
                "statusCode": res.statusCode,
                "headers": res.headers,
                "body": res.body,
            ]
            resolve(try Self.jsonString(from: payload))
        } catch {
            rejectSafe(reject, code: "E_REQUEST", error)
        }
    }

    @objc func pinnedPost(_ url: String, headersJson: String, bodyJson: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        do {
            let raw = try pinnedHttpPost(url: url, headersJson: headersJson, bodyJson: bodyJson)
            resolve(raw)
        } catch {
            rejectSafe(reject, code: "E_HTTP", error)
        }
    }

    @objc func secureRequestPinned(_ url: String, bodyJson: String, stepUpToken: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        do {
            guard let data = bodyJson.data(using: .utf8),
                  let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                reject("E_REQUEST", "Invalid JSON body", nil)
                return
            }
            let envRes = try SecuritySdk.secureRequest(path: url, body: obj)
            // Extract local-only DEK and strip it before network forwarding.
            let dekB64 = (envRes.body["_clientDek"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            var bodyFiltered = envRes.body
            bodyFiltered.removeValue(forKey: "_clientDek")
            let payload: [String: Any] = [
                "statusCode": envRes.statusCode,
                "headers": envRes.headers,
                "body": bodyFiltered,
            ]
            let rawBody = try Self.jsonString(from: payload)
            var headers: [String: String] = ["Content-Type": "application/json"]
            if !stepUpToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                headers["X-StepUp-Token"] = stepUpToken
            }
            let raw = try pinnedHttpPost(url: url, headersJson: try Self.jsonString(from: headers), bodyJson: rawBody)
            // Expect encrypted gateway response; decrypt locally and return plaintext SecureResponse shape.
            if let d = raw.data(using: .utf8),
               let respObj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
               let ok = respObj["ok"] as? Bool, ok == true,
               let enc = respObj["enc"] as? [String: Any],
               let iv = enc["aesIv"] as? String,
               let ct = enc["ciphertext"] as? String,
               let tag = enc["aesTag"] as? String,
               let dek = dekB64,
               let plain = try? decryptAesGcm(keyB64: dek, ivB64: iv, ctB64: ct, tagB64: tag),
               let plainData = plain.data(using: .utf8),
               let plainJson = try? JSONSerialization.jsonObject(with: plainData) as? [String: Any] {
                let out: [String: Any] = [
                    "statusCode": respObj["statusCode"] as? Int ?? 200,
                    "headers": respObj["headers"] as? [String: Any] ?? [:],
                    "body": plainJson,
                ]
                resolve(try Self.jsonString(from: out))
                return
            }
            resolve(raw)
        } catch {
            rejectSafe(reject, code: "E_REQUEST", error)
        }
    }

    @objc func signStepUp(_ message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        if message.count > maxBodyBytes {
            reject("E_SIGN", "message too large", nil)
            return
        }
        do {
            let sig = try SecuritySdk.sign(data: Data(message.utf8))
            resolve(sig.base64EncodedString())
        } catch {
            rejectSafe(reject, code: "E_SIGN", error)
        }
    }

    private func pinnedHttpPost(url: String, headersJson: String, bodyJson: String) throws -> String {
        guard let host = pinnedHost, !pinnedPins.isEmpty else {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "pinning not configured"])
        }
        guard let u = URL(string: url), u.scheme?.lowercased() == "https", u.host?.lowercased() == host.lowercased() else {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "https required / host mismatch"])
        }
        guard let body = bodyJson.data(using: .utf8) else {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "utf8 encode failed"])
        }
        if body.count > maxBodyBytes {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "body too large"])
        }

        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        req.httpBody = body

        if let hData = headersJson.data(using: .utf8),
           let hObj = try? JSONSerialization.jsonObject(with: hData) as? [String: Any] {
            for (k, v) in hObj {
                if let s = v as? String, !s.isEmpty {
                    req.setValue(s, forHTTPHeaderField: k)
                }
            }
        }

        let cfg = URLSessionConfiguration.ephemeral
        let session = URLSession(
            configuration: cfg,
            delegate: PinnedURLSessionDelegate(allowedSpkiSha256Base64: pinnedPins),
            delegateQueue: nil
        )

        let sem = DispatchSemaphore(value: 0)
        var outData: Data?
        var outResp: URLResponse?
        var outErr: Error?
        session.dataTask(with: req) { d, r, e in
            outData = d
            outResp = r
            outErr = e
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 20)

        if let e = outErr { throw e }
        guard let http = outResp as? HTTPURLResponse else {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "no response"])
        }
        guard (200...299).contains(http.statusCode) else {
            throw NSError(domain: "SecureSDK", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "http_\(http.statusCode)"])
        }
        return String(data: outData ?? Data(), encoding: .utf8) ?? ""
    }

    @objc func getDeviceId(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            resolve(try SecuritySdk.getDeviceId())
        } catch {
            rejectSafe(reject, code: "E_DEVICE_ID", error)
        }
    }

    @objc func getSecurityStatus(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        let s = SecuritySdk.getSecurityStatus()
        let dict: [String: Any] = [
            "riskScore": s.riskScore,
            "findings": s.findings,
        ]
        do {
            resolve(try Self.jsonString(from: dict))
        } catch {
            rejectSafe(reject, code: "E_STATUS", error)
        }
    }

    private static func jsonString(from object: [String: Any]) throws -> String {
        let d = try JSONSerialization.data(withJSONObject: object, options: [])
        guard let s = String(data: d, encoding: .utf8) else {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "UTF-8 encode failed"])
        }
        return s
    }

    private func decryptAesGcm(keyB64: String, ivB64: String, ctB64: String, tagB64: String) throws -> String {
        guard let key = Data(base64Encoded: keyB64),
              let iv = Data(base64Encoded: ivB64),
              let ct = Data(base64Encoded: ctB64),
              let tag = Data(base64Encoded: tagB64) else {
            throw NSError(domain: "SecureSDK", code: 0, userInfo: [NSLocalizedDescriptionKey: "invalid enc fields"])
        }
        let sealed = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct, tag: tag)
        let plain = try AES.GCM.open(sealed, using: SymmetricKey(data: key))
        return String(data: plain, encoding: .utf8) ?? ""
    }
}
