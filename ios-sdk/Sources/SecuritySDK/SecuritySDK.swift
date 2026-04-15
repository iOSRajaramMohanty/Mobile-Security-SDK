import CryptoKit
import Darwin
import Foundation
import Security

/// Native-only security facade (Secure Enclave / Keystore-grade signing). No JavaScript.
public enum SecuritySdk {
    private static var serverSpki: Data?
    private static let signer = KeychainSigner()

    /// Initializes hardware-backed signing (Secure Enclave when available) and installation identity.
    public static func initSdk() throws {
        try signer.warmUp()
        _ = try InstallationIdentity.getOrCreateId()
    }

    public static func configureServerPublicKey(spkiDer: Data) throws {
        _ = try EcSpki.x963FromSecp256r1Spki(spkiDer)
        serverSpki = spkiDer
    }

    public static func configureServerPublicKeyFromBase64(_ b64: String) throws {
        guard let data = Data(base64Encoded: b64) else {
            throw NSError(domain: "SecuritySdk", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid base64"])
        }
        try configureServerPublicKey(spkiDer: data)
    }

    /// ECDSA P-256 signing public key (SPKI DER), Base64 — for device registration.
    public static func getPublicKey() throws -> String {
        try signer.signingPublicKeySpki().base64EncodedString()
    }

    /// Rotates the signing key (invalidates prior material in Secure Enclave / Keychain).
    public static func rotateKeys() throws {
        try signer.rotateKeys()
    }

    /// Values to send to your registration endpoint.
    public static func getDeviceRegistrationPayload() throws -> [String: Any] {
        let installationId = try InstallationIdentity.getOrCreateId()
        let pubB64 = try signer.signingPublicKeySpki().base64EncodedString()
        return [
            "installationId": installationId,
            "signingPublicKeySpki": pubB64,
            "platform": "ios",
        ]
    }

    public struct SecureResponse {
        public let statusCode: Int
        public let headers: [String: String]
        public let body: [String: Any]

        public init(statusCode: Int, headers: [String: String], body: [String: Any]) {
            self.statusCode = statusCode
            self.headers = headers
            self.body = body
        }
    }

    public static func secureRequest(path: String, body: [String: Any]) throws -> SecureResponse {
        guard let spki = serverSpki else {
            throw NSError(domain: "SecuritySdk", code: 2, userInfo: [NSLocalizedDescriptionKey: "configure server public key first"])
        }
        let plain = try JSONSerialization.data(withJSONObject: body, options: [])
        let (host, p) = parseHostAndPath(path)
        let risk = getSecurityStatus().riskScore
        let env = try HybridEnvelopeIOS.build(
            method: "POST",
            host: host,
            contentType: "application/json",
            riskScore: risk,
            path: p,
            plaintext: plain,
            serverPublicSpki: spki,
            signer: signer
        )
        return SecureResponse(statusCode: 200, headers: ["Content-Type": "application/json"], body: env)
    }

    public static func sign(data: Data) throws -> Data {
        try signer.sign(data: data)
    }

    /// Stable installation id (Keychain), for registration — not a raw vendor id.
    public static func getDeviceId() throws -> String {
        try InstallationIdentity.getOrCreateId()
    }

    public struct SecurityStatus {
        /// 0..100 (higher = riskier runtime).
        public let riskScore: Int
        /// Array of stable string codes describing findings.
        public let findings: [String]

        public init(riskScore: Int, findings: [String]) {
            self.riskScore = max(0, min(100, riskScore))
            self.findings = Array(Set(findings))
        }
    }

    public static func getSecurityStatus() -> SecurityStatus {
        var findings: [String] = []
        var score = 0

        let isSim = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
        if isSim {
            findings.append("simulator")
            score += 30
        }

        if isDebuggerAttached() {
            findings.append("debugger")
            score += 40
        }

        if isProbablyJailbroken() {
            findings.append("jailbreak")
            score += 55
        }

        if hasHookingIndicators() {
            findings.append("hooks")
            score += 50
        }

        return SecurityStatus(riskScore: score, findings: findings)
    }

    public static func keyManagerPublicSpki() throws -> Data {
        try signer.signingPublicKeySpki()
    }
}

private func parseHostAndPath(_ input: String) -> (String, String) {
    guard let url = URL(string: input), let host = url.host else {
        return ("", input)
    }
    let path = (url.path.isEmpty ? "/" : url.path) + (url.query.map { "?\($0)" } ?? "")
    return (host, path)
}

private func isDebuggerAttached() -> Bool {
    var info = kinfo_proc()
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    var size = MemoryLayout<kinfo_proc>.stride
    let rc = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
    guard rc == 0 else { return false }
    return (info.kp_proc.p_flag & P_TRACED) != 0
}

private func isProbablyJailbroken() -> Bool {
    #if targetEnvironment(simulator)
    return false
    #else
    let fm = FileManager.default
    let suspiciousPaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/",
    ]
    if suspiciousPaths.contains(where: { fm.fileExists(atPath: $0) }) {
        return true
    }

    // Attempt to write outside the sandbox (should fail on stock devices).
    let testPath = "/private/jb_\(UUID().uuidString)"
    do {
        try "x".write(toFile: testPath, atomically: true, encoding: .utf8)
        try fm.removeItem(atPath: testPath)
        return true
    } catch {
        // Expected.
    }

    return false
    #endif
}

private func hasHookingIndicators() -> Bool {
    // Scan loaded dynamic libraries for common injection names.
    let suspectSubstrings = [
        "frida",
        "fridagadget",
        "cydia",
        "substrate",
        "mobilesubstrate",
        "libhooker",
        "fishhook",
        "cycript",
        "xposed",
    ]

    let imageCount = _dyld_image_count()
    for i in 0..<imageCount {
        guard let cName = _dyld_get_image_name(i) else { continue }
        let name = String(cString: cName).lowercased()
        if suspectSubstrings.contains(where: { name.contains($0) }) {
            return true
        }
    }

    if let env = getenv("DYLD_INSERT_LIBRARIES") {
        let s = String(cString: env)
        if !s.isEmpty {
            return true
        }
    }

    return false
}
