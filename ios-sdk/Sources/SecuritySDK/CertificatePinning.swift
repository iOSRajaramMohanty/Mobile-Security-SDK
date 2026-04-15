import CryptoKit
import Foundation
import Security

/**
 Minimal certificate pinning helper.

 This is intentionally kept as a utility (no networking is performed by this SDK).
 Host applications can adopt the `PinnedURLSessionDelegate` for URLSession pinning.
 */
public enum CertificatePinning {
    public static func sha256Base64(data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return Data(digest).base64EncodedString()
    }

    /**
     Returns **SPKI SHA-256** pin (base64) for the leaf public key.

     Pin format: SHA256(SubjectPublicKeyInfo DER).
     */
    public static func publicKeySpkiSha256Base64(from trust: SecTrust) -> String? {
        guard let key = SecTrustCopyKey(trust) else { return nil }
        guard let spki = secp256r1SpkiDer(from: key) else { return nil }
        return sha256Base64(data: spki)
    }

    /**
     Builds SubjectPublicKeyInfo DER for P-256 keys using SecKey's external representation (ANSI X9.63).
     */
    private static func secp256r1SpkiDer(from key: SecKey) -> Data? {
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any] else { return nil }
        guard (attrs[kSecAttrKeyType as String] as? String) == (kSecAttrKeyTypeECSECPrimeRandom as String) else {
            return nil
        }
        // 256-bit P-256 / secp256r1.
        guard (attrs[kSecAttrKeySizeInBits as String] as? Int) == 256 else { return nil }
        guard let x963 = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        // Expect uncompressed 0x04 || X || Y (65 bytes).
        guard x963.count == 65, x963.first == 0x04 else { return nil }

        // SubjectPublicKeyInfo for EC P-256:
        // SEQUENCE(
        //   SEQUENCE( OID ecPublicKey, OID prime256v1 ),
        //   BIT STRING( 0x00 || x963 )
        // )
        let algId: [UInt8] = [
            0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // 1.2.840.10045.2.1
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
        ]
        // BIT STRING header: 0x03, 0x42, 0x00 then 65 bytes key
        var spki = Data()
        spki.append(contentsOf: [0x30, 0x5B]) // outer SEQUENCE len 91
        spki.append(contentsOf: algId)
        spki.append(contentsOf: [0x03, 0x42, 0x00])
        spki.append(x963)
        return spki
    }
}

public final class PinnedURLSessionDelegate: NSObject, URLSessionDelegate {
    private let allowedSpkiSha256Base64: Set<String>

    public init(allowedSpkiSha256Base64: [String]) {
        self.allowedSpkiSha256Base64 = Set(allowedSpkiSha256Base64)
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let pin = CertificatePinning.publicKeySpkiSha256Base64(from: trust),
              allowedSpkiSha256Base64.contains(pin) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

