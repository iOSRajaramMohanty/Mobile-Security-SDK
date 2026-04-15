import CryptoKit
import Foundation
import Security

enum HybridEnvelopeIOS {
    private static func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func keyIdFromSpki(_ spkiDer: Data) -> String {
        let digest = SHA256.hash(data: spkiDer)
        return base64url(Data(digest))
    }

    static func build(method: String, host: String, contentType: String, riskScore: Int, path: String, plaintext: Data, serverPublicSpki: Data, signer: KeychainSigner) throws -> [String: Any] {
        let x963 = try EcSpki.x963FromSecp256r1Spki(serverPublicSpki)
        let serverPub = try P256.KeyAgreement.PublicKey(x963Representation: x963)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: serverPub)
        let ikm = shared.withUnsafeBytes { Data($0) }

        var dek = Data(count: 32)
        let st = dek.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, 32, buf.baseAddress!)
        }
        guard st == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(st))
        }

        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: dek))
        let pNonce = Data(sealed.nonce)
        let pCt = sealed.ciphertext
        let pTag = sealed.tag

        let wrapKeyData = HkdfSha256.derive(ikm: ikm, salt: nil, info: "banking-sdk-wrap-v1", length: 32)
        let wrapped = try AES.GCM.seal(dek, using: SymmetricKey(data: wrapKeyData))
        let wNonce = Data(wrapped.nonce)
        let wCt = wrapped.ciphertext
        let wTag = wrapped.tag

        let ts = Int64(Date().timeIntervalSince1970 * 1000)
        var nonce = Data(count: 16)
        let nst = nonce.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, 16, buf.baseAddress!)
        }
        guard nst == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(nst))
        }

        let ephSpki = ephemeral.publicKey.derRepresentation
        let devicePub = try signer.signingPublicKeySpki()
        let keyId = keyIdFromSpki(devicePub)
        let canonical = CanonicalPayload.build(
            method: method,
            host: host,
            contentType: contentType,
            riskScore: riskScore,
            keyId: keyId,
            path: path,
            timestampMs: ts,
            nonce: nonce,
            payloadIv: pNonce,
            payloadCt: pCt,
            payloadTag: pTag,
            wrapIv: wNonce,
            wrapCt: wCt,
            wrapTag: wTag,
            ephemeralPublicSpki: ephSpki,
        )
        let sig = try signer.sign(data: canonical)

        return [
            "v": 1,
            "algorithm": "HYBRID_P256_AES256GCM_ECDSA_SHA256",
            "method": method,
            "host": host,
            "contentType": contentType,
            "riskScore": max(0, min(100, riskScore)),
            "keyId": keyId,
            "timestampMs": ts,
            "nonce": nonce.base64EncodedString(),
            "path": path,
            "aesIv": pNonce.base64EncodedString(),
            "ciphertext": pCt.base64EncodedString(),
            "aesTag": pTag.base64EncodedString(),
            "wrappedDekIv": wNonce.base64EncodedString(),
            "wrappedDekCipher": wCt.base64EncodedString(),
            "wrappedDekTag": wTag.base64EncodedString(),
            "ephemeralPublicSpki": ephSpki.base64EncodedString(),
            // Included for debugging/telemetry only; backend must not trust this for verification.
            "deviceSigningPublicSpki": devicePub.base64EncodedString(),
            // Local-only: used to decrypt encrypted gateway responses. MUST NOT be forwarded over the network.
            "_clientDek": dek.base64EncodedString(),
            "signature": sig.base64EncodedString(),
        ]
    }
}
