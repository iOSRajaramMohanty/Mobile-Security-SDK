import CryptoKit
import Foundation

/// Native-only primitives mirroring Android `CryptoEngine` (no JavaScript crypto).
public enum CryptoEngine {
    public static func encryptAesGcm256(key: Data, plaintext: Data) throws -> (iv: Data, ciphertext: Data, tag: Data) {
        guard key.count == 32 else {
            throw NSError(domain: "CryptoEngine", code: 1, userInfo: [NSLocalizedDescriptionKey: "AES-256 key must be 32 bytes"])
        }
        let sym = SymmetricKey(data: key)
        let sealed = try AES.GCM.seal(plaintext, using: sym)
        let iv = Data(sealed.nonce)
        guard iv.count == 12 else {
            throw NSError(domain: "CryptoEngine", code: 2, userInfo: [NSLocalizedDescriptionKey: "unexpected IV length"])
        }
        return (iv, sealed.ciphertext, sealed.tag)
    }

    /// Decrypts and authenticates; throws on bad tag (CryptoKit authentication failure).
    public static func decryptAesGcm256(key: Data, iv: Data, ciphertext: Data, tag: Data) throws -> Data {
        guard key.count == 32 else {
            throw NSError(domain: "CryptoEngine", code: 1, userInfo: [NSLocalizedDescriptionKey: "AES-256 key must be 32 bytes"])
        }
        guard iv.count == 12, tag.count == 16 else {
            throw NSError(domain: "CryptoEngine", code: 3, userInfo: [NSLocalizedDescriptionKey: "invalid IV or tag length"])
        }
        let sym = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: iv)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: sym)
    }

    public static func hkdfSha256(ikm: Data, salt: Data?, info: String, length: Int) -> Data {
        HkdfSha256.derive(ikm: ikm, salt: salt, info: info, length: length)
    }

    /// Verifies ECDSA P-256 (SHA-256) over `data` using peer SPKI DER.
    public static func verifyEcdsaSha256(data: Data, signatureDer: Data, peerPublicKeySpki: Data) -> Bool {
        guard let pub = try? P256.Signing.PublicKey(derRepresentation: peerPublicKeySpki) else {
            return false
        }
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: signatureDer) else {
            return false
        }
        return pub.isValidSignature(sig, for: data)
    }
}
