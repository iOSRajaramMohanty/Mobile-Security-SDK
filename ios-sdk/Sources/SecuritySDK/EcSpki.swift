import Foundation
import Security

enum EcSpki {
    /// Converts SEC EC public key SPKI DER to raw X963 representation for CryptoKit P-256.
    static func x963FromSecp256r1Spki(_ spkiDer: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(spkiDer as CFData, attrs as CFDictionary, &err) else {
            throw err!.takeRetainedValue() as Error
        }
        var e: Unmanaged<CFError>?
        guard let rep = SecKeyCopyExternalRepresentation(key, &e) as Data? else {
            throw e!.takeRetainedValue() as Error
        }
        return rep
    }
}
