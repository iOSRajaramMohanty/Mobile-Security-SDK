import CryptoKit
import Foundation
import Security

/// P-256 ECDSA signing: prefers **Secure Enclave** (non-extractable); falls back to software key in Keychain (e.g. Simulator).
final class KeychainSigner {
    private let storageAccount = "com.bankingsdk.signing.key.repr"

    private enum KeyKind {
        case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)
        case software(P256.Signing.PrivateKey)
    }

    private var cached: KeyKind?

    /// Ensures signing keys exist (Secure Enclave or Keychain software).
    func warmUp() throws {
        _ = try signingPublicKeySpki()
    }

    /// Legacy hook — only succeeds for the software fallback path.
    func loadOrCreatePrivateKey() throws -> P256.Signing.PrivateKey {
        switch try loadOrCreate() {
        case .secureEnclave:
            throw NSError(
                domain: "KeychainSigner",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Use signing APIs; Secure Enclave private key is not exportable to CryptoKit P256.Signing.PrivateKey"],
            )
        case .software(let k):
            return k
        }
    }

    func signingPublicKeySpki() throws -> Data {
        switch try loadOrCreate() {
        case .secureEnclave(let k):
            return k.publicKey.derRepresentation
        case .software(let k):
            return k.publicKey.derRepresentation
        }
    }

    func sign(data: Data) throws -> Data {
        switch try loadOrCreate() {
        case .secureEnclave(let k):
            return try k.signature(for: data).derRepresentation
        case .software(let k):
            return try k.signature(for: data).derRepresentation
        }
    }

    /// Deletes signing material and creates a new hardware-backed (or Keychain software) key.
    func rotateKeys() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: storageAccount,
        ]
        SecItemDelete(query as CFDictionary)
        cached = nil
        _ = try loadOrCreate()
    }

    private func loadOrCreate() throws -> KeyKind {
        if let c = cached { return c }

        if let stored = try? loadDataFromKeychain() {
            if SecureEnclave.isAvailable {
                if let se = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored) {
                    cached = .secureEnclave(se)
                    return cached!
                }
            }
            let sw = try P256.Signing.PrivateKey(rawRepresentation: stored)
            cached = .software(sw)
            return cached!
        }

        if SecureEnclave.isAvailable {
            let se = try SecureEnclave.P256.Signing.PrivateKey()
            try storeDataInKeychain(se.dataRepresentation)
            cached = .secureEnclave(se)
            return cached!
        }

        let sw = P256.Signing.PrivateKey()
        try storeDataInKeychain(sw.rawRepresentation)
        cached = .software(sw)
        return cached!
    }

    private func loadDataFromKeychain() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: storageAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: AnyObject?
        let st = SecItemCopyMatching(query as CFDictionary, &out)
        guard st == errSecSuccess, let d = out as? Data else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(st))
        }
        return d
    }

    private func storeDataInKeychain(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: storageAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let st = SecItemAdd(query as CFDictionary, nil)
        guard st == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(st))
        }
    }
}
