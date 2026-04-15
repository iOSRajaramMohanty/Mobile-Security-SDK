import Foundation
import Security

/// Stable installation UUID stored in Keychain (not identifierForVendor alone).
enum InstallationIdentity {
    private static let account = "com.bankingsdk.installation.uuid"

    static func getOrCreateId() throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: AnyObject?
        let st = SecItemCopyMatching(query as CFDictionary, &out)
        if st == errSecSuccess, let d = out as? Data, let s = String(data: d, encoding: .utf8) {
            return s
        }
        let id = UUID().uuidString
        guard let data = id.data(using: .utf8) else {
            throw NSError(domain: "InstallationIdentity", code: 1)
        }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemDelete(add as CFDictionary)
        let addSt = SecItemAdd(add as CFDictionary, nil)
        guard addSt == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(addSt))
        }
        return id
    }
}
