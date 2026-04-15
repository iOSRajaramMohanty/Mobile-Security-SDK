import CryptoKit
import Foundation

/// HKDF-SHA256 (RFC 5869).
enum HkdfSha256 {
    static func derive(ikm: Data, salt: Data?, info: String, length: Int) -> Data {
        let saltBytes = salt ?? Data(count: SHA256.byteCount)
        let prk = extract(salt: saltBytes, ikm: ikm)
        return expand(prk: prk, info: info.data(using: .utf8)!, length: length)
    }

    private static func extract(salt: Data, ikm: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt))
        return Data(mac)
    }

    private static func expand(prk: Data, info: Data, length: Int) -> Data {
        let hashLen = SHA256.byteCount
        let n = (length + hashLen - 1) / hashLen
        precondition(n <= 255)
        var okm = Data()
        var tBlock = Data()
        var counter: UInt8 = 1
        while okm.count < length {
            var mac = HMAC<SHA256>(key: SymmetricKey(data: prk))
            mac.update(data: tBlock)
            mac.update(data: info)
            mac.update(data: Data([counter]))
            tBlock = Data(mac.finalize())
            okm.append(tBlock)
            counter += 1
        }
        return okm.prefix(length)
    }
}
