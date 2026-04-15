import CryptoKit
import Foundation
@testable import SecuritySDK
import XCTest

final class CryptoEngineTests: XCTestCase {
    func testAesGcmRoundtrip() throws {
        let key = Data(repeating: 2, count: 32)
        let plain = Data("engine-test".utf8)
        let (iv, ct, tag) = try CryptoEngine.encryptAesGcm256(key: key, plaintext: plain)
        let out = try CryptoEngine.decryptAesGcm256(key: key, iv: iv, ciphertext: ct, tag: tag)
        XCTAssertEqual(plain, out)
    }

    func testAesGcmBadTagFails() throws {
        let key = Data(repeating: 3, count: 32)
        let (iv, ct, tag) = try CryptoEngine.encryptAesGcm256(key: key, plaintext: Data("x".utf8))
        var bad = tag
        bad[0] ^= 0xff
        XCTAssertThrowsError(try CryptoEngine.decryptAesGcm256(key: key, iv: iv, ciphertext: ct, tag: bad))
    }

    func testHkdfLength() {
        let ikm = Data(repeating: 5, count: 32)
        let d = CryptoEngine.hkdfSha256(ikm: ikm, salt: nil, info: "t", length: 32)
        XCTAssertEqual(d.count, 32)
    }

    func testVerifyEcdsa() throws {
        let key = P256.Signing.PrivateKey()
        let msg = Data("verify-me".utf8)
        let sig = try key.signature(for: msg)
        let der = sig.derRepresentation
        let spki = key.publicKey.derRepresentation
        XCTAssertTrue(CryptoEngine.verifyEcdsaSha256(data: msg, signatureDer: der, peerPublicKeySpki: spki))
    }
}
