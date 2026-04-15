import Foundation
@testable import SecuritySDK
import XCTest

final class HkdfTest: XCTestCase {
    func testHkdfLength() {
        let ikm = Data(repeating: 7, count: 32)
        let d = HkdfSha256.derive(ikm: ikm, salt: nil, info: "info", length: 32)
        XCTAssertEqual(d.count, 32)
    }
}
