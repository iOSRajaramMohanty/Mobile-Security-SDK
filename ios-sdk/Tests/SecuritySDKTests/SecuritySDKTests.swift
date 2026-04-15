import XCTest
@testable import SecuritySDK

final class SecuritySDKTests: XCTestCase {
    func testSecurityStatusDefaults() {
        let status = SecuritySdk.getSecurityStatus()
        XCTAssertGreaterThanOrEqual(status.riskScore, 0)
        XCTAssertLessThanOrEqual(status.riskScore, 100)
        XCTAssertGreaterThanOrEqual(status.findings.count, 0)
    }
}
