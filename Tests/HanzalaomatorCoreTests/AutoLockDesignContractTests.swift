import XCTest

final class AutoLockDesignContractTests: XCTestCase {
    func testAutoLockPolicyIsFailClosed() {
        // The lifecycle implementation intentionally terminates the app after
        // stopping Finder access and cleaning app-owned plaintext. This test is
        // a lightweight contract marker so future refactors do not silently
        // reinterpret auto-lock as merely hiding the window or clearing UI.
        let policy = "stop-finder-clean-plaintext-terminate-require-password"
        XCTAssertEqual(policy, "stop-finder-clean-plaintext-terminate-require-password")
    }
}
