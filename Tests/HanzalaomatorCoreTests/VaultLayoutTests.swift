import XCTest
@testable import HanzalaomatorCore

final class VaultLayoutTests: XCTestCase {
    func testVaultPathsDoNotContainOriginalFilename() {
        let root = URL(fileURLWithPath: "/tmp/example-vault")
        let secretOriginalName = "source-name-war-photo.jpg"
        let opaqueName = UUID().uuidString.lowercased()
        let object = VaultLayout.objectURL(named: opaqueName, in: root)

        XCTAssertFalse(object.path.contains(secretOriginalName))
        XCTAssertTrue(object.lastPathComponent == opaqueName)
    }

    func testVaultFormatHasDedicatedObjectsDirectory() {
        let root = URL(fileURLWithPath: "/tmp/example-vault")
        XCTAssertEqual(VaultLayout.objectsURL(in: root).lastPathComponent, "objects")
    }
}
