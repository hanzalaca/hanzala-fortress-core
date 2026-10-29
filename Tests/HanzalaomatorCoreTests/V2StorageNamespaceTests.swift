import XCTest
@testable import HanzalaomatorCore

final class V2StorageNamespaceTests: XCTestCase {
    func testV2LayoutReusesGenericPublicNames() {
        XCTAssertEqual(V2StorageLayout.accessEnvelopeName, VaultLayout.headerName)
        XCTAssertEqual(V2StorageLayout.poolDirectoryName, VaultLayout.objectsDirectoryName)

        let publicNames = [
            V2StorageLayout.accessEnvelopeName.lowercased(),
            V2StorageLayout.poolDirectoryName.lowercased()
        ].joined(separator: " ")

        XCTAssertFalse(publicNames.contains("hidden"))
        XCTAssertFalse(publicNames.contains("concealed"))
        XCTAssertFalse(publicNames.contains("decoy"))
    }

    func testIndexAnchorIsDeterministicForSameMasterKey() throws {
        let locator = V2StorageNamespaceLocator()
        let masterKey = Data(repeating: 0x11, count: 32)

        let first = try locator.indexObjectName(masterKey: masterKey)
        let second = try locator.indexObjectName(masterKey: masterKey)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.count, 64)
        XCTAssertTrue(first.allSatisfy { character in
            character.isNumber || ("a"..."f").contains(String(character))
        })
    }

    func testDifferentMasterKeysDeriveDifferentOpaqueAnchors() throws {
        let locator = V2StorageNamespaceLocator()
        let visibleKey = Data(repeating: 0x22, count: 32)
        let concealedKey = Data(repeating: 0x33, count: 32)

        let visibleName = try locator.indexObjectName(masterKey: visibleKey)
        let concealedName = try locator.indexObjectName(masterKey: concealedKey)

        XCTAssertNotEqual(visibleName, concealedName)
        XCTAssertFalse(visibleName.contains("visible"))
        XCTAssertFalse(concealedName.contains("concealed"))
    }

    func testIndexURLLivesInsideSharedObjectPool() throws {
        let locator = V2StorageNamespaceLocator()
        let root = URL(fileURLWithPath: "/tmp/hanzala-v2")
        let masterKey = Data(repeating: 0x44, count: 32)

        let url = try locator.indexURL(masterKey: masterKey, in: root)

        XCTAssertEqual(url.deletingLastPathComponent(), V2StorageLayout.poolURL(in: root))
        XCTAssertEqual(url.lastPathComponent.count, 64)
    }

    func testInvalidMasterKeyLengthIsRejected() {
        let locator = V2StorageNamespaceLocator()

        XCTAssertThrowsError(
            try locator.indexObjectName(masterKey: Data(repeating: 0x55, count: 31))
        ) { error in
            XCTAssertEqual(error as? V2StorageNamespaceError, .invalidMasterKeyLength)
        }
    }
}
