import XCTest
@testable import HanzalaomatorCore

final class VaultStoreTests: XCTestCase {
    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorTests-\(UUID().uuidString)", isDirectory: true)
    }

    func testCreateVaultWritesHeaderIndexAndObjectsDirectoryThenReopensWithSameMasterKey() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = VaultStore()
        let created = try store.createVault(at: root, password: "correct horse battery staple")

        XCTAssertTrue(FileManager.default.fileExists(atPath: VaultLayout.headerURL(in: root).path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: VaultLayout.indexURL(in: root).path))
        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: VaultLayout.objectsURL(in: root).path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
        XCTAssertEqual(created.masterKey.count, 32)

        let reopened = try store.openVault(at: root, password: "correct horse battery staple")
        XCTAssertEqual(reopened.header.vaultID, created.header.vaultID)
        XCTAssertEqual(reopened.masterKey, created.masterKey)
    }

    func testWrongPasswordCannotOpenVault() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = VaultStore()
        _ = try store.createVault(at: root, password: "right-password")

        XCTAssertThrowsError(try store.openVault(at: root, password: "wrong-password")) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidPasswordOrCorruptedHeader)
        }
    }

    func testCreateRefusesToOverwriteExistingVaultHeader() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = VaultStore()
        _ = try store.createVault(at: root, password: "first-password")

        XCTAssertThrowsError(try store.createVault(at: root, password: "second-password")) { error in
            XCTAssertEqual(error as? VaultStoreError, .rootAlreadyContainsVault)
        }
    }

    func testCreateRefusesPreexistingObjectsDirectoryAndPreservesItsContents() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let objectsURL = VaultLayout.objectsURL(in: root)
        try FileManager.default.createDirectory(at: objectsURL, withIntermediateDirectories: true)
        let unrelatedFile = objectsURL.appendingPathComponent("keep-me.txt")
        let sentinel = Data("unrelated user data".utf8)
        try sentinel.write(to: unrelatedFile)

        XCTAssertThrowsError(try VaultStore().createVault(at: root, password: "password")) { error in
            XCTAssertEqual(error as? VaultStoreError, .rootAlreadyContainsVault)
        }

        XCTAssertEqual(try Data(contentsOf: unrelatedFile), sentinel)
        XCTAssertFalse(FileManager.default.fileExists(atPath: VaultLayout.headerURL(in: root).path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: VaultLayout.indexURL(in: root).path))
    }

    func testCorruptedHeaderIsRejected() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: VaultLayout.headerURL(in: root))

        XCTAssertThrowsError(try VaultStore().openVault(at: root, password: "anything")) { error in
            XCTAssertEqual(error as? VaultStoreError, .invalidHeader)
        }
    }
}
