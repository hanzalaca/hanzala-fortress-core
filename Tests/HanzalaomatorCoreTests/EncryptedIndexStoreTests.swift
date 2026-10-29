import Foundation
import XCTest
@testable import HanzalaomatorCore

final class EncryptedIndexStoreTests: XCTestCase {
    private func temporaryURL(_ name: String = UUID().uuidString) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorIndexTests-\(name)")
    }

    func testIndexRoundTripPreservesEntries() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let masterKey = Data(repeating: 0x11, count: 32)
        let entry = VaultEntry(
            id: UUID(),
            opaqueObjectName: "9F0C6B5A-0EAF-4D15-8C33-7A3D31211111.hzo",
            originalName: "source-video.mp4",
            byteCount: 123456,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let index = VaultIndex(entries: [entry])

        let store = EncryptedIndexStore()
        try store.write(index, to: url, masterKey: masterKey)
        let reopened = try store.read(from: url, masterKey: masterKey)

        XCTAssertEqual(reopened.formatVersion, 1)
        XCTAssertEqual(reopened.entries.count, 1)
        XCTAssertEqual(reopened.entries[0].id, entry.id)
        XCTAssertEqual(reopened.entries[0].opaqueObjectName, entry.opaqueObjectName)
        XCTAssertEqual(reopened.entries[0].originalName, entry.originalName)
        XCTAssertEqual(reopened.entries[0].byteCount, entry.byteCount)
    }

    func testEncryptedIndexDoesNotContainOriginalFilename() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let masterKey = Data(repeating: 0x22, count: 32)
        let originalName = "confidential-source-name.mov"
        let index = VaultIndex(entries: [
            VaultEntry(
                opaqueObjectName: "B0D7D971-CCAF-40E0-B72C-884612222222.hzo",
                originalName: originalName,
                byteCount: 42
            )
        ])

        try EncryptedIndexStore().write(index, to: url, masterKey: masterKey)
        let ciphertext = try Data(contentsOf: url)

        XCTAssertNil(ciphertext.range(of: Data(originalName.utf8)))
    }

    func testWrongMasterKeyIsRejected() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let correctKey = Data(repeating: 0x33, count: 32)
        let wrongKey = Data(repeating: 0x44, count: 32)
        try EncryptedIndexStore().write(VaultIndex(), to: url, masterKey: correctKey)

        XCTAssertThrowsError(try EncryptedIndexStore().read(from: url, masterKey: wrongKey)) { error in
            XCTAssertEqual(error as? EncryptedIndexError, .authenticationFailed)
        }
    }

    func testTamperedIndexIsRejected() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let masterKey = Data(repeating: 0x55, count: 32)
        try EncryptedIndexStore().write(VaultIndex(), to: url, masterKey: masterKey)

        var data = try Data(contentsOf: url)
        data[data.index(before: data.endIndex)] ^= 0x01
        try data.write(to: url)

        XCTAssertThrowsError(try EncryptedIndexStore().read(from: url, masterKey: masterKey)) { error in
            XCTAssertEqual(error as? EncryptedIndexError, .authenticationFailed)
        }
    }

    func testDomainSeparatedKeysAreDifferent() throws {
        let masterKey = Data(repeating: 0x66, count: 32)
        let deriver = DomainKeyDeriver()

        let indexKey = try deriver.derive(masterKey: masterKey, purpose: .indexV1)
        let objectKey = try deriver.derive(masterKey: masterKey, purpose: .objectV1)

        XCTAssertEqual(indexKey.count, 32)
        XCTAssertEqual(objectKey.count, 32)
        XCTAssertNotEqual(indexKey, objectKey)
        XCTAssertNotEqual(indexKey, masterKey)
        XCTAssertNotEqual(objectKey, masterKey)
    }
}
