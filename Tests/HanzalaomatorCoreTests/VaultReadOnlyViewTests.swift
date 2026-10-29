import Foundation
import XCTest
@testable import HanzalaomatorCore

final class VaultReadOnlyViewTests: XCTestCase {
    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorReadOnlyViewTests-\(UUID().uuidString)", isDirectory: true)
    }

    func testListsOriginalNamesAndReadsAuthenticatedRangesWithoutPlaintextMirror() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sourceURL = root.appendingPathComponent("field-photo.jpg")
        let sourceData = Data((0..<(2 * 1024 * 1024 + 777)).map { UInt8($0 % 251) })
        try sourceData.write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "finder-readonly-test")
        let entry = try VaultObjectStore().importFile(at: sourceURL, into: vault)
        let view = VaultReadOnlyView()

        let listed = try view.entries(in: vault)
        XCTAssertEqual(listed.map(\.originalName), ["field-photo.jpg"])

        let offset: UInt64 = 900_123
        let length = 75_000
        let rangeData = try view.read(entryID: entry.id, from: vault, offset: offset, length: length)
        let expected = sourceData.subdata(in: Int(offset)..<(Int(offset) + length))
        XCTAssertEqual(rangeData, expected)

        let vaultRootItems = try FileManager.default.contentsOfDirectory(atPath: vaultRoot.path)
        XCTAssertFalse(vaultRootItems.contains("field-photo.jpg"))
        XCTAssertEqual(Set(vaultRootItems), Set(["vault.hanzala", "index.hanzala", "objects"]))
    }

    func testReadPastEndReturnsOnlyRemainingBytes() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sourceURL = root.appendingPathComponent("note.txt")
        let sourceData = Data("0123456789".utf8)
        try sourceData.write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "range-end-test")
        let entry = try VaultObjectStore().importFile(at: sourceURL, into: vault)

        let data = try VaultReadOnlyView().read(entryID: entry.id, from: vault, offset: 7, length: 50)
        XCTAssertEqual(data, Data("789".utf8))
    }

    func testReadAtOrPastEndReturnsEmptyData() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sourceURL = root.appendingPathComponent("tiny.bin")
        try Data([1, 2, 3]).write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "eof-test")
        let entry = try VaultObjectStore().importFile(at: sourceURL, into: vault)
        let view = VaultReadOnlyView()

        XCTAssertEqual(try view.read(entryID: entry.id, from: vault, offset: 3, length: 1), Data())
        XCTAssertEqual(try view.read(entryID: entry.id, from: vault, offset: 99, length: 1), Data())
    }
}
