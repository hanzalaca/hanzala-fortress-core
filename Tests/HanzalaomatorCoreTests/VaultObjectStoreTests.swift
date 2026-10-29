import Foundation
import XCTest
@testable import HanzalaomatorCore

final class VaultObjectStoreTests: XCTestCase {
    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorObjectTests-\(UUID().uuidString)", isDirectory: true)
    }

    func testImportAndExportLargeFileRoundTrip() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let sourceURL = root.appendingPathComponent("confidential-source-video.bin")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let sourceData = Data((0..<(2 * 1024 * 1024 + 12345)).map { UInt8($0 % 251) })
        try sourceData.write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "portable-vault-password")
        let objectStore = VaultObjectStore()
        let entry = try objectStore.importFile(at: sourceURL, into: vault)

        XCTAssertEqual(entry.originalName, "confidential-source-video.bin")
        XCTAssertEqual(entry.byteCount, UInt64(sourceData.count))
        XCTAssertTrue(entry.opaqueObjectName.hasSuffix(".hzo"))
        XCTAssertFalse(entry.opaqueObjectName.contains(entry.originalName))

        let objectURL = VaultLayout.objectURL(named: entry.opaqueObjectName, in: vaultRoot)
        XCTAssertTrue(FileManager.default.fileExists(atPath: objectURL.path))

        let indexCiphertext = try Data(contentsOf: VaultLayout.indexURL(in: vaultRoot))
        let objectCiphertext = try Data(contentsOf: objectURL)
        XCTAssertNil(indexCiphertext.range(of: Data(entry.originalName.utf8)))
        XCTAssertNil(objectCiphertext.range(of: Data(entry.originalName.utf8)))

        let exportURL = root.appendingPathComponent("exported.bin")
        try objectStore.exportFile(entryID: entry.id, from: vault, to: exportURL)
        XCTAssertEqual(try Data(contentsOf: exportURL), sourceData)
    }

    func testStreamingReadReturnsAuthenticatedPlaintextWithoutExportFile() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let sourceURL = root.appendingPathComponent("mounted-photo.bin")
        let sourceData = Data((0..<(2 * 1024 * 1024 + 333)).map { UInt8($0 % 239) })
        try sourceData.write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "mount-stream-password")
        let objectStore = VaultObjectStore()
        let entry = try objectStore.importFile(at: sourceURL, into: vault)

        let before = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()
        var streamed = Data()
        var chunkCount = 0
        try objectStore.streamFile(entryID: entry.id, from: vault) { chunk in
            chunkCount += 1
            streamed.append(chunk)
        }
        let after = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()

        XCTAssertEqual(streamed, sourceData)
        XCTAssertGreaterThan(chunkCount, 1)
        XCTAssertEqual(after, before, "Streaming read must not create a plaintext export beside the vault")
    }

    func testImportCopyLeavesSourceUntouched() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let sourceURL = root.appendingPathComponent("keep-original.jpg")
        let originalData = Data("copy-mode-must-not-delete-or-modify-source".utf8)
        try originalData.write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "copy-test-password")
        let objectStore = VaultObjectStore()

        _ = try objectStore.importFile(at: sourceURL, into: vault)

        XCTAssertTrue(FileManager.default.fileExists(atPath: sourceURL.path))
        XCTAssertEqual(try Data(contentsOf: sourceURL), originalData)
    }

    func testImportedEntrySurvivesVaultReopen() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let sourceURL = root.appendingPathComponent("photo-original.jpg")
        let sourceData = Data("journalistic-source-test".utf8)
        try sourceData.write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        let created = try store.createVault(at: vaultRoot, password: "same-password-on-new-mac")
        let objectStore = VaultObjectStore()
        let imported = try objectStore.importFile(at: sourceURL, into: created)

        let reopened = try store.openVault(at: vaultRoot, password: "same-password-on-new-mac")
        let entries = try objectStore.listEntries(in: reopened)

        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].id, imported.id)
        XCTAssertEqual(entries[0].originalName, "photo-original.jpg")

        let exportURL = root.appendingPathComponent("reopened-export.jpg")
        try objectStore.exportFile(entryID: imported.id, from: reopened, to: exportURL)
        XCTAssertEqual(try Data(contentsOf: exportURL), sourceData)
    }

    func testTamperedObjectIsRejectedWithoutPlaintextOutput() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let sourceURL = root.appendingPathComponent("evidence.dat")
        try Data(repeating: 0xAB, count: 256 * 1024).write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "tamper-test-password")
        let objectStore = VaultObjectStore()
        let entry = try objectStore.importFile(at: sourceURL, into: vault)
        let objectURL = VaultLayout.objectURL(named: entry.opaqueObjectName, in: vaultRoot)

        var encrypted = try Data(contentsOf: objectURL)
        encrypted[encrypted.index(before: encrypted.endIndex)] ^= 0x01
        try encrypted.write(to: objectURL)

        let exportURL = root.appendingPathComponent("should-not-exist.dat")
        XCTAssertThrowsError(try objectStore.exportFile(entryID: entry.id, from: vault, to: exportURL))
        XCTAssertFalse(FileManager.default.fileExists(atPath: exportURL.path))
    }
}
