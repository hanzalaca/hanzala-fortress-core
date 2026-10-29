import Foundation
import XCTest
@testable import HanzalaomatorCore

final class VaultTransactionJournalTests: XCTestCase {
    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorJournalTests-\(UUID().uuidString)", isDirectory: true)
    }

    func testInterruptedUnindexedObjectIsRolledBackOnVaultOpen() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        _ = try store.createVault(at: vaultRoot, password: "journal-password")

        let journal = VaultTransactionJournal()
        let opaqueName = UUID().uuidString + ".hzo"
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: opaqueName)

        let orphanURL = VaultLayout.objectURL(named: opaqueName, in: vaultRoot)
        try Data("encrypted-orphan-simulation".utf8).write(to: orphanURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: orphanURL.path))
        XCTAssertEqual(try journal.pendingImports(in: vaultRoot).count, 1)

        _ = try store.openVault(at: vaultRoot, password: "journal-password")

        XCTAssertFalse(FileManager.default.fileExists(atPath: orphanURL.path))
        XCTAssertTrue(try journal.pendingImports(in: vaultRoot).isEmpty)
    }

    func testCommittedIndexedObjectSurvivesPendingJournalOnVaultOpen() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sourceURL = root.appendingPathComponent("source.bin")
        try Data("committed-source".utf8).write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        let created = try store.createVault(at: vaultRoot, password: "journal-password")
        let objectStore = VaultObjectStore()
        let entry = try objectStore.importFile(at: sourceURL, into: created)
        let objectURL = VaultLayout.objectURL(named: entry.opaqueObjectName, in: vaultRoot)
        XCTAssertTrue(FileManager.default.fileExists(atPath: objectURL.path))

        // Simulate a crash after the authenticated index commit but before the
        // journal record could be removed.
        let journal = VaultTransactionJournal()
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: entry.opaqueObjectName)
        XCTAssertEqual(try journal.pendingImports(in: vaultRoot).count, 1)

        let reopened = try store.openVault(at: vaultRoot, password: "journal-password")

        XCTAssertTrue(FileManager.default.fileExists(atPath: objectURL.path))
        XCTAssertTrue(try journal.pendingImports(in: vaultRoot).isEmpty)
        XCTAssertEqual(try objectStore.listEntries(in: reopened).map(\.id), [entry.id])
    }

    func testMalformedJournalRecordNeverTriggersObjectDeletion() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        _ = try store.createVault(at: vaultRoot, password: "journal-password")

        let opaqueName = UUID().uuidString + ".hzo"
        let objectURL = VaultLayout.objectURL(named: opaqueName, in: vaultRoot)
        try Data("do-not-delete-from-malformed-record".utf8).write(to: objectURL)

        let journalDirectory = VaultLayout.journalURL(in: vaultRoot)
        try FileManager.default.createDirectory(at: journalDirectory, withIntermediateDirectories: true)
        let malformedURL = journalDirectory.appendingPathComponent("import-corrupt.json")
        try Data("{not-valid-json".utf8).write(to: malformedURL)

        _ = try store.openVault(at: vaultRoot, password: "journal-password")

        XCTAssertTrue(FileManager.default.fileExists(atPath: objectURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: malformedURL.path))
    }

    func testJournalRejectsPathTraversalOpaqueNames() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let journal = VaultTransactionJournal()
        XCTAssertThrowsError(try journal.beginImport(in: root, opaqueObjectName: "../escape.hzo")) { error in
            XCTAssertEqual(error as? VaultTransactionJournalError, .invalidOpaqueObjectName)
        }
    }

    func testJournalRecordDoesNotContainOriginalFilenameMetadata() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let journal = VaultTransactionJournal()
        let opaqueName = UUID().uuidString + ".hzo"
        let record = try journal.beginImport(in: root, opaqueObjectName: opaqueName)
        let recordURL = VaultLayout.journalRecordURL(transactionID: record.transactionID, in: root)
        let text = String(decoding: try Data(contentsOf: recordURL), as: UTF8.self)

        XCTAssertTrue(text.contains(opaqueName))
        XCTAssertFalse(text.contains("originalName"))
        XCTAssertFalse(text.contains("secret-source.jpg"))
    }

    func testWrongPasswordDoesNotRunJournalRecovery() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        _ = try store.createVault(at: vaultRoot, password: "correct-password")

        let journal = VaultTransactionJournal()
        let opaqueName = UUID().uuidString + ".hzo"
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: opaqueName)
        let orphanURL = VaultLayout.objectURL(named: opaqueName, in: vaultRoot)
        try Data("opaque-encrypted-object".utf8).write(to: orphanURL)

        XCTAssertThrowsError(try store.openVault(at: vaultRoot, password: "wrong-password"))

        XCTAssertTrue(FileManager.default.fileExists(atPath: orphanURL.path))
        XCTAssertEqual(try journal.pendingImports(in: vaultRoot).count, 1)
    }

    func testCorruptedEncryptedIndexDoesNotTriggerJournalDeletion() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        _ = try store.createVault(at: vaultRoot, password: "journal-password")

        let journal = VaultTransactionJournal()
        let opaqueName = UUID().uuidString + ".hzo"
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: opaqueName)
        let orphanURL = VaultLayout.objectURL(named: opaqueName, in: vaultRoot)
        try Data("opaque-encrypted-object".utf8).write(to: orphanURL)

        let indexURL = VaultLayout.indexURL(in: vaultRoot)
        var corruptedIndex = try Data(contentsOf: indexURL)
        XCTAssertFalse(corruptedIndex.isEmpty)
        corruptedIndex[corruptedIndex.index(before: corruptedIndex.endIndex)] ^= 0x01
        try corruptedIndex.write(to: indexURL)

        XCTAssertThrowsError(try store.openVault(at: vaultRoot, password: "journal-password"))

        XCTAssertTrue(FileManager.default.fileExists(atPath: orphanURL.path))
        XCTAssertEqual(try journal.pendingImports(in: vaultRoot).count, 1)
    }

    func testMixedCommittedAndInterruptedImportsRecoverIndependently() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sourceURL = root.appendingPathComponent("source.bin")
        try Data("committed-source".utf8).write(to: sourceURL)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        let created = try store.createVault(at: vaultRoot, password: "journal-password")
        let objectStore = VaultObjectStore()
        let committedEntry = try objectStore.importFile(at: sourceURL, into: created)
        let committedObjectURL = VaultLayout.objectURL(named: committedEntry.opaqueObjectName, in: vaultRoot)

        let journal = VaultTransactionJournal()
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: committedEntry.opaqueObjectName)

        let interruptedName = UUID().uuidString + ".hzo"
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: interruptedName)
        let interruptedObjectURL = VaultLayout.objectURL(named: interruptedName, in: vaultRoot)
        try Data("interrupted-opaque-object".utf8).write(to: interruptedObjectURL)
        XCTAssertEqual(try journal.pendingImports(in: vaultRoot).count, 2)

        let reopened = try store.openVault(at: vaultRoot, password: "journal-password")

        XCTAssertTrue(FileManager.default.fileExists(atPath: committedObjectURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: interruptedObjectURL.path))
        XCTAssertTrue(try journal.pendingImports(in: vaultRoot).isEmpty)
        XCTAssertEqual(try objectStore.listEntries(in: reopened).map(\.id), [committedEntry.id])
    }

    func testMissingInterruptedObjectClearsOnlyItsJournalRecord() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        _ = try store.createVault(at: vaultRoot, password: "journal-password")

        let journal = VaultTransactionJournal()
        let missingOpaqueName = UUID().uuidString + ".hzo"
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: missingOpaqueName)
        XCTAssertEqual(try journal.pendingImports(in: vaultRoot).count, 1)

        _ = try store.openVault(at: vaultRoot, password: "journal-password")

        XCTAssertTrue(try journal.pendingImports(in: vaultRoot).isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: VaultLayout.objectURL(named: missingOpaqueName, in: vaultRoot).path
        ))
    }

    func testJournalRecoveryIsIdempotentAcrossRepeatedVaultOpens() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let store = VaultStore()
        _ = try store.createVault(at: vaultRoot, password: "journal-password")

        let journal = VaultTransactionJournal()
        let opaqueName = UUID().uuidString + ".hzo"
        _ = try journal.beginImport(in: vaultRoot, opaqueObjectName: opaqueName)
        let orphanURL = VaultLayout.objectURL(named: opaqueName, in: vaultRoot)
        try Data("opaque-encrypted-object".utf8).write(to: orphanURL)

        _ = try store.openVault(at: vaultRoot, password: "journal-password")
        XCTAssertFalse(FileManager.default.fileExists(atPath: orphanURL.path))
        XCTAssertTrue(try journal.pendingImports(in: vaultRoot).isEmpty)

        let reopenedAgain = try store.openVault(at: vaultRoot, password: "journal-password")
        XCTAssertTrue(try journal.pendingImports(in: vaultRoot).isEmpty)
        XCTAssertTrue(try VaultObjectStore().listEntries(in: reopenedAgain).isEmpty)
    }
}
