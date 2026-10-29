import Foundation
import XCTest
@testable import HanzalaomatorCore

final class OnDemandPlaintextLeaseStoreTests: XCTestCase {
    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorLeaseTests-\(UUID().uuidString)", isDirectory: true)
    }

    func testOnlyRequestedEntryIsMaterializedAndReleaseRemovesIt() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let firstSource = root.appendingPathComponent("source-one.jpg")
        let secondSource = root.appendingPathComponent("source-two.mov")
        let firstData = Data("first-sensitive-file".utf8)
        let secondData = Data("second-sensitive-file".utf8)
        try firstData.write(to: firstSource)
        try secondData.write(to: secondSource)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "lease-test")
        let objectStore = VaultObjectStore()
        let firstEntry = try objectStore.importFile(at: firstSource, into: vault)
        let secondEntry = try objectStore.importFile(at: secondSource, into: vault)

        try FileManager.default.removeItem(at: firstSource)
        try FileManager.default.removeItem(at: secondSource)

        let cacheRoot = root.appendingPathComponent("lease-cache", isDirectory: true)
        let store = OnDemandPlaintextLeaseStore(rootDirectory: cacheRoot)
        let lease = try store.acquire(entryID: firstEntry.id, from: vault)

        XCTAssertEqual(try Data(contentsOf: lease.plaintextURL), firstData)
        XCTAssertEqual(store.activeEntryIDs(), Set([firstEntry.id]))
        XCTAssertEqual(store.activeLeaseCount(for: firstEntry.id), 1)
        XCTAssertFalse(store.activeEntryIDs().contains(secondEntry.id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: vaultRoot.appendingPathComponent("source-one.jpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: vaultRoot.appendingPathComponent("source-two.mov").path))

        store.release(lease)
        XCTAssertFalse(FileManager.default.fileExists(atPath: lease.plaintextURL.path))
        XCTAssertTrue(store.activeEntryIDs().isEmpty)
    }

    func testRepeatedAcquireSharesBackingFileButUsesUniqueLeaseTokens() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let source = root.appendingPathComponent("document.pdf")
        try Data("confidential-pdf".utf8).write(to: source)
        let vault = try VaultStore().createVault(at: root.appendingPathComponent("vault"), password: "reference-test")
        let entry = try VaultObjectStore().importFile(at: source, into: vault)

        let store = OnDemandPlaintextLeaseStore(rootDirectory: root.appendingPathComponent("cache"))
        let first = try store.acquire(entryID: entry.id, from: vault)
        let second = try store.acquire(entryID: entry.id, from: vault)

        XCTAssertNotEqual(first.id, second.id)
        XCTAssertEqual(first.plaintextURL, second.plaintextURL)
        XCTAssertEqual(store.activeLeaseCount(for: entry.id), 2)
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.plaintextURL.path))

        store.release(first)
        XCTAssertEqual(store.activeLeaseCount(for: entry.id), 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.plaintextURL.path))

        // Duplicate close of the same FSKit open token must not consume the other open.
        store.release(first)
        XCTAssertEqual(store.activeLeaseCount(for: entry.id), 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.plaintextURL.path))

        store.release(second)
        XCTAssertEqual(store.activeLeaseCount(for: entry.id), 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.plaintextURL.path))
    }

    func testInvalidateAllRemovesEveryActivePlaintextLease() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let a = root.appendingPathComponent("a.txt")
        let b = root.appendingPathComponent("b.txt")
        try Data("a".utf8).write(to: a)
        try Data("b".utf8).write(to: b)
        let vault = try VaultStore().createVault(at: root.appendingPathComponent("vault"), password: "invalidate-test")
        let objectStore = VaultObjectStore()
        let entryA = try objectStore.importFile(at: a, into: vault)
        let entryB = try objectStore.importFile(at: b, into: vault)

        let cacheRoot = root.appendingPathComponent("cache")
        let store = OnDemandPlaintextLeaseStore(rootDirectory: cacheRoot)
        let leaseA = try store.acquire(entryID: entryA.id, from: vault)
        let leaseB = try store.acquire(entryID: entryB.id, from: vault)
        XCTAssertTrue(FileManager.default.fileExists(atPath: leaseA.plaintextURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: leaseB.plaintextURL.path))

        store.invalidateAll()

        XCTAssertFalse(FileManager.default.fileExists(atPath: leaseA.plaintextURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: leaseB.plaintextURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: cacheRoot.path))
        XCTAssertTrue(store.activeEntryIDs().isEmpty)
        XCTAssertEqual(store.activeLeaseCount(for: entryA.id), 0)
        XCTAssertEqual(store.activeLeaseCount(for: entryB.id), 0)
    }
}
