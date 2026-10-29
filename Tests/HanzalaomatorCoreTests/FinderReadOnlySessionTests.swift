import Foundation
import XCTest
@testable import HanzalaomatorCore

final class FinderReadOnlySessionTests: XCTestCase {
    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("HanzalaomatorFinderSessionTests-\(UUID().uuidString)", isDirectory: true)
    }

    func testEnumerationDoesNotMaterializePlaintextAndOpenOnlyMaterializesSelectedEntry() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let firstSource = root.appendingPathComponent("first.jpg")
        let secondSource = root.appendingPathComponent("second.mov")
        let firstData = Data("first-secret".utf8)
        let secondData = Data("second-secret".utf8)
        try firstData.write(to: firstSource)
        try secondData.write(to: secondSource)

        let vault = try VaultStore().createVault(at: root.appendingPathComponent("vault"), password: "finder-session-test")
        let objectStore = VaultObjectStore()
        let firstEntry = try objectStore.importFile(at: firstSource, into: vault)
        let secondEntry = try objectStore.importFile(at: secondSource, into: vault)
        try FileManager.default.removeItem(at: firstSource)
        try FileManager.default.removeItem(at: secondSource)

        let leaseStore = OnDemandPlaintextLeaseStore(rootDirectory: root.appendingPathComponent("lease-cache"))
        let session = FinderReadOnlySession(vault: vault, objectStore: objectStore, leaseStore: leaseStore)

        let listed = try session.listRoot()
        XCTAssertEqual(Set(listed.map(\.name)), Set(["first.jpg", "second.mov"]))
        XCTAssertTrue(session.activeEntryIDs().isEmpty)

        let open = try session.open(entryID: firstEntry.id)
        XCTAssertEqual(session.activeEntryIDs(), Set([firstEntry.id]))
        XCTAssertFalse(session.activeEntryIDs().contains(secondEntry.id))

        let read = try session.read(handle: open, offset: 0, length: 100)
        XCTAssertEqual(read, firstData)

        session.close(open)
        XCTAssertTrue(session.activeEntryIDs().isEmpty)
    }

    func testReadSupportsFinderStyleRanges() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let source = root.appendingPathComponent("video.bin")
        let data = Data((0..<4096).map { UInt8($0 % 251) })
        try data.write(to: source)

        let vault = try VaultStore().createVault(at: root.appendingPathComponent("vault"), password: "range-test")
        let entry = try VaultObjectStore().importFile(at: source, into: vault)
        let session = FinderReadOnlySession(vault: vault, leaseStore: OnDemandPlaintextLeaseStore(rootDirectory: root.appendingPathComponent("cache")))
        let open = try session.open(entryID: entry.id)

        let chunk = try session.read(handle: open, offset: 1234, length: 321)
        XCTAssertEqual(chunk, data.subdata(in: 1234..<(1234 + 321)))
        session.close(open)
    }

    func testInvalidateRejectsNewIOAndRemovesActivePlaintext() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let source = root.appendingPathComponent("source.pdf")
        try Data("classified".utf8).write(to: source)
        let vault = try VaultStore().createVault(at: root.appendingPathComponent("vault"), password: "invalidate-session")
        let entry = try VaultObjectStore().importFile(at: source, into: vault)

        let cacheRoot = root.appendingPathComponent("cache")
        let session = FinderReadOnlySession(vault: vault, leaseStore: OnDemandPlaintextLeaseStore(rootDirectory: cacheRoot))
        let open = try session.open(entryID: entry.id)
        XCTAssertEqual(session.activeEntryIDs(), Set([entry.id]))

        session.invalidate()

        XCTAssertTrue(session.activeEntryIDs().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: cacheRoot.path))
        XCTAssertThrowsError(try session.read(handle: open, offset: 0, length: 1)) { error in
            XCTAssertEqual(error as? FinderReadOnlySessionError, .sessionInvalidated)
        }
        XCTAssertThrowsError(try session.open(entryID: entry.id)) { error in
            XCTAssertEqual(error as? FinderReadOnlySessionError, .sessionInvalidated)
        }
        XCTAssertThrowsError(try session.listRoot()) { error in
            XCTAssertEqual(error as? FinderReadOnlySessionError, .sessionInvalidated)
        }
    }
}
