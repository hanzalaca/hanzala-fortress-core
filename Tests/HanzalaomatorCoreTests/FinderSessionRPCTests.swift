import XCTest
@testable import HanzalaomatorCore

final class FinderSessionRPCTests: XCTestCase {
    func testRPCOpensOnlyRequestedEntryAndInvalidationRemovesPlaintext() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let leaseRoot = fixture.root.appendingPathComponent("leases", isDirectory: true)
        let session = FinderReadOnlySession(
            vault: fixture.vault,
            leaseStore: OnDemandPlaintextLeaseStore(rootDirectory: leaseRoot)
        )
        let rpc = FinderSessionRPC(session: session)

        let files = try rpc.listRoot()
        XCTAssertEqual(Set(files.map { $0.id }), Set([fixture.firstID, fixture.secondID]))
        XCTAssertTrue(session.activeEntryIDs().isEmpty)

        let handle = try rpc.open(entryID: fixture.firstID)
        XCTAssertEqual(session.activeEntryIDs(), [fixture.firstID])
        XCTAssertFalse(session.activeEntryIDs().contains(fixture.secondID))

        let data = try rpc.read(handle: handle, offset: 2, length: 4)
        XCTAssertEqual(data, Data("cdef".utf8))

        rpc.invalidate()
        XCTAssertTrue(session.activeEntryIDs().isEmpty)
        XCTAssertThrowsError(try rpc.listRoot()) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .invalidated)
        }
    }

    func testRPCRejectsOversizedAndForgedHandles() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let session = FinderReadOnlySession(
            vault: fixture.vault,
            leaseStore: OnDemandPlaintextLeaseStore(
                rootDirectory: fixture.root.appendingPathComponent("leases2")
            )
        )
        let rpc = FinderSessionRPC(session: session, maximumReadLength: 4)
        let handle = try rpc.open(entryID: fixture.firstID)

        XCTAssertThrowsError(try rpc.read(handle: handle, offset: 0, length: 5)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .readTooLarge)
        }

        let forged = FinderSessionRPC.RemoteHandle(id: UUID(), entryID: fixture.firstID)
        XCTAssertThrowsError(try rpc.read(handle: forged, offset: 0, length: 1)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .unknownHandle)
        }

        rpc.close(handle)
        XCTAssertTrue(session.activeEntryIDs().isEmpty)
        rpc.close(handle) // idempotent
    }

    private struct Fixture {
        let root: URL
        let vault: OpenedVault
        let firstID: UUID
        let secondID: UUID
    }

    private func makeFixture() throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FinderSessionRPC-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "test-password")
        let objectStore = VaultObjectStore()

        let first = root.appendingPathComponent("first.txt")
        let second = root.appendingPathComponent("second.txt")
        try Data("abcdefghij".utf8).write(to: first)
        try Data("0123456789".utf8).write(to: second)

        let firstEntry = try objectStore.importFile(at: first, into: vault)
        let secondEntry = try objectStore.importFile(at: second, into: vault)
        return Fixture(root: root, vault: vault, firstID: firstEntry.id, secondID: secondEntry.id)
    }
}
