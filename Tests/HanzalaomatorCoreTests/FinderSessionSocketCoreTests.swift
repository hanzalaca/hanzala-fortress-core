import XCTest
@testable import HanzalaomatorCore

final class FinderSessionSocketCoreTests: XCTestCase {
    func testClientServerRoundTripKeepsOtherFilesEncrypted() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FinderSocket-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let plaintextRoot = root.appendingPathComponent("leases", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "socket-test-password")

        let a = root.appendingPathComponent("a.txt")
        let b = root.appendingPathComponent("b.txt")
        try Data("abcdefgh".utf8).write(to: a)
        try Data("uvwxyz".utf8).write(to: b)

        let store = VaultObjectStore()
        let entryA = try store.importFile(at: a, into: vault)
        let entryB = try store.importFile(at: b, into: vault)

        let leaseStore = OnDemandPlaintextLeaseStore(rootDirectory: plaintextRoot)
        let session = FinderReadOnlySession(vault: vault, leaseStore: leaseStore)
        let rpc = FinderSessionRPC(session: session)
        let server = FinderSessionSocketServerCore(rpc: rpc)

        let client = FinderSessionSocketClientCore(sessionID: server.id) { frame in
            let request = try FinderSessionSocketWire.decodeFrame(FinderSessionSocketWire.Request.self, from: frame)
            let response = server.handle(request)
            return try FinderSessionSocketWire.encodeFrame(response)
        }

        let files = try await client.listRoot()
        XCTAssertEqual(Set(files.map { $0.id }), Set([entryA.id, entryB.id]))
        XCTAssertTrue(session.activeEntryIDs().isEmpty)

        let handle = try await client.open(entryID: entryA.id)
        XCTAssertEqual(session.activeEntryIDs(), [entryA.id])
        XCTAssertFalse(session.activeEntryIDs().contains(entryB.id))

        let data = try await client.read(handle: handle, offset: 2, length: 4)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "cdef")

        try await client.close(handle)
        XCTAssertTrue(session.activeEntryIDs().isEmpty)
    }

    func testWrongSessionAndOversizedReadsFailClosed() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FinderSocketWrong-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let vault = try VaultStore().createVault(
            at: root.appendingPathComponent("vault", isDirectory: true),
            password: "socket-test-password"
        )
        let session = FinderReadOnlySession(vault: vault)
        let server = FinderSessionSocketServerCore(rpc: FinderSessionRPC(session: session))

        let wrong = FinderSessionSocketWire.Request(sessionID: UUID(), operation: .listRoot)
        let wrongResponse = server.handle(wrong)
        XCTAssertEqual(wrongResponse.errorCode, "wrong_session")

        let client = FinderSessionSocketClientCore(sessionID: server.id) { frame in
            let request = try FinderSessionSocketWire.decodeFrame(FinderSessionSocketWire.Request.self, from: frame)
            let response = server.handle(request)
            return try FinderSessionSocketWire.encodeFrame(response)
        }

        let forged = FinderSessionSocketClientCore.Handle(id: UUID(), entryID: UUID())
        await XCTAssertThrowsErrorAsync {
            _ = try await client.read(
                handle: forged,
                offset: 0,
                length: FinderSessionRPC.defaultMaximumReadLength + 1
            )
        }
    }
}

private func XCTAssertThrowsErrorAsync(
    _ expression: @escaping () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("Expected error", file: file, line: line)
    } catch {
        // Expected.
    }
}
