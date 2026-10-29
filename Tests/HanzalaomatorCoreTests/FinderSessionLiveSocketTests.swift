import XCTest
@testable import HanzalaomatorCore

final class FinderSessionLiveSocketTests: XCTestCase {
    func testLiveSocketDecryptsOnlyOpenedEntry() async throws {
        let root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("hzl-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let leaseRoot = root.appendingPathComponent("leases", isDirectory: true)
        let socketRoot = root.appendingPathComponent("ipc", isDirectory: true)
        let vault = try VaultStore().createVault(at: vaultRoot, password: "live-socket-test-password")

        let firstURL = root.appendingPathComponent("first.txt")
        let secondURL = root.appendingPathComponent("second.txt")
        try Data("first-secret-material".utf8).write(to: firstURL)
        try Data("second-secret-material".utf8).write(to: secondURL)

        let objectStore = VaultObjectStore()
        let first = try objectStore.importFile(at: firstURL, into: vault)
        let second = try objectStore.importFile(at: secondURL, into: vault)

        let leases = OnDemandPlaintextLeaseStore(rootDirectory: leaseRoot)
        let session = FinderReadOnlySession(vault: vault, leaseStore: leases)
        let rpc = FinderSessionRPC(session: session)
        let server = try FinderSessionLiveSocketServer(containerURL: socketRoot, rpc: rpc)
        defer { server.stop() }

        let client = FinderSessionLiveSocketClient(sessionID: server.sessionID, socketURL: server.socketURL)

        let files = try await client.listRoot()
        XCTAssertEqual(Set(files.map(\.id)), Set([first.id, second.id]))
        XCTAssertTrue(session.activeEntryIDs().isEmpty)

        let handle = try await client.open(entryID: first.id)
        XCTAssertEqual(session.activeEntryIDs(), [first.id])
        XCTAssertFalse(session.activeEntryIDs().contains(second.id))

        let bytes = try await client.read(handle: handle, offset: 6, length: 6)
        XCTAssertEqual(String(decoding: bytes, as: UTF8.self), "secret")
        XCTAssertEqual(session.activeEntryIDs(), [first.id])

        try await client.close(handle)
        XCTAssertTrue(session.activeEntryIDs().isEmpty)

        await client.invalidate()
        await XCTAssertThrowsErrorAsyncLiveSocket {
            _ = try await client.listRoot()
        }
    }
}

private func XCTAssertThrowsErrorAsyncLiveSocket(
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
