import XCTest
@testable import HanzalaomatorCore

final class FinderSessionDiscoveryTests: XCTestCase {
    func testPublishLoadAndClearDescriptor() throws {
        let root = shortTemporaryRoot()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let sessionID = UUID()
        let socketURL = root
            .appendingPathComponent("socket", isDirectory: true)
            .appendingPathComponent("finder.sock", isDirectory: false)

        let published = try FinderSessionDiscovery.publish(
            containerURL: root,
            sessionID: sessionID,
            socketURL: socketURL,
            createdAt: Date(timeIntervalSince1970: 123)
        )
        XCTAssertEqual(published.sessionID, sessionID)
        XCTAssertEqual(published.socketPath, socketURL.standardizedFileURL.path)

        let loaded = try FinderSessionDiscovery.load(containerURL: root)
        XCTAssertEqual(loaded, published)

        FinderSessionDiscovery.clear(containerURL: root)
        XCTAssertThrowsError(try FinderSessionDiscovery.load(containerURL: root)) { error in
            XCTAssertEqual(error as? FinderSessionDiscoveryError, .descriptorMissing)
        }
    }

    func testPublishRejectsSocketOutsideContainer() throws {
        let root = shortTemporaryRoot()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        XCTAssertThrowsError(
            try FinderSessionDiscovery.publish(
                containerURL: root,
                sessionID: UUID(),
                socketURL: URL(fileURLWithPath: "/tmp/outside-finder.sock")
            )
        ) { error in
            XCTAssertEqual(error as? FinderSessionDiscoveryError, .invalidSocketPath)
        }
    }

    func testPublishedServerMakesLiveSessionDiscoverableAndRemovesItOnStop() async throws {
        let root = shortTemporaryRoot()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let vault = try VaultStore().createVault(
            at: root.appendingPathComponent("vault", isDirectory: true),
            password: "discovery-test-password"
        )
        let source = root.appendingPathComponent("source.txt")
        try Data("finder-discovery-secret".utf8).write(to: source)
        let entry = try VaultObjectStore().importFile(at: source, into: vault)

        let session = FinderReadOnlySession(
            vault: vault,
            leaseStore: OnDemandPlaintextLeaseStore(
                rootDirectory: root.appendingPathComponent("leases", isDirectory: true)
            )
        )
        let published = try FinderSessionPublishedServer(
            containerURL: root.appendingPathComponent("group", isDirectory: true),
            rpc: FinderSessionRPC(session: session)
        )

        let descriptor = try FinderSessionDiscovery.load(
            containerURL: root.appendingPathComponent("group", isDirectory: true)
        )
        XCTAssertEqual(descriptor.sessionID, published.sessionID)

        let client = FinderSessionLiveSocketClient(
            sessionID: descriptor.sessionID,
            socketURL: URL(fileURLWithPath: descriptor.socketPath)
        )
        let files = try await client.listRoot()
        XCTAssertEqual(files.map(\.id), [entry.id])
        XCTAssertTrue(session.activeEntryIDs().isEmpty)

        published.stop()
        XCTAssertThrowsError(
            try FinderSessionDiscovery.load(
                containerURL: root.appendingPathComponent("group", isDirectory: true)
            )
        )
    }

    private func shortTemporaryRoot() -> URL {
        URL(fileURLWithPath: "/tmp/hzd-\(UUID().uuidString.prefix(8))", isDirectory: true)
    }
}
