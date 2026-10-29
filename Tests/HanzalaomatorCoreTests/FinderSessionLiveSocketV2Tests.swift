import XCTest
@testable import HanzalaomatorCore

final class FinderSessionLiveSocketV2Tests: XCTestCase {
    private let fileManager = FileManager.default

    func testV2LiveSocketListsAndReadsWithoutPlaintextLeaseArtifacts() async throws {
        let root = try makeShortRoot()
        defer { try? fileManager.removeItem(at: root) }

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let socketRoot = root.appendingPathComponent("ipc", isDirectory: true)
        let stores = makeStores()
        let session = try createVisibleSession(
            at: vaultRoot,
            stores: stores,
            budgetBytes: 8 * 1024 * 1024
        )
        let content = Data("v2 finder socket protected bytes".utf8)
        let entry = try stores.sessions.importData(
            content,
            originalName: "notes.txt",
            into: session
        )
        let before = try poolLeafNames(in: vaultRoot)

        let finder = V2FinderReadOnlySession(
            session: session,
            sessionStore: stores.sessions
        )
        let rpc = FinderSessionRPC(session: finder)
        let server = try FinderSessionLiveSocketServer(
            containerURL: socketRoot,
            rpc: rpc
        )
        defer { server.stop() }

        let client = FinderSessionLiveSocketClient(
            sessionID: server.sessionID,
            socketURL: server.socketURL
        )

        let files = try await client.listRoot()
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].id, entry.id)
        XCTAssertEqual(files[0].name, "notes.txt")
        XCTAssertEqual(files[0].byteCount, UInt64(content.count))
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)

        let handle = try await client.open(entryID: entry.id)
        XCTAssertEqual(finder.activeEntryIDs(), [entry.id])
        XCTAssertEqual(try poolLeafNames(in: vaultRoot), before)

        let bytes = try await client.read(handle: handle, offset: 3, length: 13)
        XCTAssertEqual(bytes, Data("finder socket".utf8))
        XCTAssertEqual(try poolLeafNames(in: vaultRoot), before)

        try await client.close(handle)
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)
    }

    func testV2LiveSocketReadsAcrossEncryptedChunkBoundary() async throws {
        let root = try makeShortRoot()
        defer { try? fileManager.removeItem(at: root) }

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let socketRoot = root.appendingPathComponent("ipc", isDirectory: true)
        let stores = makeStores()
        let session = try createVisibleSession(
            at: vaultRoot,
            stores: stores,
            budgetBytes: 96 * 1024 * 1024
        )

        let count = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        var content = Data(repeating: 0x77, count: count)
        let boundary = V2ChunkManifest.maximumLogicalChunkByteCount
        content[boundary - 3] = 0x11
        content[boundary - 2] = 0x22
        content[boundary - 1] = 0x33
        content[boundary] = 0x44
        content[boundary + 1] = 0x55

        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: stores.metadata,
            objectStore: stores.objects
        ).importChunkedData(
            content,
            originalName: "large-evidence.mov",
            masterKey: session.masterKey,
            in: vaultRoot
        )
        XCTAssertFalse(entry.auxiliaryObjectNames.isEmpty)

        let finder = V2FinderReadOnlySession(
            session: session,
            sessionStore: stores.sessions
        )
        let server = try FinderSessionLiveSocketServer(
            containerURL: socketRoot,
            rpc: FinderSessionRPC(session: finder)
        )
        defer { server.stop() }
        let client = FinderSessionLiveSocketClient(
            sessionID: server.sessionID,
            socketURL: server.socketURL
        )

        let handle = try await client.open(entryID: entry.id)
        let bytes = try await client.read(
            handle: handle,
            offset: UInt64(boundary - 3),
            length: 5
        )
        XCTAssertEqual(bytes, Data([0x11, 0x22, 0x33, 0x44, 0x55]))
        XCTAssertEqual(finder.activeEntryIDs(), [entry.id])
    }

    func testV2LiveSocketPreservesAccessIsolationAndStopRevokesReads() async throws {
        let root = try makeShortRoot()
        defer { try? fileManager.removeItem(at: root) }

        let vaultRoot = root.appendingPathComponent("vault", isDirectory: true)
        let socketRoot = root.appendingPathComponent("ipc", isDirectory: true)
        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 16 * 1024 * 1024,
            reserveBytes: 2 * 1024 * 1024
        )
        _ = try stores.bootstrap.createDualAccess(
            at: vaultRoot,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-password",
            visibleBudget: budget,
            concealedBudget: budget
        )
        let visible = try stores.sessions.openSession(
            at: vaultRoot,
            password: "ordinary-password"
        ).session
        let concealed = try stores.sessions.openSession(
            at: vaultRoot,
            password: "source-password"
        ).session

        let visibleEntry = try stores.sessions.importData(
            Data("ordinary cover material".utf8),
            originalName: "ordinary.txt",
            into: visible
        )
        let concealedEntry = try stores.sessions.importData(
            Data("protected source material".utf8),
            originalName: "source.txt",
            into: concealed
        )

        let finder = V2FinderReadOnlySession(
            session: visible,
            sessionStore: stores.sessions
        )
        let server = try FinderSessionLiveSocketServer(
            containerURL: socketRoot,
            rpc: FinderSessionRPC(session: finder)
        )
        defer { server.stop() }
        let client = FinderSessionLiveSocketClient(
            sessionID: server.sessionID,
            socketURL: server.socketURL
        )

        let files = try await client.listRoot()
        XCTAssertEqual(Set(files.map(\.id)), Set([visibleEntry.id]))
        XCTAssertFalse(files.contains(where: { $0.id == concealedEntry.id }))

        await XCTAssertThrowsErrorAsyncV2Socket {
            _ = try await client.open(entryID: concealedEntry.id)
        }

        let visibleHandle = try await client.open(entryID: visibleEntry.id)
        let visibleBytes = try await client.read(
            handle: visibleHandle,
            offset: 0,
            length: 8
        )
        XCTAssertEqual(visibleBytes, Data("ordinary".utf8))

        server.stop()
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)

        await XCTAssertThrowsErrorAsyncV2Socket {
            _ = try await client.read(handle: visibleHandle, offset: 0, length: 1)
        }
        await XCTAssertThrowsErrorAsyncV2Socket {
            _ = try await client.listRoot()
        }
    }

    private typealias Stores = (
        bootstrap: V2VaultBootstrapStore,
        metadata: V2AccessMetadataStore,
        objects: V2PoolObjectStore,
        sessions: V2VaultSessionStore
    )

    private func makeStores() -> Stores {
        let keyEngine = PasswordKeyEngine()
        let envelopeEngine = DualAccessEnvelopeEngine(
            keyEngine: keyEngine,
            makeParameters: {
                try keyEngine.makeParameters(
                    operationsLimit: 2,
                    memoryLimit: 32 * 1024 * 1024
                )
            }
        )
        let metadata = V2AccessMetadataStore(fileManager: fileManager)
        let objects = V2PoolObjectStore(fileManager: fileManager)
        let bootstrap = V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: metadata
        )
        let sessions = V2VaultSessionStore(
            bootstrapStore: bootstrap,
            metadataStore: metadata,
            objectStore: objects
        )
        return (bootstrap, metadata, objects, sessions)
    }

    private func createVisibleSession(
        at root: URL,
        stores: Stores,
        budgetBytes: UInt64
    ) throws -> V2VaultSession {
        let budget = try V2StorageBudget(
            totalBytes: budgetBytes,
            reserveBytes: budgetBytes / 8
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        return try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session
    }

    private func poolLeafNames(in root: URL) throws -> [String] {
        try fileManager.contentsOfDirectory(
            at: V2StorageLayout.poolURL(in: root),
            includingPropertiesForKeys: nil
        ).map(\.lastPathComponent).sorted()
    }

    private func makeShortRoot() throws -> URL {
        let root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("hz2-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }
}

private func XCTAssertThrowsErrorAsyncV2Socket(
    _ expression: @escaping () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("Expected error", file: file, line: line)
    } catch {
        // Expected fail-closed transport or authenticated session rejection.
    }
}
