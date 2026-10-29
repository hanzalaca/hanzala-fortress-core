import XCTest
@testable import HanzalaomatorCore

final class FinderSessionRPCV2Tests: XCTestCase {
    private let fileManager = FileManager.default

    func testV2RPCListsOpensAndReadsWithoutPlaintextLeaseFiles() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let session = try createVisibleSession(root: root, stores: stores, budgetBytes: 8 * 1024 * 1024)
        let content = Data("authenticated finder rpc bytes".utf8)
        let entry = try stores.sessions.importData(
            content,
            originalName: "notes.txt",
            into: session
        )
        let before = try poolLeafNames(in: root)

        let finder = V2FinderReadOnlySession(
            session: session,
            sessionStore: stores.sessions
        )
        let rpc = FinderSessionRPC(session: finder)

        let files = try rpc.listRoot()
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].id, entry.id)
        XCTAssertEqual(files[0].name, "notes.txt")
        XCTAssertEqual(files[0].byteCount, UInt64(content.count))
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)

        let handle = try rpc.open(entryID: entry.id)
        XCTAssertEqual(finder.activeEntryIDs(), [entry.id])
        XCTAssertEqual(try poolLeafNames(in: root), before)

        let bytes = try rpc.read(handle: handle, offset: 14, length: 6)
        XCTAssertEqual(bytes, Data("finder".utf8))
        XCTAssertEqual(try poolLeafNames(in: root), before)

        rpc.close(handle)
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)
    }

    func testV2RPCReadsAcrossChunkBoundaryThroughLogicalHandle() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let session = try createVisibleSession(root: root, stores: stores, budgetBytes: 96 * 1024 * 1024)

        let count = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        var content = Data(repeating: 0x6A, count: count)
        let boundary = V2ChunkManifest.maximumLogicalChunkByteCount
        content[boundary - 2] = 0x10
        content[boundary - 1] = 0x20
        content[boundary] = 0x30
        content[boundary + 1] = 0x40

        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: stores.metadata,
            objectStore: stores.objects
        ).importChunkedData(
            content,
            originalName: "large-evidence.mov",
            masterKey: session.masterKey,
            in: root
        )

        let finder = V2FinderReadOnlySession(session: session, sessionStore: stores.sessions)
        let rpc = FinderSessionRPC(session: finder)
        let handle = try rpc.open(entryID: entry.id)
        let bytes = try rpc.read(
            handle: handle,
            offset: UInt64(boundary - 2),
            length: 4
        )

        XCTAssertEqual(bytes, Data([0x10, 0x20, 0x30, 0x40]))
        XCTAssertEqual(finder.activeEntryIDs(), [entry.id])
    }

    func testV2RPCRejectsForgedClosedAndOversizedHandles() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores(maximumReadLength: 32)
        let session = try createVisibleSession(root: root, stores: stores, budgetBytes: 8 * 1024 * 1024)
        let entry = try stores.sessions.importData(
            Data(repeating: 0xAA, count: 64),
            originalName: "bounded.bin",
            into: session
        )

        let finder = V2FinderReadOnlySession(
            session: session,
            sessionStore: stores.sessions,
            maximumReadLength: 32
        )
        let rpc = FinderSessionRPC(session: finder, maximumReadLength: 16)
        let handle = try rpc.open(entryID: entry.id)

        XCTAssertThrowsError(try rpc.read(handle: handle, offset: 0, length: -1)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .invalidReadLength)
        }
        XCTAssertThrowsError(try rpc.read(handle: handle, offset: 0, length: 17)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .readTooLarge)
        }

        let forged = FinderSessionRPC.RemoteHandle(id: UUID(), entryID: entry.id)
        XCTAssertThrowsError(try rpc.read(handle: forged, offset: 0, length: 1)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .unknownHandle)
        }

        let forgedEntry = FinderSessionRPC.RemoteHandle(id: handle.id, entryID: UUID())
        XCTAssertThrowsError(try rpc.read(handle: forgedEntry, offset: 0, length: 1)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .unknownHandle)
        }

        rpc.close(handle)
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)
        XCTAssertThrowsError(try rpc.read(handle: handle, offset: 0, length: 1)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .unknownHandle)
        }
    }

    func testV2RPCPreservesAccessPathIsolationAndInvalidatesFailClosed() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 16 * 1024 * 1024,
            reserveBytes: 2 * 1024 * 1024
        )
        _ = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-password",
            visibleBudget: budget,
            concealedBudget: budget
        )
        let visible = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session
        let concealed = try stores.sessions.openSession(
            at: root,
            password: "source-password"
        ).session
        let concealedEntry = try stores.sessions.importData(
            Data("protected source".utf8),
            originalName: "source.txt",
            into: concealed
        )

        let visibleFinder = V2FinderReadOnlySession(
            session: visible,
            sessionStore: stores.sessions
        )
        let visibleRPC = FinderSessionRPC(session: visibleFinder)

        XCTAssertTrue(try visibleRPC.listRoot().isEmpty)
        XCTAssertThrowsError(try visibleRPC.open(entryID: concealedEntry.id)) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .entryNotFound)
        }

        visibleRPC.invalidate()
        XCTAssertTrue(visibleFinder.activeEntryIDs().isEmpty)
        XCTAssertThrowsError(try visibleRPC.listRoot()) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .invalidated)
        }
        XCTAssertThrowsError(try visibleRPC.open(entryID: concealedEntry.id)) { error in
            XCTAssertEqual(error as? FinderSessionRPCError, .invalidated)
        }
    }

    private typealias Stores = (
        bootstrap: V2VaultBootstrapStore,
        metadata: V2AccessMetadataStore,
        objects: V2PoolObjectStore,
        sessions: V2VaultSessionStore
    )

    private func makeStores(
        maximumReadLength: Int = V2VaultSessionStore.defaultMaximumReadLength
    ) -> Stores {
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
            objectStore: objects,
            maximumReadLength: maximumReadLength
        )
        return (bootstrap, metadata, objects, sessions)
    }

    private func createVisibleSession(
        root: URL,
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

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-finder-rpc-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try fileManager.removeItem(at: url)
        return url
    }
}
