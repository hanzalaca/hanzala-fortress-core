import XCTest
@testable import HanzalaomatorCore

final class V2FinderReadOnlySessionTests: XCTestCase {
    private let fileManager = FileManager.default

    func testListAndOpenUseLogicalHandlesWithoutCreatingPoolArtifacts() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let session = try createVisibleSession(
            root: root,
            stores: stores,
            budgetBytes: 8 * 1024 * 1024
        )
        let content = Data("finder logical plaintext".utf8)
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

        let files = try finder.listRoot()
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].id, entry.id)
        XCTAssertEqual(files[0].name, "notes.txt")
        XCTAssertEqual(files[0].byteCount, UInt64(content.count))

        let handle = try finder.open(entryID: entry.id)
        XCTAssertEqual(finder.activeEntryIDs(), [entry.id])
        XCTAssertEqual(try poolLeafNames(in: root), before)

        let bytes = try finder.read(handle: handle, offset: 7, length: 7)
        XCTAssertEqual(bytes, Data("logical".utf8))
        XCTAssertEqual(try poolLeafNames(in: root), before)

        finder.close(handle)
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)
    }

    func testChunkedReadCrossesBoundaryWithoutWholeFileLease() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let session = try createVisibleSession(
            root: root,
            stores: stores,
            budgetBytes: 96 * 1024 * 1024
        )

        let count = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        var content = Data(repeating: 0x51, count: count)
        let boundary = V2ChunkManifest.maximumLogicalChunkByteCount
        content[boundary - 2] = 0x11
        content[boundary - 1] = 0x22
        content[boundary] = 0x33
        content[boundary + 1] = 0x44

        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: stores.metadata,
            objectStore: stores.objects
        ).importChunkedData(
            content,
            originalName: "large-source.mov",
            masterKey: session.masterKey,
            in: root
        )
        XCTAssertFalse(entry.auxiliaryObjectNames.isEmpty)

        let finder = V2FinderReadOnlySession(
            session: session,
            sessionStore: stores.sessions
        )
        let handle = try finder.open(entryID: entry.id)
        let bytes = try finder.read(
            handle: handle,
            offset: UInt64(boundary - 2),
            length: 4
        )
        XCTAssertEqual(bytes, Data([0x11, 0x22, 0x33, 0x44]))
        XCTAssertEqual(finder.activeEntryIDs(), [entry.id])
    }

    func testForgedAndClosedHandlesCannotRead() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let session = try createVisibleSession(
            root: root,
            stores: stores,
            budgetBytes: 8 * 1024 * 1024
        )
        let entry = try stores.sessions.importData(
            Data("secret".utf8),
            originalName: "secret.txt",
            into: session
        )
        let finder = V2FinderReadOnlySession(
            session: session,
            sessionStore: stores.sessions
        )
        let real = try finder.open(entryID: entry.id)
        let forged = V2FinderReadOnlySession.OpenHandle(
            id: UUID(),
            entryID: entry.id
        )

        XCTAssertThrowsError(
            try finder.read(handle: forged, offset: 0, length: 1)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .handleNotFound)
        }

        finder.close(real)
        XCTAssertThrowsError(
            try finder.read(handle: real, offset: 0, length: 1)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .handleNotFound)
        }
    }

    func testVisibleFinderSessionCannotOpenConcealedEntry() throws {
        let root = try makeRoot(removeAfterCreating: true)
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
        XCTAssertTrue(try visibleFinder.listRoot().isEmpty)
        XCTAssertThrowsError(
            try visibleFinder.open(entryID: concealedEntry.id)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .entryNotFound)
        }
    }

    func testBoundsAndInvalidationFailClosed() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores(maximumReadLength: 32)
        let session = try createVisibleSession(
            root: root,
            stores: stores,
            budgetBytes: 8 * 1024 * 1024
        )
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
        let handle = try finder.open(entryID: entry.id)

        XCTAssertThrowsError(
            try finder.read(handle: handle, offset: 0, length: -1)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .invalidReadRange)
        }
        XCTAssertThrowsError(
            try finder.read(handle: handle, offset: 0, length: 33)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .readTooLarge)
        }

        finder.invalidate()
        XCTAssertTrue(finder.activeEntryIDs().isEmpty)
        XCTAssertThrowsError(try finder.listRoot()) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
        }
        XCTAssertThrowsError(
            try finder.read(handle: handle, offset: 0, length: 1)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
        }
        XCTAssertThrowsError(try finder.open(entryID: entry.id)) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
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
        let pool = V2StorageLayout.poolURL(in: root)
        return try fileManager.contentsOfDirectory(
            at: pool,
            includingPropertiesForKeys: nil
        ).map(\.lastPathComponent).sorted()
    }

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-finder-session-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        if removeAfterCreating {
            try fileManager.removeItem(at: url)
        }
        return url
    }
}
