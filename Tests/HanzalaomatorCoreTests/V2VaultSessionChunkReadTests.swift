import XCTest
@testable import HanzalaomatorCore

final class V2VaultSessionChunkReadTests: XCTestCase {
    private let fileManager = FileManager.default

    func testSessionReadsChunkedEntryAcrossBoundaryAndVerifiesIntegrity() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let content = makeLargeContent()
        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: stores.metadata,
            objectStore: stores.objects
        ).importChunkedData(
            content,
            originalName: "evidence.mov",
            masterKey: session.masterKey,
            in: root
        )

        XCTAssertFalse(entry.auxiliaryObjectNames.isEmpty)
        XCTAssertEqual(try stores.sessions.listEntries(in: session), [entry])

        let boundary = UInt64(V2ChunkManifest.maximumLogicalChunkByteCount)
        let offset = boundary - 37
        let length = 113
        let result = try stores.sessions.readEntryRange(
            id: entry.id,
            offset: offset,
            length: length,
            in: session
        )
        let expectedStart = Int(offset)
        XCTAssertEqual(
            result,
            Data(content[expectedStart..<(expectedStart + length)])
        )

        XCTAssertNoThrow(
            try stores.sessions.verifyEntryIntegrity(id: entry.id, in: session)
        )
        XCTAssertThrowsError(
            try stores.sessions.readEntry(id: entry.id, in: session)
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .unexpectedObjectKind)
        }
    }

    func testSessionChunkedReadUsesAuthenticatedEntryIdentityAcrossAccessPaths() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
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

        let content = makeLargeContent()
        let concealedEntry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: stores.metadata,
            objectStore: stores.objects
        ).importChunkedData(
            content,
            originalName: "source-video.mov",
            masterKey: concealed.masterKey,
            in: root
        )

        XCTAssertEqual(
            try stores.sessions.readEntryRange(
                id: concealedEntry.id,
                offset: 128,
                length: 512,
                in: concealed
            ),
            Data(content[128..<640])
        )

        XCTAssertThrowsError(
            try stores.sessions.readEntryRange(
                id: concealedEntry.id,
                offset: 0,
                length: 32,
                in: visible
            )
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .entryNotFound)
        }
        XCTAssertThrowsError(
            try stores.sessions.verifyEntryIntegrity(
                id: concealedEntry.id,
                in: visible
            )
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .entryNotFound)
        }
    }

    func testSessionReadRangeEnforcesBoundBeforeTouchingStorage() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

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
            maximumReadLength: 64
        )
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session
        let entry = try sessions.importData(
            Data(repeating: 0x44, count: 128),
            originalName: "bounded.bin",
            into: session
        )

        XCTAssertThrowsError(
            try sessions.readEntryRange(
                id: entry.id,
                offset: 0,
                length: 65,
                in: session
            )
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .readTooLarge)
        }
        XCTAssertThrowsError(
            try sessions.readEntryRange(
                id: entry.id,
                offset: 0,
                length: -1,
                in: session
            )
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .invalidReadLength)
        }
        XCTAssertEqual(
            try sessions.readEntryRange(
                id: entry.id,
                offset: 120,
                length: 64,
                in: session
            ),
            Data(repeating: 0x44, count: 8)
        )
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

    private func makeLargeContent() -> Data {
        let count = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        var data = Data(repeating: 0x5A, count: count)
        let boundary = V2ChunkManifest.maximumLogicalChunkByteCount
        if boundary > 0, boundary + 2 < data.count {
            data[boundary - 1] = 0xA1
            data[boundary] = 0xB2
            data[boundary + 1] = 0xC3
            data[boundary + 2] = 0xD4
        }
        return data
    }

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-session-chunk-read-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        if removeAfterCreating {
            try fileManager.removeItem(at: url)
        }
        return url
    }
}
