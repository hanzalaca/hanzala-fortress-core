import XCTest
@testable import HanzalaomatorCore

final class V2VaultSessionChunkRemovalTests: XCTestCase {
    private let fileManager = FileManager.default

    func testSessionRemovesAuthenticatedChunkedEntryWithoutExposingPoolNames() throws {
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
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let objectStore = V2PoolObjectStore(fileManager: fileManager)
        let bootstrap = V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: metadataStore
        )
        let sessions = V2VaultSessionStore(
            bootstrapStore: bootstrap,
            metadataStore: metadataStore,
            objectStore: objectStore
        )
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let content = Data(
            repeating: 0xA5,
            count: V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        )
        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).importChunkedData(
            content,
            originalName: "large-source.mov",
            masterKey: session.masterKey,
            in: root
        )
        let ownedNames = [entry.opaqueObjectName] + entry.auxiliaryObjectNames
        XCTAssertFalse(entry.auxiliaryObjectNames.isEmpty)
        XCTAssertTrue(ownedNames.allSatisfy {
            objectStore.containsObject(named: $0, in: root)
        })

        let removalID = try sessions.removeEntry(id: entry.id, from: session)
        XCTAssertNotNil(removalID)
        XCTAssertTrue(try sessions.listEntries(in: session).isEmpty)
        XCTAssertTrue(ownedNames.allSatisfy {
            !objectStore.containsObject(named: $0, in: root)
        })

        let metadata = try metadataStore.read(masterKey: session.masterKey, in: root)
        XCTAssertTrue(metadata.pendingRemovals.isEmpty)
        XCTAssertEqual(metadata.usage, V2LogicalUsageLedger())
    }

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-session-chunk-removal-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        if removeAfterCreating {
            try fileManager.removeItem(at: url)
        }
        return url
    }
}
