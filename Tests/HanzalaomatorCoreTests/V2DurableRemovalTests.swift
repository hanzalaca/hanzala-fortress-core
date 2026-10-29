import XCTest
@testable import HanzalaomatorCore

final class V2DurableRemovalTests: XCTestCase {
    private let fileManager = FileManager.default

    func testDirectorySyncFailureAfterUnlinkKeepsAuthenticatedTombstoneUntilFreshRecovery() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x91, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let failingCommitter = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            synchronizeDirectory: { _ in
                throw V2DurableFileCommitError.namespaceSyncFailed
            }
        )
        let objectStore = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: failingCommitter
        )
        let budget = try V2StorageBudget(
            totalBytes: 32 * 1024 * 1024,
            reserveBytes: 4 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let objectName = String(repeating: "9", count: V2OpaqueObjectName.encodedLength)
        let entryID = UUID(uuidString: "91000000-0000-0000-0000-000000000001")!
        let entry = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            nameGenerator: { objectName },
            transactionIDGenerator: { entryID }
        ).importData(
            Data("durably remove me".utf8),
            originalName: "report.txt",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        let removalID = UUID(uuidString: "91000000-0000-0000-0000-000000000002")!
        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore,
                transactionIDGenerator: { removalID }
            ).removeEntry(id: entry.id, masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectDeleteFailed)
        }

        XCTAssertFalse(fileManager.fileExists(
            atPath: V2StorageLayout.objectURL(named: objectName, in: root).path
        ))
        let afterFailure = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(afterFailure.pendingRemovals.map(\.transactionID), [removalID])
        XCTAssertTrue(afterFailure.entries.isEmpty)

        // Simulate a later clean process/boot. Fresh normal stores first sync the
        // already-missing exact namespace entry, then finalize the tombstone.
        let freshMetadata = V2AccessMetadataStore(fileManager: fileManager)
        let freshObjects = V2PoolObjectStore(fileManager: fileManager)
        let report = try V2RemovalTransactionCoordinator(
            metadataStore: freshMetadata,
            objectStore: freshObjects
        ).recoverPendingRemovals(masterKey: key, in: root)

        XCTAssertEqual(report.deletedTransactionIDs, [])
        XCTAssertEqual(report.finalizedAlreadyMissingTransactionIDs, [removalID])
        XCTAssertTrue(
            try freshMetadata.read(masterKey: key, in: root).pendingRemovals.isEmpty
        )
    }

    func testAlreadyMissingObjectIsNotFinalizedWhenDirectorySyncCannotBeConfirmed() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x92, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let normalObjects = V2PoolObjectStore(fileManager: fileManager)
        let budget = try V2StorageBudget(
            totalBytes: 32 * 1024 * 1024,
            reserveBytes: 4 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let objectName = String(repeating: "8", count: V2OpaqueObjectName.encodedLength)
        let entryID = UUID(uuidString: "92000000-0000-0000-0000-000000000001")!
        let entry = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: normalObjects,
            nameGenerator: { objectName },
            transactionIDGenerator: { entryID }
        ).importData(
            Data("interrupted delete".utf8),
            originalName: "evidence.bin",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        let removalID = UUID(uuidString: "92000000-0000-0000-0000-000000000002")!
        let current = try metadataStore.read(masterKey: key, in: root)
        let pending = try current.beginningRemoval(
            entryID: entry.id,
            transactionID: removalID
        )
        try metadataStore.commitSpaceReleasingRemovalTransition(
            from: current,
            to: pending,
            masterKey: key,
            in: root
        )
        try fileManager.removeItem(
            at: V2StorageLayout.objectURL(named: objectName, in: root)
        )

        let failingCommitter = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            synchronizeDirectory: { _ in
                throw V2DurableFileCommitError.namespaceSyncFailed
            }
        )
        let failingObjects = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: failingCommitter
        )

        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: failingObjects
            ).recoverPendingRemovals(masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectDeleteFailed)
        }

        XCTAssertEqual(
            try metadataStore.read(masterKey: key, in: root)
                .pendingRemovals.map(\.transactionID),
            [removalID]
        )
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-durable-removal-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        return root
    }
}
