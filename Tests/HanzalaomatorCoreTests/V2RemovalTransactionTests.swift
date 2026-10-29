import XCTest
@testable import HanzalaomatorCore

final class V2RemovalTransactionTests: XCTestCase {
    private let fileManager = FileManager.default

    func testRemoveEntryDeletesOnlyAuthenticatedObjectAndFinalizesTombstone() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x61, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let objectStore = V2PoolObjectStore()
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let objectName = opaque("a")
        let entryID = UUID(uuidString: "51000000-0000-0000-0000-000000000001")!
        let entry = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            nameGenerator: { objectName },
            transactionIDGenerator: { entryID }
        ).importData(
            Data("delete me safely".utf8),
            originalName: "report.txt",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        let removalID = UUID(uuidString: "52000000-0000-0000-0000-000000000001")!
        let returnedID = try V2RemovalTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            transactionIDGenerator: { removalID }
        ).removeEntry(id: entry.id, masterKey: key, in: root)

        XCTAssertEqual(returnedID, removalID)
        XCTAssertFalse(objectStore.containsObject(named: objectName, in: root))

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(metadata.generation, 4)
        XCTAssertTrue(metadata.entries.isEmpty)
        XCTAssertTrue(metadata.pendingRemovals.isEmpty)
        XCTAssertEqual(metadata.usage, V2LogicalUsageLedger())
        XCTAssertFalse(metadata.authenticatedOwnedObjectNames.contains(objectName))
    }

    func testPendingRemovalIsOwnedTombstonedAndKeepsCapacityReserved() throws {
        let budget = try V2StorageBudget(totalBytes: 100, reserveBytes: 20)
        let entryID = UUID(uuidString: "53000000-0000-0000-0000-000000000001")!
        let removalID = UUID(uuidString: "53000000-0000-0000-0000-000000000002")!
        let objectName = opaque("b")
        let entry = V2AccessEntry(
            id: entryID,
            opaqueObjectName: objectName,
            originalName: "live.bin",
            logicalByteCount: 70
        )
        let metadata = V2AccessMetadata(
            entries: [entry],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 70, objectCount: 1)
        )

        let pending = try metadata.beginningRemoval(
            entryID: entryID,
            transactionID: removalID,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        XCTAssertTrue(pending.entries.isEmpty)
        XCTAssertEqual(pending.pendingRemovals.count, 1)
        XCTAssertEqual(pending.pendingRemovals[0].opaqueObjectName, objectName)
        XCTAssertEqual(pending.pendingRemovals[0].logicalByteCount, 70)
        XCTAssertEqual(pending.usage, V2LogicalUsageLedger())
        XCTAssertEqual(pending.pendingRemovalLogicalBytes, 70)
        XCTAssertTrue(pending.authenticatedOwnedObjectNames.contains(objectName))
        XCTAssertTrue(pending.authenticatedTombstonedObjectNames.contains(objectName))

        XCTAssertThrowsError(
            try pending.beginningImport(V2PendingImport(
                opaqueObjectName: opaque("c"),
                originalName: "too-soon.bin",
                logicalByteCount: 11
            ))
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .usageExceedsBudget)
        }
    }

    func testRecoveryDeletesAuthenticatedObjectLeftAfterCrash() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x62, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let objectStore = V2PoolObjectStore()
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let objectName = opaque("d")
        let entryID = UUID(uuidString: "54000000-0000-0000-0000-000000000001")!
        let entry = try importEntry(
            name: objectName,
            entryID: entryID,
            content: Data("survived crash".utf8),
            key: key,
            root: root,
            metadataStore: metadataStore,
            objectStore: objectStore
        )

        let removalID = UUID(uuidString: "54000000-0000-0000-0000-000000000002")!
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningRemoval(
            entryID: entry.id,
            transactionID: removalID,
            createdAt: Date(timeIntervalSince1970: 1_700_000_001)
        )
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)
        XCTAssertTrue(objectStore.containsObject(named: objectName, in: root))

        let report = try V2RemovalTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).recoverPendingRemovals(masterKey: key, in: root)

        XCTAssertEqual(report.deletedTransactionIDs, [removalID])
        XCTAssertEqual(report.finalizedAlreadyMissingTransactionIDs, [])
        XCTAssertFalse(objectStore.containsObject(named: objectName, in: root))
        let recovered = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(recovered.pendingRemovals.isEmpty)
        XCTAssertTrue(recovered.entries.isEmpty)
    }

    func testRecoveryFinalizesTombstoneWhenObjectAlreadyMissing() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x63, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let objectStore = V2PoolObjectStore()
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let objectName = opaque("e")
        let entryID = UUID(uuidString: "55000000-0000-0000-0000-000000000001")!
        let entry = try importEntry(
            name: objectName,
            entryID: entryID,
            content: Data("already removed".utf8),
            key: key,
            root: root,
            metadataStore: metadataStore,
            objectStore: objectStore
        )

        let removalID = UUID(uuidString: "55000000-0000-0000-0000-000000000002")!
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningRemoval(
            entryID: entry.id,
            transactionID: removalID,
            createdAt: Date(timeIntervalSince1970: 1_700_000_002)
        )
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)
        try fileManager.removeItem(at: V2StorageLayout.objectURL(named: objectName, in: root))

        let report = try V2RemovalTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).recoverPendingRemovals(masterKey: key, in: root)

        XCTAssertEqual(report.deletedTransactionIDs, [])
        XCTAssertEqual(report.finalizedAlreadyMissingTransactionIDs, [removalID])
        let recovered = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(recovered.pendingRemovals.isEmpty)
        XCTAssertTrue(recovered.entries.isEmpty)
    }

    func testRecoveryFailsClosedForWrongKeyObjectAndPreservesTombstone() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let keyA = Data(repeating: 0x64, count: 32)
        let keyB = Data(repeating: 0x65, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let objectStore = V2PoolObjectStore()
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: keyA, in: root)

        let objectName = opaque("f")
        let entryID = UUID(uuidString: "56000000-0000-0000-0000-000000000001")!
        let entry = try importEntry(
            name: objectName,
            entryID: entryID,
            content: Data([1, 2, 3, 4]),
            key: keyA,
            root: root,
            metadataStore: metadataStore,
            objectStore: objectStore
        )

        let removalID = UUID(uuidString: "56000000-0000-0000-0000-000000000002")!
        let current = try metadataStore.read(masterKey: keyA, in: root)
        let claimed = try current.beginningRemoval(entryID: entry.id, transactionID: removalID)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: keyA, in: root)

        let objectURL = V2StorageLayout.objectURL(named: objectName, in: root)
        try fileManager.removeItem(at: objectURL)
        _ = try objectStore.createObject(
            named: objectName,
            kind: .data,
            content: Data([1, 2, 3, 4]),
            masterKey: keyB,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore
            ).recoverPendingRemovals(masterKey: keyA, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }

        let after = try metadataStore.read(masterKey: keyA, in: root)
        XCTAssertEqual(after.pendingRemovals.count, 1)
        XCTAssertEqual(after.pendingRemovals[0].transactionID, removalID)
        XCTAssertTrue(fileManager.fileExists(atPath: objectURL.path))
    }

    func testRecoveryFailsClosedForLengthMismatchAndPreservesObject() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x66, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let objectStore = V2PoolObjectStore()
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let objectName = opaque("1")
        let entryID = UUID(uuidString: "57000000-0000-0000-0000-000000000001")!
        let entry = try importEntry(
            name: objectName,
            entryID: entryID,
            content: Data([1, 2, 3, 4]),
            key: key,
            root: root,
            metadataStore: metadataStore,
            objectStore: objectStore
        )

        let removalID = UUID(uuidString: "57000000-0000-0000-0000-000000000002")!
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningRemoval(entryID: entry.id, transactionID: removalID)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let objectURL = V2StorageLayout.objectURL(named: objectName, in: root)
        try fileManager.removeItem(at: objectURL)
        _ = try objectStore.createObject(
            named: objectName,
            kind: .data,
            content: Data([9, 9, 9, 9, 9]),
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore
            ).recoverPendingRemovals(masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectLengthMismatch)
        }

        let after = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(after.pendingRemovals.count, 1)
        XCTAssertTrue(fileManager.fileExists(atPath: objectURL.path))
    }

    func testRecoveryRejectsSymlinkWithoutDeletingTarget() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x67, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let objectStore = V2PoolObjectStore()
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let objectName = opaque("2")
        let entryID = UUID(uuidString: "58000000-0000-0000-0000-000000000001")!
        let entry = try importEntry(
            name: objectName,
            entryID: entryID,
            content: Data("symlink".utf8),
            key: key,
            root: root,
            metadataStore: metadataStore,
            objectStore: objectStore
        )

        let removalID = UUID(uuidString: "58000000-0000-0000-0000-000000000002")!
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningRemoval(entryID: entry.id, transactionID: removalID)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let objectURL = V2StorageLayout.objectURL(named: objectName, in: root)
        try fileManager.removeItem(at: objectURL)
        let target = root.appendingPathComponent("outside-target.bin")
        try Data("do not delete".utf8).write(to: target)
        try fileManager.createSymbolicLink(at: objectURL, withDestinationURL: target)

        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore
            ).recoverPendingRemovals(masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectIsNotRegularFile)
        }

        XCTAssertTrue(fileManager.fileExists(atPath: target.path))
        let after = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(after.pendingRemovals.count, 1)
    }

    func testUnknownEntryCannotBecomeDeletionCapability() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let metadata = V2AccessMetadata(budget: budget)

        XCTAssertThrowsError(
            try metadata.beginningRemoval(
                entryID: UUID(),
                transactionID: UUID()
            )
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataTransitionError, .entryNotFound)
        }
    }

    func testMetadataWithoutPendingRemovalsDecodesAsEmpty() throws {
        struct PreviousMetadata: Codable {
            let formatVersion: UInt32
            let accessID: UUID
            let generation: UInt64
            let entries: [V2AccessEntry]
            let pendingImports: [V2PendingImport]
            let tombstonedObjectNames: [String]
            let budget: V2StorageBudget
            let usage: V2LogicalUsageLedger
        }

        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let previous = PreviousMetadata(
            formatVersion: V2AccessMetadata.formatVersion,
            accessID: UUID(),
            generation: 0,
            entries: [],
            pendingImports: [],
            tombstonedObjectNames: [],
            budget: budget,
            usage: V2LogicalUsageLedger()
        )
        let data = try JSONEncoder().encode(previous)
        let decoded = try JSONDecoder().decode(V2AccessMetadata.self, from: data)

        XCTAssertTrue(decoded.pendingRemovals.isEmpty)
        XCTAssertNoThrow(try decoded.validate())
    }

    private func importEntry(
        name: String,
        entryID: UUID,
        content: Data,
        key: Data,
        root: URL,
        metadataStore: V2AccessMetadataStore,
        objectStore: V2PoolObjectStore
    ) throws -> V2AccessEntry {
        try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            nameGenerator: { name },
            transactionIDGenerator: { entryID }
        ).importData(
            content,
            originalName: "evidence.bin",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-removal-transaction-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
