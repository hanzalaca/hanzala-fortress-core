import XCTest
@testable import HanzalaomatorCore

final class V2OwnershipTransactionTests: XCTestCase {
    private let fileManager = FileManager.default

    func testImportClaimsNameBeforeWriteThenPublishesLiveEntry() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x51, count: 32)
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        let metadataStore = V2AccessMetadataStore()
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let name = opaque("a")
        let transactionID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
        let objectStore = V2PoolObjectStore()
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            nameGenerator: { name },
            transactionIDGenerator: { transactionID }
        )
        let content = Data("authenticated import".utf8)

        let entry = try coordinator.importData(
            content,
            originalName: "report.txt",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertEqual(entry.id, transactionID)
        XCTAssertEqual(entry.opaqueObjectName, name)
        XCTAssertEqual(entry.originalName, "report.txt")
        XCTAssertEqual(entry.logicalByteCount, UInt64(content.count))

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(metadata.generation, 2)
        XCTAssertTrue(metadata.pendingImports.isEmpty)
        XCTAssertEqual(metadata.entries, [entry])
        XCTAssertEqual(metadata.usage.logicalBytes, UInt64(content.count))
        XCTAssertEqual(metadata.usage.objectCount, 1)

        let opened = try objectStore.readObject(named: name, masterKey: key, in: root)
        XCTAssertEqual(opened.kind, .data)
        XCTAssertEqual(opened.content, content)
    }

    func testPhysicalAdmissionFailureAbortsClaimBeforeObjectCreation() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x61, count: 32)
        let budget = try V2StorageBudget(totalBytes: 40_000_000, reserveBytes: 1_000_000)
        let metadataCapacity = V2PhysicalCapacityGuard { _ in UInt64.max }
        let metadataStore = V2AccessMetadataStore(
            physicalCapacityGuard: metadataCapacity
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let name = opaque("7")
        let objectStore = V2PoolObjectStore()
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            physicalCapacityGuard: V2PhysicalCapacityGuard { _ in 0 },
            nameGenerator: { name }
        )

        XCTAssertThrowsError(
            try coordinator.importData(
                Data("low space".utf8),
                originalName: "low-space.txt",
                masterKey: key,
                in: root,
                paddedPlaintextByteCount: 4_096
            )
        ) { error in
            guard case .insufficientPhysicalCapacity = error as? V2PhysicalCapacityGuardError else {
                return XCTFail("Expected physical-capacity rejection, got \(error)")
            }
        }

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(metadata.generation, 2)
        XCTAssertTrue(metadata.pendingImports.isEmpty)
        XCTAssertTrue(metadata.entries.isEmpty)
        XCTAssertEqual(metadata.usage, V2LogicalUsageLedger())
        XCTAssertFalse(objectStore.containsObject(named: name, in: root))
    }

    func testExistingCandidateIsSkippedWithoutClaimOrOverwrite() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x52, count: 32)
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        let metadataStore = V2AccessMetadataStore()
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let existingName = opaque("b")
        let freshName = opaque("c")
        let objectStore = V2PoolObjectStore()
        let sentinel = Data("existing object".utf8)
        _ = try objectStore.createObject(
            named: existingName,
            kind: .data,
            content: sentinel,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )
        let existingURL = V2StorageLayout.objectURL(named: existingName, in: root)
        let before = try Data(contentsOf: existingURL)

        var names = [existingName, freshName]
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            nameGenerator: { names.removeFirst() }
        )
        let entry = try coordinator.importData(
            Data("new object".utf8),
            originalName: "new.txt",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertEqual(entry.opaqueObjectName, freshName)
        XCTAssertEqual(try Data(contentsOf: existingURL), before)
        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertFalse(metadata.authenticatedOwnedObjectNames.contains(existingName))
        XCTAssertTrue(metadata.authenticatedOwnedObjectNames.contains(freshName))
    }

    func testRecoveryAbortsPendingClaimWhenObjectWasNeverCreated() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x53, count: 32)
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        let metadataStore = V2AccessMetadataStore()
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let transactionID = UUID(uuidString: "20000000-0000-0000-0000-000000000001")!
        let pending = V2PendingImport(
            transactionID: transactionID,
            opaqueObjectName: opaque("d"),
            originalName: "missing.txt",
            logicalByteCount: 123
        )
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningImport(pending)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let report = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: V2PoolObjectStore()
        ).recoverPendingImports(masterKey: key, in: root)

        XCTAssertEqual(report.finalizedTransactionIDs, [])
        XCTAssertEqual(report.abortedMissingObjectTransactionIDs, [transactionID])
        let recovered = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(recovered.generation, 2)
        XCTAssertTrue(recovered.pendingImports.isEmpty)
        XCTAssertTrue(recovered.entries.isEmpty)
        XCTAssertEqual(recovered.usage, V2LogicalUsageLedger())
    }

    func testRecoveryFinalizesAuthenticatedObjectLeftAfterCrash() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x54, count: 32)
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        let metadataStore = V2AccessMetadataStore()
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let transactionID = UUID(uuidString: "30000000-0000-0000-0000-000000000001")!
        let name = opaque("e")
        let content = Data("object survived crash".utf8)
        let pending = V2PendingImport(
            transactionID: transactionID,
            opaqueObjectName: name,
            originalName: "survived.txt",
            logicalByteCount: UInt64(content.count)
        )
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningImport(pending)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let objectStore = V2PoolObjectStore()
        _ = try objectStore.createObject(
            named: name,
            kind: .data,
            content: content,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        let report = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).recoverPendingImports(masterKey: key, in: root)

        XCTAssertEqual(report.finalizedTransactionIDs, [transactionID])
        XCTAssertEqual(report.abortedMissingObjectTransactionIDs, [])
        let recovered = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(recovered.generation, 2)
        XCTAssertTrue(recovered.pendingImports.isEmpty)
        XCTAssertEqual(recovered.entries.count, 1)
        XCTAssertEqual(recovered.entries[0].opaqueObjectName, name)
        XCTAssertEqual(recovered.usage.logicalBytes, UInt64(content.count))
    }

    func testRecoveryFailsClosedForWrongKeyObjectAndPreservesPendingClaim() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let keyA = Data(repeating: 0x55, count: 32)
        let keyB = Data(repeating: 0x56, count: 32)
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        let metadataStore = V2AccessMetadataStore()
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: keyA, in: root)

        let transactionID = UUID(uuidString: "40000000-0000-0000-0000-000000000001")!
        let name = opaque("f")
        let pending = V2PendingImport(
            transactionID: transactionID,
            opaqueObjectName: name,
            originalName: "suspicious.bin",
            logicalByteCount: 4
        )
        let current = try metadataStore.read(masterKey: keyA, in: root)
        let claimed = try current.beginningImport(pending)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: keyA, in: root)

        let objectStore = V2PoolObjectStore()
        _ = try objectStore.createObject(
            named: name,
            kind: .data,
            content: Data([1, 2, 3, 4]),
            masterKey: keyB,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertThrowsError(
            try V2OwnershipTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore
            ).recoverPendingImports(masterKey: keyA, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }

        let after = try metadataStore.read(masterKey: keyA, in: root)
        XCTAssertEqual(after.generation, 1)
        XCTAssertEqual(after.pendingImports.count, 1)
        assertSamePendingIgnoringSerializedDate(after.pendingImports[0], pending)
        XCTAssertTrue(fileManager.fileExists(
            atPath: V2StorageLayout.objectURL(named: name, in: root).path
        ))
    }

    func testStaleMetadataTransitionIsRejected() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x57, count: 32)
        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 4_000)
        let store = V2AccessMetadataStore()
        _ = try store.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let original = try store.read(masterKey: key, in: root)
        let first = try original.beginningImport(V2PendingImport(
            opaqueObjectName: opaque("1"),
            originalName: "first.txt",
            logicalByteCount: 10
        ))
        try store.commitTransition(from: original, to: first, masterKey: key, in: root)

        let stale = try original.beginningImport(V2PendingImport(
            opaqueObjectName: opaque("2"),
            originalName: "stale.txt",
            logicalByteCount: 10
        ))
        XCTAssertThrowsError(
            try store.commitTransition(from: original, to: stale, masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .staleMetadata)
        }

        let actual = try store.read(masterKey: key, in: root)
        XCTAssertEqual(actual.pendingImports.count, first.pendingImports.count)
        XCTAssertEqual(actual.pendingImports.count, 1)
        assertSamePendingIgnoringSerializedDate(actual.pendingImports[0], first.pendingImports[0])
    }

    func testPendingImportsReserveBudgetBeforeObjectCreation() throws {
        let budget = try V2StorageBudget(totalBytes: 100, reserveBytes: 20)
        let live = V2AccessEntry(
            opaqueObjectName: opaque("3"),
            originalName: "live.bin",
            logicalByteCount: 70
        )
        let metadata = V2AccessMetadata(
            entries: [live],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 70, objectCount: 1)
        )
        let pending = V2PendingImport(
            opaqueObjectName: opaque("4"),
            originalName: "pending.bin",
            logicalByteCount: 11
        )

        XCTAssertThrowsError(try metadata.beginningImport(pending)) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .usageExceedsBudget)
        }
    }

    func testPendingNameIsAuthenticatedOwnedButNotDeletable() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let name = opaque("5")
        let metadata = try V2AccessMetadata(budget: budget).beginningImport(
            V2PendingImport(
                opaqueObjectName: name,
                originalName: "pending.txt",
                logicalByteCount: 10
            )
        )
        XCTAssertTrue(metadata.authenticatedOwnedObjectNames.contains(name))
        XCTAssertFalse(metadata.authenticatedTombstonedObjectNames.contains(name))

        let decision = V2PoolCleanupPolicy().decision(
            for: name,
            authenticatedOwnedObjectNames: metadata.authenticatedOwnedObjectNames,
            authenticatedTombstonedObjectNames: metadata.authenticatedTombstonedObjectNames
        )
        XCTAssertEqual(decision, .preserveLiveOwned)
    }

    func testLegacyMetadataWithoutPendingImportsDecodesAsEmpty() throws {
        struct LegacyMetadata: Codable {
            let formatVersion: UInt32
            let accessID: UUID
            let generation: UInt64
            let entries: [V2AccessEntry]
            let tombstonedObjectNames: [String]
            let budget: V2StorageBudget
            let usage: V2LogicalUsageLedger
        }

        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let legacy = LegacyMetadata(
            formatVersion: V2AccessMetadata.formatVersion,
            accessID: UUID(),
            generation: 0,
            entries: [],
            tombstonedObjectNames: [],
            budget: budget,
            usage: V2LogicalUsageLedger()
        )
        let data = try JSONEncoder().encode(legacy)
        let decoded = try JSONDecoder().decode(V2AccessMetadata.self, from: data)

        XCTAssertTrue(decoded.pendingImports.isEmpty)
        XCTAssertNoThrow(try decoded.validate())
    }

    func testGenerationOverflowFailsBeforeTransition() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let metadata = V2AccessMetadata(
            generation: UInt64.max,
            budget: budget
        )
        XCTAssertNoThrow(try metadata.validate())

        XCTAssertThrowsError(
            try metadata.beginningImport(V2PendingImport(
                opaqueObjectName: opaque("6"),
                originalName: "overflow.txt",
                logicalByteCount: 1
            ))
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataTransitionError, .generationOverflow)
        }
    }

    private func assertSamePendingIgnoringSerializedDate(
        _ lhs: V2PendingImport,
        _ rhs: V2PendingImport,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(lhs.transactionID, rhs.transactionID, file: file, line: line)
        XCTAssertEqual(lhs.opaqueObjectName, rhs.opaqueObjectName, file: file, line: line)
        XCTAssertEqual(lhs.originalName, rhs.originalName, file: file, line: line)
        XCTAssertEqual(lhs.logicalByteCount, rhs.logicalByteCount, file: file, line: line)
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-ownership-transaction-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
