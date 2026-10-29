import XCTest
@testable import HanzalaomatorCore

final class V2PowerLossFaultInjectionTests: XCTestCase {
    private let fileManager = FileManager.default

    func testWriteNewCrashBeforeNamespaceCommitLeavesOnlyStagingResidue() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("final.bin")
        let payload = Data("durable ciphertext".utf8)

        let committer = makeCrashCommitter(at: .afterStagingSync)

        XCTAssertThrowsError(
            try committer.writeNew(
                payload,
                to: destination,
                stagingPrefix: ".hz-powerloss-"
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DurableCommitSimulatedCrash,
                .powerLoss(.afterStagingSync)
            )
        }

        XCTAssertFalse(fileManager.fileExists(atPath: destination.path))
        XCTAssertEqual(
            try names(in: root, prefix: ".hz-powerloss-").count,
            1
        )
    }

    func testWriteNewCrashAfterNamespaceCommitLeavesPublishedDestination() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("final.bin")
        let payload = Data("durable ciphertext".utf8)

        let committer = makeCrashCommitter(at: .afterNamespaceCommit)

        XCTAssertThrowsError(
            try committer.writeNew(
                payload,
                to: destination,
                stagingPrefix: ".hz-powerloss-"
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DurableCommitSimulatedCrash,
                .powerLoss(.afterNamespaceCommit)
            )
        }

        XCTAssertEqual(try Data(contentsOf: destination), payload)
        XCTAssertTrue(try names(in: root, prefix: ".hz-powerloss-").isEmpty)
    }

    func testMetadataCrashBeforeReplaceKeepsOldGenerationAndNoOwnershipClaim() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let masterKey = testMasterKey()
        let budget = try testBudget()
        var armed = false

        let crashingCommitter = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, _ in
                if armed, point == .afterStagingSync {
                    throw V2DurableCommitSimulatedCrash.powerLoss(point)
                }
            }
        )
        let metadata = V2AccessMetadataStore(
            fileManager: fileManager,
            durableCommitter: crashingCommitter
        )
        let initial = try metadata.createInitialEmpty(
            budget: budget,
            masterKey: masterKey,
            in: root
        )
        armed = true

        let objectName = String(repeating: "a", count: V2OpaqueObjectName.encodedLength)
        let transactionID = UUID(uuidString: "A1000000-0000-0000-0000-000000000101")!
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: metadata,
            objectStore: V2PoolObjectStore(fileManager: fileManager),
            nameGenerator: { objectName },
            transactionIDGenerator: { transactionID }
        )

        XCTAssertThrowsError(
            try coordinator.importData(
                Data("evidence".utf8),
                originalName: "evidence.txt",
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        )

        let reopened = try V2AccessMetadataStore(fileManager: fileManager).read(
            masterKey: masterKey,
            in: root
        )
        XCTAssertEqual(reopened, initial)
        XCTAssertTrue(reopened.pendingImports.isEmpty)
        XCTAssertTrue(reopened.entries.isEmpty)
        XCTAssertFalse(
            V2PoolObjectStore(fileManager: fileManager).containsObject(
                named: objectName,
                in: root
            )
        )
        XCTAssertEqual(
            try names(
                in: V2StorageLayout.poolURL(in: root),
                prefix: ".hanzala-v2-metadata-stage-"
            ).count,
            1
        )
    }

    func testMetadataCrashAfterReplaceIsRecoveredAsMissingPendingObject() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let masterKey = testMasterKey()
        let budget = try testBudget()
        var armed = false

        let crashingCommitter = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, _ in
                if armed, point == .afterNamespaceCommit {
                    throw V2DurableCommitSimulatedCrash.powerLoss(point)
                }
            }
        )
        let crashingMetadata = V2AccessMetadataStore(
            fileManager: fileManager,
            durableCommitter: crashingCommitter
        )
        _ = try crashingMetadata.createInitialEmpty(
            budget: budget,
            masterKey: masterKey,
            in: root
        )
        armed = true

        let objectName = String(repeating: "b", count: V2OpaqueObjectName.encodedLength)
        let transactionID = UUID(uuidString: "B1000000-0000-0000-0000-000000000102")!
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: crashingMetadata,
            objectStore: V2PoolObjectStore(fileManager: fileManager),
            nameGenerator: { objectName },
            transactionIDGenerator: { transactionID }
        )

        XCTAssertThrowsError(
            try coordinator.importData(
                Data("interrupted claim".utf8),
                originalName: "claim.txt",
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        )

        // Simulate process restart: discard every faulting store/coordinator and
        // reopen from disk with fresh normal instances.
        let freshMetadata = V2AccessMetadataStore(fileManager: fileManager)
        let afterCrash = try freshMetadata.read(masterKey: masterKey, in: root)
        XCTAssertEqual(afterCrash.pendingImports.map(\.transactionID), [transactionID])
        XCTAssertFalse(
            V2PoolObjectStore(fileManager: fileManager).containsObject(
                named: objectName,
                in: root
            )
        )

        let recovery = V2OwnershipTransactionCoordinator(
            metadataStore: freshMetadata,
            objectStore: V2PoolObjectStore(fileManager: fileManager)
        )
        let report = try recovery.recoverPendingImports(
            masterKey: masterKey,
            in: root
        )
        XCTAssertEqual(report.abortedMissingObjectTransactionIDs, [transactionID])
        XCTAssertTrue(report.finalizedTransactionIDs.isEmpty)

        let repaired = try freshMetadata.read(masterKey: masterKey, in: root)
        XCTAssertTrue(repaired.pendingImports.isEmpty)
        XCTAssertTrue(repaired.entries.isEmpty)
    }

    func testObjectCrashBeforeRenameAbortsAuthenticatedPendingClaimOnFreshRecovery() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let masterKey = testMasterKey()
        let budget = try testBudget()
        let metadata = V2AccessMetadataStore(fileManager: fileManager)
        _ = try metadata.createInitialEmpty(
            budget: budget,
            masterKey: masterKey,
            in: root
        )

        let objectName = String(repeating: "c", count: V2OpaqueObjectName.encodedLength)
        let transactionID = UUID(uuidString: "C1000000-0000-0000-0000-000000000103")!
        let crashingCommitter = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, destination in
                if destination.lastPathComponent == objectName,
                   point == .afterStagingSync {
                    throw V2DurableCommitSimulatedCrash.powerLoss(point)
                }
            }
        )
        let crashingObjects = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: crashingCommitter
        )
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: metadata,
            objectStore: crashingObjects,
            nameGenerator: { objectName },
            transactionIDGenerator: { transactionID }
        )

        XCTAssertThrowsError(
            try coordinator.importData(
                Data("protected source".utf8),
                originalName: "source.txt",
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        )

        let freshMetadata = V2AccessMetadataStore(fileManager: fileManager)
        let afterCrash = try freshMetadata.read(masterKey: masterKey, in: root)
        XCTAssertEqual(afterCrash.pendingImports.map(\.transactionID), [transactionID])
        XCTAssertFalse(
            V2PoolObjectStore(fileManager: fileManager).containsObject(
                named: objectName,
                in: root
            )
        )

        let recovery = V2OwnershipTransactionCoordinator(
            metadataStore: freshMetadata,
            objectStore: V2PoolObjectStore(fileManager: fileManager)
        )
        let report = try recovery.recoverPendingImports(masterKey: masterKey, in: root)
        XCTAssertEqual(report.abortedMissingObjectTransactionIDs, [transactionID])
        XCTAssertTrue(report.finalizedTransactionIDs.isEmpty)
        XCTAssertTrue(
            try freshMetadata.read(masterKey: masterKey, in: root).pendingImports.isEmpty
        )

        XCTAssertEqual(
            try names(
                in: V2StorageLayout.poolURL(in: root),
                prefix: ".hanzala-v2-stage-"
            ).count,
            1
        )
    }

    func testObjectCrashAfterRenameFinalizesAuthenticatedPendingClaimOnFreshRecovery() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let masterKey = testMasterKey()
        let budget = try testBudget()
        let metadata = V2AccessMetadataStore(fileManager: fileManager)
        _ = try metadata.createInitialEmpty(
            budget: budget,
            masterKey: masterKey,
            in: root
        )

        let objectName = String(repeating: "d", count: V2OpaqueObjectName.encodedLength)
        let transactionID = UUID(uuidString: "D1000000-0000-0000-0000-000000000104")!
        let crashingCommitter = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, destination in
                if destination.lastPathComponent == objectName,
                   point == .afterNamespaceCommit {
                    throw V2DurableCommitSimulatedCrash.powerLoss(point)
                }
            }
        )
        let crashingObjects = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: crashingCommitter
        )
        let coordinator = V2OwnershipTransactionCoordinator(
            metadataStore: metadata,
            objectStore: crashingObjects,
            nameGenerator: { objectName },
            transactionIDGenerator: { transactionID }
        )
        let content = Data("protected source survives rename".utf8)

        XCTAssertThrowsError(
            try coordinator.importData(
                content,
                originalName: "source.txt",
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        )

        let freshMetadata = V2AccessMetadataStore(fileManager: fileManager)
        let freshObjects = V2PoolObjectStore(fileManager: fileManager)
        let afterCrash = try freshMetadata.read(masterKey: masterKey, in: root)
        XCTAssertEqual(afterCrash.pendingImports.map(\.transactionID), [transactionID])
        XCTAssertTrue(freshObjects.containsObject(named: objectName, in: root))

        let recovery = V2OwnershipTransactionCoordinator(
            metadataStore: freshMetadata,
            objectStore: freshObjects
        )
        let report = try recovery.recoverPendingImports(masterKey: masterKey, in: root)
        XCTAssertEqual(report.finalizedTransactionIDs, [transactionID])
        XCTAssertTrue(report.abortedMissingObjectTransactionIDs.isEmpty)

        let repaired = try freshMetadata.read(masterKey: masterKey, in: root)
        XCTAssertTrue(repaired.pendingImports.isEmpty)
        let entry = try XCTUnwrap(repaired.entries.first(where: { $0.id == transactionID }))
        XCTAssertEqual(entry.opaqueObjectName, objectName)
        XCTAssertEqual(entry.logicalByteCount, UInt64(content.count))

        let object = try freshObjects.readObject(
            named: objectName,
            masterKey: masterKey,
            in: root
        )
        XCTAssertEqual(object.kind, .data)
        XCTAssertEqual(object.content, content)
        XCTAssertTrue(
            try names(
                in: V2StorageLayout.poolURL(in: root),
                prefix: ".hanzala-v2-stage-"
            ).isEmpty
        )
    }

    private func makeCrashCommitter(
        at crashPoint: V2DurableCommitCrashPoint
    ) -> V2DurableFileCommitter {
        V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, _ in
                if point == crashPoint {
                    throw V2DurableCommitSimulatedCrash.powerLoss(point)
                }
            }
        )
    }

    private func testMasterKey() -> Data {
        Data((0..<32).map { UInt8($0) })
    }

    private func testBudget() throws -> V2StorageBudget {
        try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-powerloss-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        return root
    }

    private func names(in directory: URL, prefix: String) throws -> [String] {
        try fileManager.contentsOfDirectory(atPath: directory.path)
            .filter { $0.hasPrefix(prefix) }
            .sorted()
    }
}
