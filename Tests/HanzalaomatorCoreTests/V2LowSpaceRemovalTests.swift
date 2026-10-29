import XCTest
@testable import HanzalaomatorCore

final class V2LowSpaceRemovalTests: XCTestCase {
    private let fileManager = FileManager.default

    func testOrdinaryMetadataWriteIsBlockedWhileAuthenticatedRemovalCanReleaseSpace() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        var availableBytes = UInt64.max
        let guardrail = V2PhysicalCapacityGuard { _ in availableBytes }
        let metadataStore = V2AccessMetadataStore(
            physicalCapacityGuard: guardrail
        )
        let objectStore = V2PoolObjectStore()
        let key = Data(repeating: 0x81, count: 32)
        let budget = try V2StorageBudget(
            totalBytes: 128 * 1024 * 1024,
            reserveBytes: 64 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let liveName = opaque("a")
        let liveID = UUID(uuidString: "81000000-0000-0000-0000-000000000001")!
        let liveEntry = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            physicalCapacityGuard: guardrail,
            nameGenerator: { liveName },
            transactionIDGenerator: { liveID }
        ).importData(
            Data("release this encrypted object".utf8),
            originalName: "release.txt",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        // Deliberately create a valid same-key pool object that is not referenced
        // by this access path's authenticated metadata. Removal must never infer
        // that it is garbage merely because free space is low.
        let unknownName = opaque("b")
        _ = try objectStore.createObject(
            named: unknownName,
            kind: .data,
            content: Data("unknown shared-pool object".utf8),
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )
        let unknownBefore = try Data(
            contentsOf: V2StorageLayout.objectURL(named: unknownName, in: root)
        )

        // Simulate external/APFS pressure: enough room remains for one bounded
        // metadata ciphertext, but nowhere near the encrypted 64 MiB reserve.
        availableBytes = UInt64(V2PoolObjectCodec.maximumEnvelopeByteCount)

        let current = try metadataStore.read(masterKey: key, in: root)
        let blockedImport = try current.beginningImport(
            V2PendingImport(
                opaqueObjectName: opaque("c"),
                originalName: "blocked.txt",
                logicalByteCount: 1
            )
        )
        XCTAssertThrowsError(
            try metadataStore.commitTransition(
                from: current,
                to: blockedImport,
                masterKey: key,
                in: root
            )
        ) { error in
            guard case .insufficientPhysicalCapacity = error as? V2PhysicalCapacityGuardError else {
                return XCTFail("Expected ordinary reserve-preserving rejection, got \(error)")
            }
        }

        let removalID = UUID(uuidString: "81000000-0000-0000-0000-000000000002")!
        XCTAssertEqual(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore,
                transactionIDGenerator: { removalID }
            ).removeEntry(
                id: liveEntry.id,
                masterKey: key,
                in: root
            ),
            removalID
        )

        XCTAssertFalse(objectStore.containsObject(named: liveName, in: root))
        XCTAssertTrue(objectStore.containsObject(named: unknownName, in: root))
        XCTAssertEqual(
            try Data(contentsOf: V2StorageLayout.objectURL(named: unknownName, in: root)),
            unknownBefore
        )

        let after = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(after.entries.isEmpty)
        XCTAssertTrue(after.pendingRemovals.isEmpty)
        XCTAssertEqual(after.usage, V2LogicalUsageLedger())
        XCTAssertFalse(after.authenticatedOwnedObjectNames.contains(liveName))
        XCTAssertFalse(after.authenticatedOwnedObjectNames.contains(unknownName))
    }

    func testRemovalStillFailsClosedWhenMetadataCiphertextItselfCannotFit() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        var availableBytes = UInt64.max
        let guardrail = V2PhysicalCapacityGuard { _ in availableBytes }
        let metadataStore = V2AccessMetadataStore(
            physicalCapacityGuard: guardrail
        )
        let objectStore = V2PoolObjectStore()
        let key = Data(repeating: 0x82, count: 32)
        let budget = try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 16 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let liveName = opaque("d")
        let liveEntry = try V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            physicalCapacityGuard: guardrail,
            nameGenerator: { liveName }
        ).importData(
            Data("must remain".utf8),
            originalName: "remain.txt",
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        availableBytes = 0
        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore
            ).removeEntry(
                id: liveEntry.id,
                masterKey: key,
                in: root
            )
        ) { error in
            guard case .insufficientPhysicalCapacity = error as? V2PhysicalCapacityGuardError else {
                return XCTFail("Expected exact metadata-allocation rejection, got \(error)")
            }
        }

        XCTAssertTrue(objectStore.containsObject(named: liveName, in: root))
        let after = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(after.entries.map(\.id), [liveEntry.id])
        XCTAssertTrue(after.pendingRemovals.isEmpty)
    }

    func testLowSpaceExceptionRejectsImportTransitionEvenWithCapacityAvailable() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let guardrail = V2PhysicalCapacityGuard { _ in UInt64.max }
        let metadataStore = V2AccessMetadataStore(
            physicalCapacityGuard: guardrail
        )
        let key = Data(repeating: 0x83, count: 32)
        let budget = try V2StorageBudget(totalBytes: 1_000_000, reserveBytes: 100_000)
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let current = try metadataStore.read(masterKey: key, in: root)
        let importTransition = try current.beginningImport(
            V2PendingImport(
                opaqueObjectName: opaque("e"),
                originalName: "not-removal.txt",
                logicalByteCount: 1
            )
        )

        XCTAssertThrowsError(
            try metadataStore.commitSpaceReleasingRemovalTransition(
                from: current,
                to: importTransition,
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2AccessMetadataStoreError,
                .invalidSpaceReleasingTransition
            )
        }

        XCTAssertEqual(
            try metadataStore.read(masterKey: key, in: root),
            current
        )
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-low-space-removal-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }
}
