import XCTest
@testable import HanzalaomatorCore

/// The fixed-capacity pool wired into real sessions: imports, removals and
/// crash recovery must never change what someone holding the device sees,
/// which is the list of file sizes in the vault folder.
final class V2FixedCapacityWiringTests: XCTestCase {
    private let fileManager = FileManager.default
    private let password = "fixed-capacity-password"
    /// The smallest capacity: 251 slots, about 62 MiB on disk.
    private let capacity = V2FixedCapacityPlan.minimumCapacityBytes

    func testShapeStaysFixedThroughImportsAndRemovals() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let shape = try sizesOnDisk(root)
        let status = try XCTUnwrap(try stores.sessions.fixedCapacityStatus(in: session))
        XCTAssertTrue(status.isFilled)
        XCTAssertEqual(status.capacityBytes, capacity)
        XCTAssertEqual(status.freePlaintextBytes, status.slotPlaintextBytes)

        let note = Data("a source's phone number".utf8)
        let small = try stores.sessions.importData(note, originalName: "note.txt", into: session)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(try stores.sessions.readEntry(id: small.id, in: session).data, note)

        // Larger than one object, so it is stored as a manifest and 4 MiB chunks.
        let large = Data((0..<(17 * 1024 * 1024)).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        let source = root.deletingLastPathComponent()
            .appendingPathComponent("fixed-source-\(UUID().uuidString)")
        try large.write(to: source)
        defer { try? fileManager.removeItem(at: source) }
        let chunked = try stores.sessions.importFile(at: source, originalName: "video.mov", into: session)
        XCTAssertFalse(chunked.auxiliaryObjectNames.isEmpty)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(
            try stores.sessions.readEntryRange(id: chunked.id, offset: 5_000_000, length: 1000, in: session),
            large.subdata(in: 5_000_000..<5_001_000)
        )
        let used = try XCTUnwrap(try stores.sessions.fixedCapacityStatus(in: session))
        XCTAssertLessThan(used.freePlaintextBytes, status.freePlaintextBytes)

        try stores.sessions.removeEntry(id: small.id, from: session)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        try stores.sessions.removeEntry(id: chunked.id, from: session)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(try stores.sessions.listEntries(in: session), [])
        XCTAssertEqual(try stores.sessions.fixedCapacityStatus(in: session), status)
    }

    func testTooLargeForAnyFreeSlotIsVaultFullAndChangesNothing() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let shape = try sizesOnDisk(root)

        // At this capacity there are no 16 MiB slots.
        let big = Data(count: 15 * 1024 * 1024)
        XCTAssertThrowsError(try stores.sessions.importData(big, originalName: "big.bin", into: session)) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .vaultFull)
        }
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(try stores.sessions.listEntries(in: session), [])
        XCTAssertEqual(try stores.metadata.read(masterKey: session.masterKey, in: root).pendingImports, [])
    }

    func testImportsWaitForTheFillAndPrepareResumesIt() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: password, budget: try budget())
        let session = try stores.sessions.openSession(at: root, password: password).session

        // An interrupted creation: fixed capacity turned on, a few covers written.
        let current = try stores.metadata.read(masterKey: session.masterKey, in: root)
        try stores.metadata.commitTransition(
            from: current,
            to: try current.beginningFixedCapacity(capacityBytes: capacity),
            masterKey: session.masterKey,
            in: root
        )
        let covers = V2FixedCapacityCovers(objectStore: stores.objects)
        try covers.ensureCoverPresent(V2CoverSlot(bucketPlaintextByteCount: 4096, index: 0), masterKey: session.masterKey, in: root)

        XCTAssertThrowsError(try stores.sessions.importData(Data("x".utf8), originalName: "x.txt", into: session)) { error in
            XCTAssertEqual(error as? V2AccessMetadataTransitionError, .fixedCapacityNotFilled)
        }
        XCTAssertFalse(try XCTUnwrap(try stores.sessions.fixedCapacityStatus(in: session)).isFilled)

        // A different size is refused; the same size resumes.
        XCTAssertThrowsError(try stores.sessions.prepareFixedCapacity(capacityBytes: capacity * 2, in: session)) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .fixedCapacityUnavailable)
        }
        try stores.sessions.prepareFixedCapacity(capacityBytes: capacity, in: session)
        XCTAssertTrue(try XCTUnwrap(try stores.sessions.fixedCapacityStatus(in: session)).isFilled)
        XCTAssertNoThrow(try stores.sessions.importData(Data("x".utf8), originalName: "x.txt", into: session))
    }

    func testVaultWithFilesCannotBecomeFixedCapacity() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: password, budget: try budget())
        let session = try stores.sessions.openSession(at: root, password: password).session
        _ = try stores.sessions.importData(Data("x".utf8), originalName: "x.txt", into: session)

        XCTAssertThrowsError(try stores.sessions.prepareFixedCapacity(capacityBytes: capacity, in: session)) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .fixedCapacityUnavailable)
        }
        XCTAssertNil(try stores.sessions.fixedCapacityStatus(in: session))
    }

    /// Crash after the new object was written but before its slot's cover was
    /// removed: one extra object on disk. Opening the vault finishes the swap.
    func testRecoveryFinishesAnImportInterruptedBeforeTheCoverWentAway() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let shape = try sizesOnDisk(root)
        let key = session.masterKey
        let covers = V2FixedCapacityCovers(objectStore: stores.objects)

        let current = try stores.metadata.read(masterKey: key, in: root)
        let slot = try covers.chooseCoveredSlots(
            minimumPlaintextByteCounts: [4096],
            state: try XCTUnwrap(current.fixedCapacity),
            masterKey: key,
            in: root
        )[0]
        let content = Data("written just before the battery died".utf8)
        let pending = V2PendingImport(
            opaqueObjectName: try V2OpaqueObjectName.generate(),
            originalName: "late.txt",
            logicalByteCount: UInt64(content.count),
            coverSlot: slot
        )
        try stores.metadata.commitTransition(from: current, to: try current.beginningImport(pending), masterKey: key, in: root)
        _ = try stores.objects.createObject(
            named: pending.opaqueObjectName,
            kind: .data,
            content: content,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: slot.bucketPlaintextByteCount
        )
        XCTAssertEqual(try sizesOnDisk(root).count, shape.count + 1)

        let report = try stores.sessions.recover(session: session)
        XCTAssertEqual(report.imports.finalizedTransactionIDs, [pending.transactionID])
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(try stores.sessions.readEntry(id: pending.transactionID, in: session).data, content)
    }

    /// Crash before the new object was written: its cover is still there and
    /// recovery gives the slot back.
    func testRecoveryAbortsAnImportWhoseObjectWasNeverWritten() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let shape = try sizesOnDisk(root)
        let key = session.masterKey
        let before = try XCTUnwrap(try stores.sessions.fixedCapacityStatus(in: session))
        let covers = V2FixedCapacityCovers(objectStore: stores.objects)

        let current = try stores.metadata.read(masterKey: key, in: root)
        let slot = try covers.chooseCoveredSlots(
            minimumPlaintextByteCounts: [4096],
            state: try XCTUnwrap(current.fixedCapacity),
            masterKey: key,
            in: root
        )[0]
        let pending = V2PendingImport(
            opaqueObjectName: try V2OpaqueObjectName.generate(),
            originalName: "never.txt",
            logicalByteCount: 5,
            coverSlot: slot
        )
        try stores.metadata.commitTransition(from: current, to: try current.beginningImport(pending), masterKey: key, in: root)

        let report = try stores.sessions.recover(session: session)
        XCTAssertEqual(report.imports.abortedMissingObjectTransactionIDs, [pending.transactionID])
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(try stores.sessions.fixedCapacityStatus(in: session), before)
    }

    /// Crash after the replacement cover was written but before the real
    /// object was deleted. Recovery deletes the object and frees the slot.
    func testRecoveryFinishesARemovalInterruptedAfterTheCoverWasWritten() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let key = session.masterKey
        let before = try XCTUnwrap(try stores.sessions.fixedCapacityStatus(in: session))
        let entry = try stores.sessions.importData(Data("delete me".utf8), originalName: "old.txt", into: session)
        let shape = try sizesOnDisk(root)
        let covers = V2FixedCapacityCovers(objectStore: stores.objects)

        let current = try stores.metadata.read(masterKey: key, in: root)
        let slots = try covers.chooseEmptySlots(
            forObjectsNamed: [entry.opaqueObjectName],
            state: try XCTUnwrap(current.fixedCapacity),
            reserved: [],
            masterKey: key,
            in: root
        )
        let transactionID = UUID()
        try stores.metadata.commitSpaceReleasingRemovalTransition(
            from: current,
            to: try current.beginningRemoval(entryID: entry.id, transactionID: transactionID, coverSlots: slots),
            masterKey: key,
            in: root
        )
        try covers.ensureCoverPresent(slots[0], masterKey: key, in: root)
        XCTAssertEqual(try sizesOnDisk(root).count, shape.count + 1)

        let report = try stores.sessions.recover(session: session)
        XCTAssertEqual(report.removals.deletedTransactionIDs, [transactionID])
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(try stores.sessions.listEntries(in: session), [])
        XCTAssertEqual(try stores.sessions.fixedCapacityStatus(in: session), before)
    }

    func testMetadataRejectsSlotsThatBreakTheCount() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let current = try stores.metadata.read(masterKey: session.masterKey, in: root)
        let state = try XCTUnwrap(current.fixedCapacity)

        // An import with no slot, or with a slot that is not free, is refused.
        let noSlot = V2PendingImport(opaqueObjectName: try V2OpaqueObjectName.generate(), originalName: "a.txt", logicalByteCount: 1)
        XCTAssertThrowsError(try current.beginningImport(noSlot)) { error in
            XCTAssertEqual(error as? V2AccessMetadataTransitionError, .coverSlotMismatch)
        }
        let slot = V2CoverSlot(bucketPlaintextByteCount: 4096, index: 0)
        let taken = try state.ledger.setting(false, for: [slot])
        let tampered = V2AccessMetadata(
            accessID: current.accessID,
            generation: current.generation,
            budget: current.budget,
            fixedCapacity: state.with(ledger: taken)
        )
        XCTAssertThrowsError(try tampered.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .coverCountMismatch)
        }
    }

    func testFullDiskRefusesARemovalBeforeItStarts() throws {
        let free = AvailableBytes(UInt64.max / 4)
        let (root, stores, session) = try makeFixedVault(
            physicalCapacityGuard: V2PhysicalCapacityGuard { _ in free.value }
        )
        defer { try? fileManager.removeItem(at: root) }
        let entry = try stores.sessions.importData(Data("keep me".utf8), originalName: "keep.txt", into: session)
        let shape = try sizesOnDisk(root)

        free.value = 1024
        XCTAssertThrowsError(try stores.sessions.removeEntry(id: entry.id, from: session)) { error in
            guard case .insufficientPhysicalCapacity? = error as? V2PhysicalCapacityGuardError else {
                return XCTFail("unexpected error \(error)")
            }
        }
        XCTAssertEqual(try stores.sessions.listEntries(in: session), [entry])
        XCTAssertEqual(try stores.metadata.read(masterKey: session.masterKey, in: root).pendingRemovals, [])
        XCTAssertEqual(try sizesOnDisk(root), shape)

        free.value = UInt64.max / 4
        XCTAssertNoThrow(try stores.sessions.removeEntry(id: entry.id, from: session))
    }

    func testCapacityCannotChangeOnceSet() throws {
        let (root, stores, session) = try makeFixedVault()
        defer { try? fileManager.removeItem(at: root) }
        let current = try stores.metadata.read(masterKey: session.masterKey, in: root)
        let bigger = capacity * 2
        let changed = V2AccessMetadata(
            accessID: current.accessID,
            generation: current.generation + 1,
            budget: current.budget,
            fixedCapacity: V2FixedCapacityState(
                capacityBytes: bigger,
                isFilled: true,
                ledger: V2CoverLedger(fullFor: try V2FixedCapacityPlan(capacityBytes: bigger))
            )
        )
        XCTAssertThrowsError(
            try stores.metadata.commitTransition(from: current, to: changed, masterKey: session.masterKey, in: root)
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .fixedCapacityMutationNotAllowed)
        }
    }

    /// Ordinary vaults keep their exact earlier metadata format.
    func testOrdinaryMetadataHasNoFixedCapacityFields() throws {
        let metadata = try V2AccessMetadata(budget: budget()).beginningImport(
            V2PendingImport(opaqueObjectName: try V2OpaqueObjectName.generate(), originalName: "a.txt", logicalByteCount: 1)
        )
        let encoded = String(decoding: try JSONEncoder().encode(metadata), as: UTF8.self)
        XCTAssertFalse(encoded.contains("fixedCapacity"))
        XCTAssertFalse(encoded.contains("coverSlot"))
    }

    // MARK: - Helpers

    private typealias Stores = (
        bootstrap: V2VaultBootstrapStore,
        metadata: V2AccessMetadataStore,
        objects: V2PoolObjectStore,
        sessions: V2VaultSessionStore
    )

    private final class AvailableBytes: @unchecked Sendable {
        var value: UInt64
        init(_ value: UInt64) { self.value = value }
    }

    private func makeFixedVault(
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard()
    ) throws -> (URL, Stores, V2VaultSession) {
        let root = try makeRoot()
        let stores = makeStores(physicalCapacityGuard: physicalCapacityGuard)
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: password, budget: try budget())
        let session = try stores.sessions.openSession(at: root, password: password).session
        var calls = 0
        try stores.sessions.prepareFixedCapacity(capacityBytes: capacity, in: session) { done, total in
            calls += 1
            XCTAssertLessThanOrEqual(done, total)
        }
        XCTAssertEqual(calls, try V2FixedCapacityPlan(capacityBytes: capacity).slotCount)
        return (root, stores, session)
    }

    private func budget() throws -> V2StorageBudget {
        try V2StorageBudget(totalBytes: 1024 * 1024 * 1024, reserveBytes: 1024 * 1024)
    }

    private func makeStores(
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard()
    ) -> Stores {
        let keyEngine = PasswordKeyEngine()
        let envelopeEngine = DualAccessEnvelopeEngine(
            keyEngine: keyEngine,
            makeParameters: {
                try keyEngine.makeParameters(operationsLimit: 2, memoryLimit: 32 * 1024 * 1024)
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
            physicalCapacityGuard: physicalCapacityGuard
        )
        return (bootstrap, metadata, objects, sessions)
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-fixed-wiring-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try fileManager.removeItem(at: url)
        return url
    }

    private func sizesOnDisk(_ root: URL) throws -> [Int] {
        let pool = V2StorageLayout.poolURL(in: root)
        return try fileManager.contentsOfDirectory(at: pool, includingPropertiesForKeys: [.fileSizeKey])
            .map { try XCTUnwrap($0.resourceValues(forKeys: [.fileSizeKey]).fileSize) }
            .sorted()
    }
}
