import XCTest
@testable import HanzalaomatorCore

/// A fixed-capacity pool must look identical on disk whatever it holds: the
/// same number of objects, the same size for each, the same total.
final class V2FixedCapacityPoolTests: XCTestCase {
    private let fileManager = FileManager.default
    private let key = Data(repeating: 0x42, count: 32)
    private let otherKey = Data(repeating: 0x43, count: 32)

    func testPlanDependsOnlyOnCapacityAndStaysWithinIt() throws {
        for gigabytes: UInt64 in [1, 2, 5, 10] {
            let capacity = gigabytes * 1024 * 1024 * 1024
            let plan = try V2FixedCapacityPlan(capacityBytes: capacity)
            XCTAssertEqual(plan, try V2FixedCapacityPlan(capacityBytes: capacity))
            XCTAssertLessThanOrEqual(plan.slotPlaintextBytes, capacity)
            // Less than one 4 MiB chunk is left unused.
            XCTAssertLessThan(capacity - plan.slotPlaintextBytes, UInt64(4 * 1024 * 1024))
            XCTAssertEqual(plan.slots.map(\.plaintextByteCount), plan.slots.map(\.plaintextByteCount).sorted())
            XCTAssertTrue(plan.slots.allSatisfy { V2DataObjectPaddingPolicy.plaintextBuckets.contains($0.plaintextByteCount) })
        }
        let oneGB = try V2FixedCapacityPlan(capacityBytes: 1024 * 1024 * 1024)
        XCTAssertEqual(oneGB.slots.first?.plaintextByteCount, 4 * 1024)
        XCTAssertGreaterThan(oneGB.slots.first?.count ?? 0, 1_000)
    }

    func testPlanRefusesCapacitiesOutOfRange() {
        XCTAssertThrowsError(try V2FixedCapacityPlan(capacityBytes: V2FixedCapacityPlan.minimumCapacityBytes - 1)) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .capacityOutOfRange)
        }
        XCTAssertThrowsError(try V2FixedCapacityPlan(capacityBytes: V2FixedCapacityPlan.maximumCapacityBytes + 1)) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .capacityOutOfRange)
        }
        XCTAssertThrowsError(try V2FixedCapacityPlan(capacityBytes: 1, counts: [5_000: 1])) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .invalidProfile)
        }
        XCTAssertThrowsError(try V2FixedCapacityPlan(capacityBytes: 1, counts: [4_096: 0])) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .invalidProfile)
        }
    }

    func testFillCreatesCoversThatLookLikeRealObjects() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        var reported: [(Int, Int)] = []
        let ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root) { reported.append(($0, $1)) }

        XCTAssertEqual(ledger.freeSlotCount, 6)
        XCTAssertEqual(reported.last?.0, 6)
        XCTAssertEqual(reported.last?.1, 6)
        XCTAssertEqual(try sizesOnDisk(root), expectedShape())

        // A cover and a real object of the same bucket have the same size.
        let store = V2PoolObjectStore()
        let elsewhere = try makeRoot()
        defer { try? fileManager.removeItem(at: elsewhere) }
        let real = try store.createObject(
            kind: .data,
            content: Data("note".utf8),
            masterKey: key,
            in: elsewhere,
            paddedPlaintextByteCount: 4 * 1024
        )
        XCTAssertEqual(Int(real.sealedByteCount), sealedSize(4 * 1024))

        // Covers authenticate only under the vault's key.
        let cover = try pool.coverNamer(masterKey: key)(4 * 1024, 0)
        XCTAssertEqual(try store.readObject(named: cover, masterKey: key, in: root).kind, .padding)
        XCTAssertThrowsError(try store.readObject(named: cover, masterKey: otherKey, in: root))
    }

    func testStoreAndReleaseNeverChangeTheShapeOnDisk() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        let store = V2PoolObjectStore()
        var ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root)
        let shape = try sizesOnDisk(root)

        let small = Data("a short source note".utf8)
        let medium = Data(repeating: 0x5a, count: 10 * 1024)
        let first = try pool.store(kind: .data, content: small, masterKey: key, in: root, ledger: &ledger)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        let second = try pool.store(kind: .data, content: medium, masterKey: key, in: root, ledger: &ledger)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(first.plaintextByteCount, 4 * 1024)
        XCTAssertEqual(second.plaintextByteCount, 16 * 1024)
        XCTAssertEqual(ledger.freeSlotCount, 4)

        XCTAssertEqual(try store.readObject(named: first.opaqueName, masterKey: key, in: root).content, small)
        XCTAssertEqual(try store.readObject(named: second.opaqueName, masterKey: key, in: root).content, medium)

        try pool.release(first, masterKey: key, in: root, ledger: &ledger)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(ledger.freeSlotCount, 5)
        XCTAssertFalse(store.containsObject(named: first.opaqueName, in: root))

        try pool.release(second, masterKey: key, in: root, ledger: &ledger)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(ledger.freeSlotCount, 6)
        XCTAssertNoStagingFiles(root)
    }

    func testUsedUpBucketFallsBackToALargerSlotInsteadOfGrowing() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        var ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root)
        let shape = try sizesOnDisk(root)

        var buckets: [Int] = []
        for index in 0..<6 {
            let reference = try pool.store(kind: .data, content: Data("file \(index)".utf8), masterKey: key, in: root, ledger: &ledger)
            buckets.append(reference.plaintextByteCount)
            XCTAssertEqual(try sizesOnDisk(root), shape)
        }
        XCTAssertEqual(buckets, [4_096, 4_096, 4_096, 16_384, 16_384, 4 * 1024 * 1024])

        XCTAssertThrowsError(
            try pool.store(kind: .data, content: Data("one more".utf8), masterKey: key, in: root, ledger: &ledger)
        ) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .vaultFull)
        }
        XCTAssertEqual(try sizesOnDisk(root), shape)
    }

    func testContentTooBigForAnyFreeSlotIsRefusedWithoutChanges() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        let plan = try V2FixedCapacityPlan(capacityBytes: 1, counts: [4_096: 2])
        var ledger = try pool.fill(plan: plan, masterKey: key, in: root)
        let shape = try sizesOnDisk(root)
        let before = ledger

        XCTAssertThrowsError(
            try pool.store(kind: .data, content: Data(count: 8 * 1024), masterKey: key, in: root, ledger: &ledger)
        ) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .vaultFull)
        }
        XCTAssertEqual(ledger, before)
        XCTAssertEqual(try sizesOnDisk(root), shape)
    }

    func testOnlyDataAndManifestObjectsTakeSlots() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        var ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root)
        for kind in [V2PoolObjectKind.metadata, .padding, .recovery] {
            XCTAssertThrowsError(try pool.store(kind: kind, content: Data(), masterKey: key, in: root, ledger: &ledger)) { error in
                XCTAssertEqual(error as? V2FixedCapacityPoolError, .unsupportedKind)
            }
        }
        _ = try pool.store(kind: .manifest, content: Data("manifest".utf8), masterKey: key, in: root, ledger: &ledger)
    }

    func testWrongKeyCannotStoreOrReleaseAndNothingChanges() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        var ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root)
        let shape = try sizesOnDisk(root)
        let before = ledger

        // The cover does not authenticate under another key, so the swap is
        // rolled back.
        XCTAssertThrowsError(try pool.store(kind: .data, content: Data("x".utf8), masterKey: otherKey, in: root, ledger: &ledger))
        XCTAssertEqual(ledger, before)
        XCTAssertEqual(try sizesOnDisk(root), shape)

        let stored = try pool.store(kind: .data, content: Data("x".utf8), masterKey: key, in: root, ledger: &ledger)
        let afterStore = ledger
        XCTAssertThrowsError(try pool.release(stored, masterKey: otherKey, in: root, ledger: &ledger))
        XCTAssertEqual(ledger, afterStore)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertTrue(V2PoolObjectStore().containsObject(named: stored.opaqueName, in: root))
    }

    func testReleaseRefusesAForgedReference() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        var ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root)
        let stored = try pool.store(kind: .data, content: Data("x".utf8), masterKey: key, in: root, ledger: &ledger)
        let shape = try sizesOnDisk(root)

        let wrongBucket = V2FixedCapacitySlotReference(
            opaqueName: stored.opaqueName,
            kindRawValue: stored.kindRawValue,
            plaintextByteCount: 64 * 1024,
            logicalByteCount: stored.logicalByteCount
        )
        XCTAssertThrowsError(try pool.release(wrongBucket, masterKey: key, in: root, ledger: &ledger)) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .invalidSlotReference)
        }
        let coveredSlot = try XCTUnwrap(ledger.buckets[0].randomSlot(covered: true))
        let coverAsData = V2FixedCapacitySlotReference(
            opaqueName: try pool.coverNamer(masterKey: key)(4 * 1024, coveredSlot),
            kindRawValue: V2PoolObjectKind.data.rawValue,
            plaintextByteCount: 4 * 1024,
            logicalByteCount: 0
        )
        XCTAssertThrowsError(try pool.release(coverAsData, masterKey: key, in: root, ledger: &ledger))
        XCTAssertEqual(try sizesOnDisk(root), shape)
    }

    func testLedgerRoundTripsThroughCodable() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let ledger = try V2FixedCapacityPool().fill(plan: try smallPlan(), masterKey: key, in: root)
        let decoded = try JSONDecoder().decode(V2CoverLedger.self, from: try JSONEncoder().encode(ledger))
        XCTAssertEqual(decoded, ledger)
        XCTAssertEqual(decoded.freePlaintextBytes, try smallPlan().slotPlaintextBytes)
    }

    func testLedgerForTheLargestCapacityFitsTheFixedMetadataSize() throws {
        let plan = try V2FixedCapacityPlan(capacityBytes: V2FixedCapacityPlan.maximumCapacityBytes)
        XCTAssertLessThan(plan.slotCount, 70_000)
        let encoded = try JSONEncoder().encode(V2CoverLedger(fullFor: plan))
        XCTAssertLessThan(encoded.count, V2FixedCapacityPlan.metadataPaddedPlaintextByteCount / 8)
    }

    func testInterruptedFillResumesAndRestoresTheShape() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        _ = try pool.fill(plan: try smallPlan(), masterKey: key, in: root)
        let shape = try sizesOnDisk(root)

        // Simulate a fill that stopped before writing two covers.
        let namer = try pool.coverNamer(masterKey: key)
        for name in [namer(4 * 1024, 1), namer(4 * 1024 * 1024, 0)] {
            try fileManager.removeItem(at: V2StorageLayout.objectURL(named: name, in: root))
        }
        XCTAssertNotEqual(try sizesOnDisk(root), shape)

        var written = 0
        let ledger = try pool.fill(plan: try smallPlan(), masterKey: key, in: root) { done, _ in written = done }
        XCTAssertEqual(written, 6)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(ledger, V2CoverLedger(fullFor: try smallPlan()))
    }

    /// A crash after release wrote its cover but before the ledger was saved
    /// leaves a genuine cover in a slot the ledger calls empty. A retry must
    /// reuse it instead of failing on the existing name.
    func testReleaseRetryReusesACoverLeftByAnInterruptedRelease() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        let plan = try V2FixedCapacityPlan(capacityBytes: 1, counts: [4_096: 2])
        var ledger = try pool.fill(plan: plan, masterKey: key, in: root)
        let shape = try sizesOnDisk(root)
        let stored = try pool.store(kind: .data, content: Data("x".utf8), masterKey: key, in: root, ledger: &ledger)
        let emptySlot = try XCTUnwrap(ledger.buckets[0].randomSlot(covered: false))

        // The interrupted release: its cover exists, the real object and the
        // ledger were not updated.
        _ = try V2PoolObjectStore().createObject(
            named: try pool.coverNamer(masterKey: key)(4_096, emptySlot),
            kind: .padding,
            content: Data(),
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )
        XCTAssertEqual(try sizesOnDisk(root).count, shape.count + 1)

        try pool.release(stored, masterKey: key, in: root, ledger: &ledger)
        XCTAssertEqual(try sizesOnDisk(root), shape)
        XCTAssertEqual(ledger, V2CoverLedger(fullFor: plan))
    }

    /// A crash after store removed a cover but before the ledger was saved
    /// leaves a slot marked covered with no cover. Store skips it.
    func testStoreSkipsASlotWhoseCoverIsAlreadyGone() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        let plan = try V2FixedCapacityPlan(capacityBytes: 1, counts: [4_096: 2])
        var ledger = try pool.fill(plan: plan, masterKey: key, in: root)
        try fileManager.removeItem(
            at: V2StorageLayout.objectURL(named: try pool.coverNamer(masterKey: key)(4_096, 0), in: root)
        )
        let shapeAfterCrash = try sizesOnDisk(root)

        let stored = try pool.store(kind: .data, content: Data("x".utf8), masterKey: key, in: root, ledger: &ledger)
        XCTAssertEqual(try sizesOnDisk(root), shapeAfterCrash)
        // Whichever slot was tried first, the missing cover is never used:
        // the next store finds nothing left.
        XCTAssertEqual(try V2PoolObjectStore().readObject(named: stored.opaqueName, masterKey: key, in: root).content, Data("x".utf8))
        XCTAssertThrowsError(try pool.store(kind: .data, content: Data("y".utf8), masterKey: key, in: root, ledger: &ledger)) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .vaultFull)
        }
    }

    func testFillRefusesAWrongSizedFileAtACoverName() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let pool = V2FixedCapacityPool()
        try fileManager.createDirectory(at: V2StorageLayout.poolURL(in: root), withIntermediateDirectories: true)
        let name = try pool.coverNamer(masterKey: key)(4_096, 0)
        try Data("not a cover".utf8).write(to: V2StorageLayout.objectURL(named: name, in: root))
        XCTAssertThrowsError(try pool.fill(plan: try smallPlan(), masterKey: key, in: root)) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .unexpectedObject)
        }
    }

    func testCoverNamesAreValidOpaqueNamesAndDependOnTheKey() throws {
        let pool = V2FixedCapacityPool()
        let mine = try pool.coverNamer(masterKey: key)
        let theirs = try pool.coverNamer(masterKey: otherKey)
        XCTAssertTrue(V2OpaqueObjectName.isValid(mine(4_096, 0)))
        XCTAssertEqual(mine(4_096, 0), mine(4_096, 0))
        XCTAssertNotEqual(mine(4_096, 0), mine(4_096, 1))
        XCTAssertNotEqual(mine(4_096, 0), mine(16_384, 0))
        XCTAssertNotEqual(mine(4_096, 0), theirs(4_096, 0))
        XCTAssertNotEqual(mine(4_096, 0), try V2StorageNamespaceLocator().indexObjectName(masterKey: key))
        XCTAssertThrowsError(try pool.coverNamer(masterKey: Data(count: 5))) { error in
            XCTAssertEqual(error as? V2FixedCapacityPoolError, .invalidMasterKeyLength)
        }
    }

    // MARK: - Helpers

    /// 3 x 4 KiB, 2 x 16 KiB, 1 x 4 MiB.
    private func smallPlan() throws -> V2FixedCapacityPlan {
        try V2FixedCapacityPlan(capacityBytes: 1, counts: [4_096: 3, 16_384: 2, 4 * 1024 * 1024: 1])
    }

    private func expectedShape() -> [Int] {
        ([4_096, 4_096, 4_096, 16_384, 16_384, 4 * 1024 * 1024]).map(sealedSize).sorted()
    }

    private func sealedSize(_ plaintext: Int) -> Int {
        V2PoolObjectCodec.maximumEnvelopeByteCount - V2PoolObjectCodec.maximumPlaintextByteCount + plaintext
    }

    /// What someone holding the device sees: the sorted sizes of every file.
    private func sizesOnDisk(_ root: URL) throws -> [Int] {
        let pool = V2StorageLayout.poolURL(in: root)
        return try fileManager.contentsOfDirectory(at: pool, includingPropertiesForKeys: [.fileSizeKey])
            .map { try XCTUnwrap($0.resourceValues(forKeys: [.fileSizeKey]).fileSize) }
            .sorted()
    }

    private func XCTAssertNoStagingFiles(_ root: URL, file: StaticString = #filePath, line: UInt = #line) {
        let names = (try? fileManager.contentsOfDirectory(atPath: V2StorageLayout.poolURL(in: root).path)) ?? []
        XCTAssertFalse(names.contains { $0.hasPrefix(".") }, file: file, line: line)
        XCTAssertTrue(names.allSatisfy(V2OpaqueObjectName.isValid), file: file, line: line)
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("hanzala-fixed-capacity-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }
}
