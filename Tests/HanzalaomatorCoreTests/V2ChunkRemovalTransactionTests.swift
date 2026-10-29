import XCTest
@testable import HanzalaomatorCore

final class V2ChunkRemovalTransactionTests: XCTestCase {
    private let fileManager = FileManager.default

    func testChunkedRemovalDeletesManifestAndEveryChunkThenFinalizesMetadata() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let fixture = try makeChunkedFixture(root: root, keyByte: 0x91)
        let allNames = [fixture.entry.opaqueObjectName] + fixture.entry.auxiliaryObjectNames
        XCTAssertTrue(allNames.allSatisfy {
            fixture.objectStore.containsObject(named: $0, in: root)
        })

        let removalID = UUID(uuidString: "91000000-0000-0000-0000-000000000001")!
        let returned = try V2RemovalTransactionCoordinator(
            metadataStore: fixture.metadataStore,
            objectStore: fixture.objectStore,
            transactionIDGenerator: { removalID }
        ).removeEntry(
            id: fixture.entry.id,
            masterKey: fixture.key,
            in: root
        )

        XCTAssertEqual(returned, removalID)
        XCTAssertTrue(allNames.allSatisfy {
            !fixture.objectStore.containsObject(named: $0, in: root)
        })

        let metadata = try fixture.metadataStore.read(masterKey: fixture.key, in: root)
        XCTAssertTrue(metadata.entries.isEmpty)
        XCTAssertTrue(metadata.pendingRemovals.isEmpty)
        XCTAssertEqual(metadata.usage, V2LogicalUsageLedger())
        for name in allNames {
            XCTAssertFalse(metadata.authenticatedOwnedObjectNames.contains(name))
            XCTAssertFalse(metadata.authenticatedTombstonedObjectNames.contains(name))
        }
    }

    func testRecoveryResumesChunkedRemovalWhenOneChunkWasAlreadyDeleted() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let fixture = try makeChunkedFixture(root: root, keyByte: 0x92)
        let manifest = try readManifest(fixture: fixture, root: root)
        let removalID = UUID(uuidString: "92000000-0000-0000-0000-000000000001")!
        try commitChunkedRemovalClaim(
            fixture: fixture,
            removalID: removalID,
            root: root
        )

        let firstChunk = try XCTUnwrap(manifest.chunks.first)
        try fixture.objectStore.deleteAuthenticatedObject(
            named: firstChunk.opaqueObjectName,
            masterKey: fixture.key,
            expectedKind: .data,
            expectedLogicalByteCount: firstChunk.logicalByteCount,
            in: root
        )
        XCTAssertFalse(fixture.objectStore.containsObject(
            named: firstChunk.opaqueObjectName,
            in: root
        ))
        XCTAssertTrue(fixture.objectStore.containsObject(
            named: fixture.entry.opaqueObjectName,
            in: root
        ))

        let report = try V2RemovalTransactionCoordinator(
            metadataStore: fixture.metadataStore,
            objectStore: fixture.objectStore
        ).recoverPendingRemovals(masterKey: fixture.key, in: root)

        XCTAssertEqual(report.deletedTransactionIDs, [removalID])
        XCTAssertTrue(report.finalizedAlreadyMissingTransactionIDs.isEmpty)
        let allNames = [fixture.entry.opaqueObjectName] + fixture.entry.auxiliaryObjectNames
        XCTAssertTrue(allNames.allSatisfy {
            !fixture.objectStore.containsObject(named: $0, in: root)
        })
        let recovered = try fixture.metadataStore.read(masterKey: fixture.key, in: root)
        XCTAssertTrue(recovered.pendingRemovals.isEmpty)
        XCTAssertTrue(recovered.entries.isEmpty)
    }

    func testRecoveryFailsClosedWhenManifestIsMissingButChunkRemains() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let fixture = try makeChunkedFixture(root: root, keyByte: 0x93)
        let removalID = UUID(uuidString: "93000000-0000-0000-0000-000000000001")!
        try commitChunkedRemovalClaim(
            fixture: fixture,
            removalID: removalID,
            root: root
        )

        try fixture.objectStore.deleteAuthenticatedObject(
            named: fixture.entry.opaqueObjectName,
            masterKey: fixture.key,
            expectedKind: .manifest,
            in: root
        )
        XCTAssertFalse(fixture.objectStore.containsObject(
            named: fixture.entry.opaqueObjectName,
            in: root
        ))
        let survivingChunk = try XCTUnwrap(fixture.entry.auxiliaryObjectNames.first)
        XCTAssertTrue(fixture.objectStore.containsObject(named: survivingChunk, in: root))

        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: fixture.metadataStore,
                objectStore: fixture.objectStore
            ).recoverPendingRemovals(masterKey: fixture.key, in: root)
        ) { error in
            XCTAssertEqual(
                error as? V2RemovalTransactionError,
                .manifestMissingWithAuxiliaryObjects
            )
        }

        let after = try fixture.metadataStore.read(masterKey: fixture.key, in: root)
        XCTAssertTrue(after.entries.isEmpty)
        XCTAssertEqual(after.pendingRemovals.count, 1)
        XCTAssertEqual(after.pendingRemovals[0].transactionID, removalID)
        XCTAssertEqual(
            after.pendingRemovals[0].auxiliaryObjectNames,
            fixture.entry.auxiliaryObjectNames
        )
        XCTAssertTrue(after.authenticatedTombstonedObjectNames.contains(survivingChunk))
        XCTAssertTrue(fixture.objectStore.containsObject(named: survivingChunk, in: root))
    }

    func testTamperedChunkFailsPreflightBeforeLiveEntryBecomesTombstone() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let fixture = try makeChunkedFixture(root: root, keyByte: 0x94)
        let firstChunkName = try XCTUnwrap(fixture.entry.auxiliaryObjectNames.first)
        let chunkURL = V2StorageLayout.objectURL(named: firstChunkName, in: root)
        var sealed = try Data(contentsOf: chunkURL)
        sealed[sealed.index(before: sealed.endIndex)] ^= 0x01
        try sealed.write(to: chunkURL, options: [.atomic])

        XCTAssertThrowsError(
            try V2RemovalTransactionCoordinator(
                metadataStore: fixture.metadataStore,
                objectStore: fixture.objectStore
            ).removeEntry(
                id: fixture.entry.id,
                masterKey: fixture.key,
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }

        let metadata = try fixture.metadataStore.read(masterKey: fixture.key, in: root)
        XCTAssertEqual(metadata.entries, [fixture.entry])
        XCTAssertTrue(metadata.pendingRemovals.isEmpty)
        XCTAssertTrue(metadata.authenticatedOwnedObjectNames.contains(firstChunkName))
        XCTAssertFalse(metadata.authenticatedTombstonedObjectNames.contains(firstChunkName))
        XCTAssertTrue(fileManager.fileExists(atPath: chunkURL.path))
    }

    func testLegacyPendingRemovalDecodesWithNoAuxiliaryNames() throws {
        struct LegacyPendingRemoval: Codable {
            let transactionID: UUID
            let entryID: UUID
            let opaqueObjectName: String
            let logicalByteCount: UInt64
            let createdAt: Date
        }

        let legacy = LegacyPendingRemoval(
            transactionID: UUID(),
            entryID: UUID(),
            opaqueObjectName: opaque("a"),
            logicalByteCount: 123,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let decoded = try JSONDecoder().decode(
            V2PendingRemoval.self,
            from: JSONEncoder().encode(legacy)
        )

        XCTAssertEqual(decoded.transactionID, legacy.transactionID)
        XCTAssertEqual(decoded.entryID, legacy.entryID)
        XCTAssertEqual(decoded.opaqueObjectName, legacy.opaqueObjectName)
        XCTAssertEqual(decoded.logicalByteCount, legacy.logicalByteCount)
        XCTAssertTrue(decoded.auxiliaryObjectNames.isEmpty)
    }

    private typealias Fixture = (
        key: Data,
        metadataStore: V2AccessMetadataStore,
        objectStore: V2PoolObjectStore,
        entry: V2AccessEntry
    )

    private func makeChunkedFixture(root: URL, keyByte: UInt8) throws -> Fixture {
        let key = Data(repeating: keyByte, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let objectStore = V2PoolObjectStore(fileManager: fileManager)
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )
        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).importChunkedData(
            largeContent(seed: keyByte),
            originalName: "large-evidence.mov",
            masterKey: key,
            in: root
        )
        return (key, metadataStore, objectStore, entry)
    }

    private func commitChunkedRemovalClaim(
        fixture: Fixture,
        removalID: UUID,
        root: URL
    ) throws {
        let current = try fixture.metadataStore.read(masterKey: fixture.key, in: root)
        let claimed = try current.beginningChunkedRemoval(
            entryID: fixture.entry.id,
            transactionID: removalID,
            auxiliaryObjectNames: fixture.entry.auxiliaryObjectNames,
            createdAt: Date(timeIntervalSince1970: 1_700_100_000)
        )
        try fixture.metadataStore.commitTransition(
            from: current,
            to: claimed,
            masterKey: fixture.key,
            in: root
        )
    }

    private func readManifest(fixture: Fixture, root: URL) throws -> V2ChunkManifest {
        let object = try fixture.objectStore.readObject(
            named: fixture.entry.opaqueObjectName,
            masterKey: fixture.key,
            in: root
        )
        XCTAssertEqual(object.kind, .manifest)
        return try V2ChunkManifestCodec().decodeContent(object.content)
    }

    private func largeContent(seed: UInt8) -> Data {
        let count = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        var data = Data(repeating: seed, count: count)
        let boundary = V2ChunkManifest.maximumLogicalChunkByteCount
        if boundary + 2 < data.count {
            data[boundary - 1] = seed &+ 1
            data[boundary] = seed &+ 2
            data[boundary + 1] = seed &+ 3
            data[boundary + 2] = seed &+ 4
        }
        return data
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-chunk-removal-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
