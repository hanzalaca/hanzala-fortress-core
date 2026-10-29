import XCTest
import CryptoKit
@testable import HanzalaomatorCore

final class V2ChunkOwnershipTransactionTests: XCTestCase {
    private let fileManager = FileManager.default

    func testChunkedImportClaimsAllNamesThenPublishesOneLiveEntry() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x81, count: 32)
        let budget = try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        let metadataStore = V2AccessMetadataStore()
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let content = largeContent(seed: 0x31)
        let names = deterministicNames()
        var generatedNames = names
        let transactionID = UUID(uuidString: "81000000-0000-0000-0000-000000000001")!
        let objectStore = V2PoolObjectStore()
        let coordinator = V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            nameGenerator: { generatedNames.removeFirst() },
            transactionIDGenerator: { transactionID }
        )

        let entry = try coordinator.importChunkedData(
            content,
            originalName: "evidence.mov",
            masterKey: key,
            in: root
        )

        XCTAssertEqual(entry.id, transactionID)
        XCTAssertEqual(entry.opaqueObjectName, names[0])
        XCTAssertEqual(entry.auxiliaryObjectNames, Array(names.dropFirst()))
        XCTAssertEqual(entry.logicalByteCount, UInt64(content.count))

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(metadata.generation, 2)
        XCTAssertTrue(metadata.pendingChunkImports.isEmpty)
        XCTAssertEqual(metadata.entries.count, 1)
        XCTAssertEqual(metadata.usage.logicalBytes, UInt64(content.count))
        XCTAssertEqual(metadata.usage.objectCount, 1)
        XCTAssertEqual(
            metadata.authenticatedOwnedObjectNames,
            Set(names)
        )

        let manifestObject = try objectStore.readObject(
            named: names[0],
            masterKey: key,
            in: root
        )
        XCTAssertEqual(manifestObject.kind, .manifest)
        let manifest = try V2ChunkManifestCodec().decodeContent(manifestObject.content)
        XCTAssertEqual(manifest.fileID, transactionID)
        XCTAssertEqual(manifest.logicalByteCount, UInt64(content.count))
        XCTAssertEqual(manifest.sha256Digest, V2ChunkedFileIntegrity.sha256(content))
        XCTAssertEqual(manifest.chunks.map(\.opaqueObjectName), Array(names.dropFirst()))
    }

    func testRecoveryRollsBackAuthenticatedChunksWhenManifestWasNeverCreated() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x82, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let budget = try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let pending = try makePending(
            transactionID: UUID(uuidString: "82000000-0000-0000-0000-000000000001")!,
            names: deterministicNames(),
            digest: Data(repeating: 0x55, count: SHA256.Digest.byteCount)
        )
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningChunkImport(pending)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let objectStore = V2PoolObjectStore()
        let first = pending.chunks[0]
        _ = try objectStore.createObject(
            named: first.opaqueObjectName,
            kind: .data,
            content: Data(repeating: 0x44, count: Int(first.logicalByteCount)),
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: V2ChunkManifest.chunkPaddedPlaintextByteCount
        )

        let report = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).recoverPendingChunkImports(masterKey: key, in: root)

        XCTAssertEqual(report.finalizedTransactionIDs, [])
        XCTAssertEqual(report.abortedIncompleteTransactionIDs, [pending.transactionID])
        XCTAssertFalse(objectStore.containsObject(named: first.opaqueObjectName, in: root))

        let recovered = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(recovered.generation, 2)
        XCTAssertTrue(recovered.pendingChunkImports.isEmpty)
        XCTAssertTrue(recovered.entries.isEmpty)
        XCTAssertEqual(recovered.usage, V2LogicalUsageLedger())
    }

    func testRecoveryCreatesManifestAndFinalizesWhenAllClaimedChunksExist() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x83, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let budget = try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let content = largeContent(seed: 0x52)
        let names = deterministicNames()
        let pending = try makePending(
            transactionID: UUID(uuidString: "83000000-0000-0000-0000-000000000001")!,
            names: names,
            digest: V2ChunkedFileIntegrity.sha256(content)
        )
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningChunkImport(pending)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let objectStore = V2PoolObjectStore()
        var offset = 0
        for chunk in pending.chunks {
            let count = Int(chunk.logicalByteCount)
            let end = offset + count
            _ = try objectStore.createObject(
                named: chunk.opaqueObjectName,
                kind: .data,
                content: Data(content[offset..<end]),
                masterKey: key,
                in: root,
                paddedPlaintextByteCount: V2ChunkManifest.chunkPaddedPlaintextByteCount
            )
            offset = end
        }
        XCTAssertFalse(objectStore.containsObject(named: pending.manifestObjectName, in: root))

        let report = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).recoverPendingChunkImports(masterKey: key, in: root)

        XCTAssertEqual(report.finalizedTransactionIDs, [pending.transactionID])
        XCTAssertEqual(report.abortedIncompleteTransactionIDs, [])
        XCTAssertTrue(objectStore.containsObject(named: pending.manifestObjectName, in: root))

        let recovered = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(recovered.pendingChunkImports.isEmpty)
        XCTAssertEqual(recovered.entries.count, 1)
        XCTAssertEqual(recovered.entries[0].opaqueObjectName, pending.manifestObjectName)
        XCTAssertEqual(
            recovered.entries[0].auxiliaryObjectNames,
            pending.chunks.map(\.opaqueObjectName)
        )
    }

    func testManifestWithMissingChunkFailsClosedAndPreservesClaim() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x84, count: 32)
        let metadataStore = V2AccessMetadataStore()
        let budget = try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let pending = try makePending(
            transactionID: UUID(uuidString: "84000000-0000-0000-0000-000000000001")!,
            names: deterministicNames(),
            digest: Data(repeating: 0x77, count: SHA256.Digest.byteCount)
        )
        let current = try metadataStore.read(masterKey: key, in: root)
        let claimed = try current.beginningChunkImport(pending)
        try metadataStore.commitTransition(from: current, to: claimed, masterKey: key, in: root)

        let manifestCodec = V2ChunkManifestCodec()
        let encoded = try manifestCodec.encodeContent(pending.manifest())
        let paddingTarget = try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
            forEncodedMetadataByteCount: encoded.count
        )
        let objectStore = V2PoolObjectStore()
        _ = try objectStore.createObject(
            named: pending.manifestObjectName,
            kind: .manifest,
            content: encoded,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: paddingTarget
        )

        XCTAssertThrowsError(
            try V2ChunkOwnershipTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: objectStore,
                manifestCodec: manifestCodec
            ).recoverPendingChunkImports(masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(
                error as? V2ChunkOwnershipTransactionError,
                .manifestPresentButChunkMissing
            )
        }

        let after = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(after.generation, 1)
        XCTAssertEqual(after.pendingChunkImports.count, 1)
        XCTAssertEqual(after.pendingChunkImports[0].transactionID, pending.transactionID)
        XCTAssertTrue(objectStore.containsObject(named: pending.manifestObjectName, in: root))
    }

    func testLegacyEntryAndMetadataDecodeWithoutChunkFields() throws {
        struct LegacyEntry: Codable {
            let id: UUID
            let opaqueObjectName: String
            let originalName: String
            let logicalByteCount: UInt64
            let createdAt: Date
        }
        struct LegacyMetadata: Codable {
            let formatVersion: UInt32
            let accessID: UUID
            let generation: UInt64
            let entries: [LegacyEntry]
            let pendingImports: [V2PendingImport]
            let pendingRemovals: [V2PendingRemoval]
            let tombstonedObjectNames: [String]
            let budget: V2StorageBudget
            let usage: V2LogicalUsageLedger
        }

        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let entry = LegacyEntry(
            id: UUID(),
            opaqueObjectName: opaque("a"),
            originalName: "legacy.txt",
            logicalByteCount: 10,
            createdAt: Date(timeIntervalSince1970: 100)
        )
        let legacy = LegacyMetadata(
            formatVersion: V2AccessMetadata.formatVersion,
            accessID: UUID(),
            generation: 0,
            entries: [entry],
            pendingImports: [],
            pendingRemovals: [],
            tombstonedObjectNames: [],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 10, objectCount: 1)
        )

        let decoded = try JSONDecoder().decode(
            V2AccessMetadata.self,
            from: JSONEncoder().encode(legacy)
        )
        XCTAssertTrue(decoded.pendingChunkImports.isEmpty)
        XCTAssertEqual(decoded.entries[0].auxiliaryObjectNames, [])
        XCTAssertNoThrow(try decoded.validate())
    }

    func testSingleObjectRemovalRejectsChunkedLiveEntry() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let entry = V2AccessEntry(
            opaqueObjectName: opaque("a"),
            auxiliaryObjectNames: [opaque("b")],
            originalName: "large.bin",
            logicalByteCount: 10
        )
        let metadata = V2AccessMetadata(
            entries: [entry],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 10, objectCount: 1)
        )
        XCTAssertNoThrow(try metadata.validate())

        XCTAssertThrowsError(
            try metadata.beginningRemoval(entryID: entry.id, transactionID: UUID())
        ) { error in
            XCTAssertEqual(
                error as? V2AccessMetadataTransitionError,
                .chunkedRemovalUnsupported
            )
        }
    }

    private func makePending(
        transactionID: UUID,
        names: [String],
        digest: Data
    ) throws -> V2PendingChunkImport {
        let total = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        var remaining = total
        var lengths: [Int] = []
        while remaining > 0 {
            let next = min(V2ChunkManifest.maximumLogicalChunkByteCount, remaining)
            lengths.append(next)
            remaining -= next
        }
        XCTAssertEqual(names.count, lengths.count + 1)

        let pending = V2PendingChunkImport(
            transactionID: transactionID,
            manifestObjectName: names[0],
            originalName: "large-evidence.bin",
            logicalByteCount: UInt64(total),
            chunks: zip(names.dropFirst(), lengths).map {
                V2PendingChunkObject(
                    opaqueObjectName: $0.0,
                    logicalByteCount: UInt64($0.1)
                )
            },
            sha256Digest: digest,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        try pending.manifest().validate()
        return pending
    }

    private func largeContent(seed: UInt8) -> Data {
        let count = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        return Data((0..<count).map { seed &+ UInt8(truncatingIfNeeded: $0) })
    }

    private func deterministicNames() -> [String] {
        ["a", "b", "c", "d", "e", "f"].map { opaque(Character($0)) }
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-chunk-ownership-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
