import Foundation
import CryptoKit

public enum V2ChunkOwnershipTransactionError: Error, Equatable, Sendable {
    case chunkingNotRequired
    case tooManyChunks
    case invalidGeneratedObjectName
    case candidateObjectAlreadyExists
    case nameGenerationExhausted
    case transitionRetryExhausted
    case pendingChunkKindMismatch
    case pendingChunkLengthMismatch
    case pendingManifestKindMismatch
    case pendingManifestMismatch
    case chunkDigestMismatch
    case manifestPresentButChunkMissing
    case finalizedEntryMissing
    case sourceMetadataReadFailed
    case sourceIsSymbolicLink
    case sourceNotRegularFile
    case sourceSizeUnavailable
    case sourceOpenFailed
    case sourceReadFailed
    case sourceChangedDuringImport
}

public struct V2PendingChunkImportRecoveryReport: Equatable, Sendable {
    public let finalizedTransactionIDs: [UUID]
    public let abortedIncompleteTransactionIDs: [UUID]

    public init(
        finalizedTransactionIDs: [UUID] = [],
        abortedIncompleteTransactionIDs: [UUID] = []
    ) {
        self.finalizedTransactionIDs = finalizedTransactionIDs
        self.abortedIncompleteTransactionIDs = abortedIncompleteTransactionIDs
    }
}

/// Crash-conscious multi-object ownership protocol for large v2 files.
///
/// Ordering is deliberate:
/// 1. reserve the manifest name and every chunk name in authenticated metadata;
/// 2. immutably write each name-bound encrypted chunk;
/// 3. verify every chunk and the whole-file SHA-256 digest;
/// 4. write and authenticate the encrypted manifest;
/// 5. transition the authenticated claim to one live logical entry.
///
/// Recovery never scans the shared pool. It follows only names that were already
/// committed in the authenticated pending transaction. If the manifest is absent
/// and the chunk set is incomplete, authenticated chunks are rolled back and the
/// claim is aborted. If a manifest exists, missing or malformed chunks fail closed
/// because the transaction had reached the publish-preparation boundary.
///
/// In a fixed-capacity vault the claim also reserves one free cover slot per
/// object. Each chunk's cover is removed right after that chunk is written, and
/// the manifest's after the manifest is authenticated, so the vault never holds
/// more than one extra object at a time. Rollback writes a chunk's cover back
/// before deleting the chunk.
public final class V2ChunkOwnershipTransactionCoordinator {
    public static let maximumNameGenerationAttempts = 16
    public static let maximumTransitionRetries = 8

    /// Source files are never read into one giant plaintext value. The streaming
    /// path performs bounded sequential I/O no larger than the canonical chunk
    /// plaintext target on either its pre-hash or write pass.
    public static let maximumStreamingReadByteCount = V2ChunkManifest.chunkPaddedPlaintextByteCount

    private let metadataStore: V2AccessMetadataStore
    private let objectStore: V2PoolObjectStore
    private let manifestCodec: V2ChunkManifestCodec
    private let physicalCapacityGuard: V2PhysicalCapacityGuard
    private let nameGenerator: () throws -> String
    private let transactionIDGenerator: () -> UUID
    private let covers: V2FixedCapacityCovers

    /// Internal deterministic seam used only by core tests to mutate or replace a
    /// source pathname between the bounded pre-hash pass and encrypted write pass.
    /// The retained `V2SecureSourceFile` descriptor must prevent path replacement
    /// from redirecting pass two.
    var streamingPassBoundaryHook: (() -> Void)?

    public init(
        metadataStore: V2AccessMetadataStore = V2AccessMetadataStore(),
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        manifestCodec: V2ChunkManifestCodec = V2ChunkManifestCodec(),
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard(),
        nameGenerator: @escaping () throws -> String = { try V2OpaqueObjectName.generate() },
        transactionIDGenerator: @escaping () -> UUID = { UUID() }
    ) {
        self.metadataStore = metadataStore
        self.objectStore = objectStore
        self.manifestCodec = manifestCodec
        self.physicalCapacityGuard = physicalCapacityGuard
        self.nameGenerator = nameGenerator
        self.transactionIDGenerator = transactionIDGenerator
        self.covers = V2FixedCapacityCovers(objectStore: objectStore)
        self.streamingPassBoundaryHook = nil
    }

    /// Foundation import for an already-materialized large payload. This remains
    /// useful for tests and in-memory callers, while file-backed production work
    /// should use `importChunkedFile` to keep plaintext memory bounded.
    public func importChunkedData(
        _ content: Data,
        originalName: String,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessEntry {
        guard content.count > V2DataObjectPaddingPolicy.maximumLogicalContentByteCount else {
            throw V2ChunkOwnershipTransactionError.chunkingNotRequired
        }

        let chunkLengths = try Self.canonicalChunkLengths(for: content.count)
        let digest = V2ChunkedFileIntegrity.sha256(content)
        let pending = try claimPendingChunkImport(
            originalName: originalName,
            logicalByteCount: UInt64(content.count),
            chunkLengths: chunkLengths,
            digest: digest,
            masterKey: masterKey,
            in: root
        )
        let budget = try metadataStore.read(masterKey: masterKey, in: root).budget

        var offset = 0
        for index in pending.chunks.indices {
            let count = chunkLengths[index]
            let end = offset + count
            let bytes = Data(content[offset..<end])

            try writeChunk(
                bytes,
                index: index,
                of: pending,
                budget: budget,
                masterKey: masterKey,
                in: root
            )
            offset = end
        }

        return try publishWrittenChunkImport(
            pending,
            masterKey: masterKey,
            in: root
        )
    }

    /// Two-pass bounded file import for large source files.
    ///
    /// The source pathname is resolved exactly once into `V2SecureSourceFile`.
    /// Both the pre-hash pass and the encrypted write pass read the same retained
    /// no-follow descriptor. Pass two rewinds that descriptor rather than opening
    /// the pathname again, so a rename/replacement cannot redirect plaintext input.
    /// In-place mutation of the opened inode is detected from its captured snapshot
    /// before pass two and again after streaming completes.
    public func importChunkedFile(
        at sourceURL: URL,
        originalName: String,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessEntry {
        let source: V2SecureSourceFile
        do {
            source = try V2SecureSourceFile(url: sourceURL)
        } catch let error as V2SecureSourceFileError {
            throw Self.mapSecureSourceError(error)
        }
        return try importChunkedFile(
            source: source,
            originalName: originalName,
            masterKey: masterKey,
            in: root
        )
    }

    /// Internal session integration path. `V2VaultSessionStore` already opens a
    /// secure source descriptor before deciding small versus chunked routing, so
    /// it can hand that exact descriptor here instead of reopening the pathname.
    func importChunkedFile(
        source: V2SecureSourceFile,
        originalName: String,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessEntry {
        let inspected = try inspectStreamingSource(source)
        let pending = try claimPendingChunkImport(
            originalName: originalName,
            logicalByteCount: UInt64(inspected.byteCount),
            chunkLengths: inspected.chunkLengths,
            digest: inspected.digest,
            masterKey: masterKey,
            in: root
        )
        let budget = try metadataStore.read(masterKey: masterKey, in: root).budget

        streamingPassBoundaryHook?()

        do {
            try rewindStreamingSource(source)
            let writtenDigest = try writeStreamingChunks(
                from: source,
                expectedByteCount: inspected.byteCount,
                pending: pending,
                budget: budget,
                masterKey: masterKey,
                in: root
            )
            try validateStreamingSourceUnchanged(source)
            guard writtenDigest == inspected.digest else {
                throw V2ChunkOwnershipTransactionError.sourceChangedDuringImport
            }
        } catch let error as V2ChunkOwnershipTransactionError where error.isStreamingSourceFailure {
            // The manifest has not been created on this path. Roll back only
            // successfully authenticated objects whose names were already claimed
            // in private metadata. If a manifest unexpectedly exists, fail closed
            // and leave the pending claim for recovery/investigation.
            try rollbackStreamingSourceFailure(
                pending,
                masterKey: masterKey,
                in: root
            )
            throw error
        }

        return try publishWrittenChunkImport(
            pending,
            masterKey: masterKey,
            in: root
        )
    }

    /// Repairs only authenticated pending chunk transactions for this access path.
    /// No unknown pool name is inspected or deleted.
    public func recoverPendingChunkImports(
        masterKey: Data,
        in root: URL
    ) throws -> V2PendingChunkImportRecoveryReport {
        var finalized: [UUID] = []
        var aborted: [UUID] = []

        while true {
            let metadata = try metadataStore.read(masterKey: masterKey, in: root)
            guard let pending = metadata.pendingChunkImports.first else {
                return V2PendingChunkImportRecoveryReport(
                    finalizedTransactionIDs: finalized,
                    abortedIncompleteTransactionIDs: aborted
                )
            }

            let manifestObject = try optionalObject(
                named: pending.manifestObjectName,
                masterKey: masterKey,
                in: root
            )
            let chunkInspection = try inspectChunks(
                pending,
                masterKey: masterKey,
                in: root
            )

            if manifestObject != nil {
                try verifyManifestObject(
                    manifestObject!,
                    pending: pending,
                    masterKey: masterKey,
                    in: root
                )
                guard chunkInspection.allPresent else {
                    throw V2ChunkOwnershipTransactionError.manifestPresentButChunkMissing
                }

                try removeAllCovers(of: pending, masterKey: masterKey, in: root)
                _ = try finalizePendingChunkImport(
                    transactionID: pending.transactionID,
                    masterKey: masterKey,
                    in: root
                )
                finalized.append(pending.transactionID)
                continue
            }

            if chunkInspection.allPresent {
                try createManifestIfAbsent(pending, masterKey: masterKey, in: root)
                try verifyManifest(pending, masterKey: masterKey, in: root)
                try removeAllCovers(of: pending, masterKey: masterKey, in: root)
                _ = try finalizePendingChunkImport(
                    transactionID: pending.transactionID,
                    masterKey: masterKey,
                    in: root
                )
                finalized.append(pending.transactionID)
                continue
            }

            // No manifest was ever committed and the chunk set is incomplete.
            // Every present object was authenticated above under its exact claimed
            // name before it becomes eligible for rollback deletion. In a
            // fixed-capacity vault a written chunk's cover is put back before
            // the chunk is deleted. A cover is removed only after its object is
            // written, so absent objects still have theirs.
            for chunk in chunkInspection.presentChunks {
                if let index = pending.chunks.firstIndex(of: chunk),
                   let slot = pending.coverSlots?[index + 1] {
                    try covers.ensureCoverPresent(slot, masterKey: masterKey, in: root)
                }
                do {
                    try objectStore.deleteAuthenticatedObject(
                        named: chunk.opaqueObjectName,
                        masterKey: masterKey,
                        expectedKind: .data,
                        expectedLogicalByteCount: chunk.logicalByteCount,
                        in: root
                    )
                } catch V2PoolObjectStoreError.objectNotFound {
                    // Desired rollback state already reached.
                }
            }
            try abortPendingChunkImport(
                transactionID: pending.transactionID,
                masterKey: masterKey,
                in: root
            )
            aborted.append(pending.transactionID)
        }
    }

    private struct StreamingSourceDescriptor {
        let byteCount: Int
        let chunkLengths: [Int]
        let digest: Data
    }

    private struct ChunkInspection {
        let allPresent: Bool
        let presentChunks: [V2PendingChunkObject]
    }

    private func inspectStreamingSource(
        _ source: V2SecureSourceFile
    ) throws -> StreamingSourceDescriptor {
        let byteCount = source.byteCount
        guard byteCount > V2DataObjectPaddingPolicy.maximumLogicalContentByteCount else {
            throw V2ChunkOwnershipTransactionError.chunkingNotRequired
        }

        try validateStreamingSourceUnchanged(source)
        let chunkLengths = try Self.canonicalChunkLengths(for: byteCount)
        let digest = try hashStreamingSource(
            source,
            expectedByteCount: byteCount
        )
        try validateStreamingSourceUnchanged(source)
        return StreamingSourceDescriptor(
            byteCount: byteCount,
            chunkLengths: chunkLengths,
            digest: digest
        )
    }

    private func hashStreamingSource(
        _ source: V2SecureSourceFile,
        expectedByteCount: Int
    ) throws -> Data {
        var hasher = SHA256()
        var totalRead = 0
        while totalRead < expectedByteCount {
            let requested = min(
                Self.maximumStreamingReadByteCount,
                expectedByteCount - totalRead
            )
            let bytes = try readUpTo(
                requested,
                from: source
            )
            guard !bytes.isEmpty else {
                throw V2ChunkOwnershipTransactionError.sourceChangedDuringImport
            }
            hasher.update(data: bytes)
            totalRead += bytes.count
        }

        guard try sourceIsAtEOF(source) else {
            throw V2ChunkOwnershipTransactionError.sourceChangedDuringImport
        }
        return Data(hasher.finalize())
    }

    private func writeStreamingChunks(
        from source: V2SecureSourceFile,
        expectedByteCount: Int,
        pending: V2PendingChunkImport,
        budget: V2StorageBudget,
        masterKey: Data,
        in root: URL
    ) throws -> Data {
        var hasher = SHA256()
        var totalRead = 0
        for (index, chunk) in pending.chunks.enumerated() {
            guard chunk.logicalByteCount <= UInt64(Int.max) else {
                throw V2ChunkOwnershipTransactionError.sourceChangedDuringImport
            }
            let expectedChunkByteCount = Int(chunk.logicalByteCount)
            let bytes = try readExactly(
                expectedChunkByteCount,
                from: source
            )
            hasher.update(data: bytes)
            totalRead += bytes.count

            try writeChunk(
                bytes,
                index: index,
                of: pending,
                budget: budget,
                masterKey: masterKey,
                in: root
            )
        }

        guard totalRead == expectedByteCount,
              try sourceIsAtEOF(source) else {
            throw V2ChunkOwnershipTransactionError.sourceChangedDuringImport
        }
        return Data(hasher.finalize())
    }

    private func readExactly(
        _ byteCount: Int,
        from source: V2SecureSourceFile
    ) throws -> Data {
        var result = Data()
        result.reserveCapacity(byteCount)

        while result.count < byteCount {
            let remaining = byteCount - result.count
            let bytes = try readUpTo(remaining, from: source)
            guard !bytes.isEmpty else {
                throw V2ChunkOwnershipTransactionError.sourceChangedDuringImport
            }
            result.append(bytes)
        }
        return result
    }

    private func readUpTo(
        _ byteCount: Int,
        from source: V2SecureSourceFile
    ) throws -> Data {
        do {
            return try source.read(upToCount: byteCount)
        } catch let error as V2SecureSourceFileError {
            throw Self.mapSecureSourceError(error)
        }
    }

    private func sourceIsAtEOF(_ source: V2SecureSourceFile) throws -> Bool {
        let extra = try readUpTo(1, from: source)
        return extra.isEmpty
    }

    private func rewindStreamingSource(_ source: V2SecureSourceFile) throws {
        do {
            try source.rewind()
        } catch let error as V2SecureSourceFileError {
            throw Self.mapSecureSourceError(error)
        }
    }

    private func validateStreamingSourceUnchanged(_ source: V2SecureSourceFile) throws {
        do {
            try source.validateUnchanged()
        } catch let error as V2SecureSourceFileError {
            throw Self.mapSecureSourceError(error)
        }
    }

    private static func mapSecureSourceError(
        _ error: V2SecureSourceFileError
    ) -> V2ChunkOwnershipTransactionError {
        switch error {
        case .sourceOpenFailed:
            return .sourceOpenFailed
        case .sourceIsSymbolicLink:
            return .sourceIsSymbolicLink
        case .sourceNotRegularFile:
            return .sourceNotRegularFile
        case .sourceSizeUnavailable:
            return .sourceSizeUnavailable
        case .sourceReadFailed, .sourceSeekFailed:
            return .sourceReadFailed
        case .sourceChanged:
            return .sourceChangedDuringImport
        }
    }

    private func rollbackStreamingSourceFailure(
        _ pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws {
        // Our streaming path never creates a manifest before both passes agree.
        // If a regular object unexpectedly occupies the claimed manifest name,
        // preserve the authenticated claim rather than crossing the publish
        // boundary and potentially orphaning an externally raced object.
        if objectStore.containsObject(named: pending.manifestObjectName, in: root) {
            return
        }

        for (index, chunk) in pending.chunks.enumerated() {
            do {
                let object = try objectStore.readObject(
                    named: chunk.opaqueObjectName,
                    masterKey: masterKey,
                    in: root
                )
                guard object.kind == .data else {
                    throw V2ChunkOwnershipTransactionError.pendingChunkKindMismatch
                }
                guard UInt64(object.content.count) == chunk.logicalByteCount else {
                    throw V2ChunkOwnershipTransactionError.pendingChunkLengthMismatch
                }
                // Put the chunk's cover back before the chunk goes away.
                if let slot = pending.coverSlots?[index + 1] {
                    try covers.ensureCoverPresent(slot, masterKey: masterKey, in: root)
                }
                try objectStore.deleteAuthenticatedObject(
                    named: chunk.opaqueObjectName,
                    masterKey: masterKey,
                    expectedKind: .data,
                    expectedLogicalByteCount: chunk.logicalByteCount,
                    in: root
                )
            } catch V2PoolObjectStoreError.objectNotFound {
                continue
            }
        }

        try abortPendingChunkImport(
            transactionID: pending.transactionID,
            masterKey: masterKey,
            in: root
        )
    }

    private func claimPendingChunkImport(
        originalName: String,
        logicalByteCount: UInt64,
        chunkLengths: [Int],
        digest: Data,
        masterKey: Data,
        in root: URL
    ) throws -> V2PendingChunkImport {
        guard chunkLengths.count <= V2ChunkManifest.maximumChunkCount else {
            throw V2ChunkOwnershipTransactionError.tooManyChunks
        }

        for _ in 0..<Self.maximumNameGenerationAttempts {
            let manifestName = try validatedGeneratedName()
            var chunkNames: [String] = []
            chunkNames.reserveCapacity(chunkLengths.count)
            for _ in chunkLengths {
                chunkNames.append(try validatedGeneratedName())
            }

            let allNames = [manifestName] + chunkNames
            guard Set(allNames).count == allNames.count else {
                continue
            }

            let transactionID = transactionIDGenerator()
            var pending = V2PendingChunkImport(
                transactionID: transactionID,
                manifestObjectName: manifestName,
                originalName: originalName,
                logicalByteCount: logicalByteCount,
                chunks: zip(chunkNames, chunkLengths).map {
                    V2PendingChunkObject(
                        opaqueObjectName: $0.0,
                        logicalByteCount: UInt64($0.1)
                    )
                },
                sha256Digest: digest
            )
            try pending.manifest().validate()

            do {
                _ = try commitMetadataMutation(masterKey: masterKey, in: root) { current in
                    for name in allNames {
                        guard !current.authenticatedOwnedObjectNames.contains(name),
                              !self.objectStore.containsObject(named: name, in: root) else {
                            throw V2ChunkOwnershipTransactionError.candidateObjectAlreadyExists
                        }
                    }
                    if let state = current.fixedCapacity {
                        guard state.isFilled else {
                            throw V2AccessMetadataTransitionError.fixedCapacityNotFilled
                        }
                        let manifestTarget = try self.manifestPaddingTarget(for: pending)
                        let slots = try self.covers.chooseCoveredSlots(
                            minimumPlaintextByteCounts: [manifestTarget]
                                + Array(repeating: V2ChunkManifest.chunkPaddedPlaintextByteCount, count: pending.chunks.count),
                            state: state,
                            masterKey: masterKey,
                            in: root
                        )
                        pending = pending.withCoverSlots(slots)
                    } else {
                        pending = pending.withCoverSlots(nil)
                    }
                    return try current.beginningChunkImport(pending)
                }
                return pending
            } catch V2ChunkOwnershipTransactionError.candidateObjectAlreadyExists {
                continue
            } catch V2AccessMetadataTransitionError.objectNameAlreadyOwned {
                continue
            }
        }

        throw V2ChunkOwnershipTransactionError.nameGenerationExhausted
    }

    private func publishWrittenChunkImport(
        _ pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessEntry {
        _ = try inspectChunks(pending, masterKey: masterKey, in: root)
        try createManifestIfAbsent(pending, masterKey: masterKey, in: root)
        try verifyManifest(pending, masterKey: masterKey, in: root)
        if let slot = pending.coverSlots?.first {
            try covers.ensureCoverRemoved(slot, masterKey: masterKey, in: root)
        }
        _ = try finalizePendingChunkImport(
            transactionID: pending.transactionID,
            masterKey: masterKey,
            in: root
        )

        let persisted = try metadataStore.read(masterKey: masterKey, in: root)
        guard let entry = persisted.entries.first(where: { $0.id == pending.transactionID }) else {
            throw V2ChunkOwnershipTransactionError.finalizedEntryMissing
        }
        return entry
    }

    /// Authenticates every present chunk. When all are present it also authenticates
    /// the whole-file digest before manifest creation/finalization.
    private func inspectChunks(
        _ pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws -> ChunkInspection {
        var present: [V2PendingChunkObject] = []
        var allPresent = true
        var hasher = SHA256()

        for chunk in pending.chunks {
            let object: V2PoolObject
            do {
                object = try objectStore.readObject(
                    named: chunk.opaqueObjectName,
                    masterKey: masterKey,
                    in: root
                )
            } catch V2PoolObjectStoreError.objectNotFound {
                allPresent = false
                continue
            }

            guard object.kind == .data else {
                throw V2ChunkOwnershipTransactionError.pendingChunkKindMismatch
            }
            guard UInt64(object.content.count) == chunk.logicalByteCount else {
                throw V2ChunkOwnershipTransactionError.pendingChunkLengthMismatch
            }
            present.append(chunk)
            hasher.update(data: object.content)
        }

        if allPresent {
            let digest = Data(hasher.finalize())
            guard digest == pending.sha256Digest else {
                throw V2ChunkOwnershipTransactionError.chunkDigestMismatch
            }
        }

        return ChunkInspection(allPresent: allPresent, presentChunks: present)
    }

    private func createManifestIfAbsent(
        _ pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws {
        if let existing = try optionalObject(
            named: pending.manifestObjectName,
            masterKey: masterKey,
            in: root
        ) {
            try verifyManifestObject(
                existing,
                pending: pending,
                masterKey: masterKey,
                in: root
            )
            return
        }

        let encoded = try manifestCodec.encodeContent(pending.manifest())
        let paddingTarget = try pending.coverSlots?.first?.bucketPlaintextByteCount
            ?? V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
                forEncodedMetadataByteCount: encoded.count
            )
        let budget = try metadataStore.read(masterKey: masterKey, in: root).budget
        try validateDataObjectPhysicalWrite(
            paddedPlaintextByteCount: paddingTarget,
            budget: budget,
            in: root
        )

        do {
            _ = try objectStore.createObject(
                named: pending.manifestObjectName,
                kind: .manifest,
                content: encoded,
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: paddingTarget
            )
        } catch V2PoolObjectStoreError.objectAlreadyExists {
            // A racing writer may have appeared after the absence check. It must
            // authenticate as the exact expected manifest or recovery fails closed.
        }
    }

    private func verifyManifest(
        _ pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws {
        guard let object = try optionalObject(
            named: pending.manifestObjectName,
            masterKey: masterKey,
            in: root
        ) else {
            throw V2PoolObjectStoreError.objectNotFound
        }
        try verifyManifestObject(
            object,
            pending: pending,
            masterKey: masterKey,
            in: root
        )
    }

    private func verifyManifestObject(
        _ object: V2PoolObject,
        pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws {
        guard object.kind == .manifest else {
            throw V2ChunkOwnershipTransactionError.pendingManifestKindMismatch
        }
        let decoded = try manifestCodec.decodeContent(object.content)
        guard decoded == pending.manifest() else {
            throw V2ChunkOwnershipTransactionError.pendingManifestMismatch
        }
    }

    private func optionalObject(
        named name: String,
        masterKey: Data,
        in root: URL
    ) throws -> V2PoolObject? {
        do {
            return try objectStore.readObject(
                named: name,
                masterKey: masterKey,
                in: root
            )
        } catch V2PoolObjectStoreError.objectNotFound {
            return nil
        }
    }

    private func finalizePendingChunkImport(
        transactionID: UUID,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessMetadata {
        try commitMetadataMutation(masterKey: masterKey, in: root) { current in
            try current.finalizingChunkImport(transactionID: transactionID)
        }
    }

    private func abortPendingChunkImport(
        transactionID: UUID,
        masterKey: Data,
        in root: URL
    ) throws {
        _ = try commitMetadataMutation(masterKey: masterKey, in: root) { current in
            try current.abortingChunkImport(transactionID: transactionID)
        }
    }

    private func commitMetadataMutation(
        masterKey: Data,
        in root: URL,
        mutation: (V2AccessMetadata) throws -> V2AccessMetadata
    ) throws -> V2AccessMetadata {
        for _ in 0..<Self.maximumTransitionRetries {
            let current = try metadataStore.read(masterKey: masterKey, in: root)
            let next = try mutation(current)
            do {
                try metadataStore.commitTransition(
                    from: current,
                    to: next,
                    masterKey: masterKey,
                    in: root
                )
                return next
            } catch V2AccessMetadataStoreError.staleMetadata {
                continue
            }
        }
        throw V2ChunkOwnershipTransactionError.transitionRetryExhausted
    }

    /// Writes chunk `index` padded to its size (its slot's bucket in a
    /// fixed-capacity vault), then removes that slot's cover.
    private func writeChunk(
        _ bytes: Data,
        index: Int,
        of pending: V2PendingChunkImport,
        budget: V2StorageBudget,
        masterKey: Data,
        in root: URL
    ) throws {
        let slot = pending.coverSlots?[index + 1]
        let paddedPlaintextByteCount = slot?.bucketPlaintextByteCount
            ?? V2ChunkManifest.chunkPaddedPlaintextByteCount
        try validateDataObjectPhysicalWrite(
            paddedPlaintextByteCount: paddedPlaintextByteCount,
            budget: budget,
            in: root
        )
        _ = try objectStore.createObject(
            named: pending.chunks[index].opaqueObjectName,
            kind: .data,
            content: bytes,
            masterKey: masterKey,
            in: root,
            paddedPlaintextByteCount: paddedPlaintextByteCount
        )
        if let slot {
            try covers.ensureCoverRemoved(slot, masterKey: masterKey, in: root)
        }
    }

    private func removeAllCovers(
        of pending: V2PendingChunkImport,
        masterKey: Data,
        in root: URL
    ) throws {
        for slot in pending.coverSlots ?? [] {
            try covers.ensureCoverRemoved(slot, masterKey: masterKey, in: root)
        }
    }

    private func manifestPaddingTarget(for pending: V2PendingChunkImport) throws -> Int {
        let encoded = try manifestCodec.encodeContent(pending.manifest())
        return try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
            forEncodedMetadataByteCount: encoded.count
        )
    }

    private func validateDataObjectPhysicalWrite(
        paddedPlaintextByteCount: Int,
        budget: V2StorageBudget,
        in root: URL
    ) throws {
        let sealedByteCount = try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
            paddedPlaintextByteCount: paddedPlaintextByteCount
        )
        try physicalCapacityGuard.validateDataWrite(
            physicalWriteByteCount: sealedByteCount,
            budget: budget,
            at: root
        )
    }

    private func validatedGeneratedName() throws -> String {
        let name = try nameGenerator()
        guard V2OpaqueObjectName.isValid(name) else {
            throw V2ChunkOwnershipTransactionError.invalidGeneratedObjectName
        }
        return name
    }

    private static func canonicalChunkLengths(for byteCount: Int) throws -> [Int] {
        guard byteCount > V2DataObjectPaddingPolicy.maximumLogicalContentByteCount else {
            throw V2ChunkOwnershipTransactionError.chunkingNotRequired
        }

        let maximum = V2ChunkManifest.maximumLogicalChunkByteCount
        var remaining = byteCount
        var lengths: [Int] = []
        while remaining > 0 {
            let next = min(maximum, remaining)
            lengths.append(next)
            remaining -= next
            if lengths.count > V2ChunkManifest.maximumChunkCount {
                throw V2ChunkOwnershipTransactionError.tooManyChunks
            }
        }
        return lengths
    }
}

private extension V2ChunkOwnershipTransactionError {
    var isStreamingSourceFailure: Bool {
        switch self {
        case .sourceMetadataReadFailed,
             .sourceIsSymbolicLink,
             .sourceNotRegularFile,
             .sourceSizeUnavailable,
             .sourceOpenFailed,
             .sourceReadFailed,
             .sourceChangedDuringImport:
            return true
        default:
            return false
        }
    }
}
