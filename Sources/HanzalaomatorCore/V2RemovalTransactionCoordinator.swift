import Foundation

public enum V2RemovalTransactionError: Error, Equatable, Sendable {
    case transitionRetryExhausted
    case pendingRemovalMissing
    case pendingManifestKindMismatch
    case pendingManifestMismatch
    case manifestMissingWithAuxiliaryObjects
}

public struct V2PendingRemovalRecoveryReport: Equatable, Sendable {
    public let deletedTransactionIDs: [UUID]
    public let finalizedAlreadyMissingTransactionIDs: [UUID]

    public init(
        deletedTransactionIDs: [UUID] = [],
        finalizedAlreadyMissingTransactionIDs: [UUID] = []
    ) {
        self.deletedTransactionIDs = deletedTransactionIDs
        self.finalizedAlreadyMissingTransactionIDs = finalizedAlreadyMissingTransactionIDs
    }
}

/// Crash-conscious authenticated deletion protocol for v2 live entries.
///
/// Tombstone finalization now additionally requires durable namespace deletion:
/// an object unlink must synchronize the pool directory, and an already-missing
/// exact authenticated name is re-confirmed by synchronizing that same directory
/// before encrypted pending-removal metadata may be finalized.
/// Unknown shared-pool objects are never scanned or treated as garbage.
///
/// In a fixed-capacity vault the claim also reserves one empty slot of the
/// same bucket for each object. Each object's cover is written before that
/// object is deleted, so the vault's shape never shrinks, and the slots are
/// marked free only when the removal finalizes.
public final class V2RemovalTransactionCoordinator {
    public static let maximumTransitionRetries = 8

    private let metadataStore: V2AccessMetadataStore
    private let objectStore: V2PoolObjectStore
    private let manifestCodec: V2ChunkManifestCodec
    private let chunkReader: V2ChunkedFileReader
    private let transactionIDGenerator: () -> UUID
    private let covers: V2FixedCapacityCovers
    private let physicalCapacityGuard: V2PhysicalCapacityGuard

    public init(
        metadataStore: V2AccessMetadataStore = V2AccessMetadataStore(),
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        manifestCodec: V2ChunkManifestCodec = V2ChunkManifestCodec(),
        chunkReader: V2ChunkedFileReader? = nil,
        transactionIDGenerator: @escaping () -> UUID = { UUID() },
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard()
    ) {
        self.physicalCapacityGuard = physicalCapacityGuard
        self.metadataStore = metadataStore
        self.objectStore = objectStore
        self.manifestCodec = manifestCodec
        self.chunkReader = chunkReader ?? V2ChunkedFileReader(objectStore: objectStore)
        self.transactionIDGenerator = transactionIDGenerator
        self.covers = V2FixedCapacityCovers(objectStore: objectStore)
    }

    @discardableResult
    public func removeEntry(
        id entryID: UUID,
        masterKey: Data,
        in root: URL
    ) throws -> UUID {
        let transactionID = transactionIDGenerator()
        let claimed = try claimRemoval(
            entryID: entryID,
            transactionID: transactionID,
            masterKey: masterKey,
            in: root
        )
        guard let pending = claimed.pendingRemovals.first(where: {
            $0.transactionID == transactionID
        }) else {
            throw V2RemovalTransactionError.pendingRemovalMissing
        }

        _ = try physicallyRemovePending(pending, masterKey: masterKey, in: root)
        _ = try finalizePendingRemoval(
            transactionID: transactionID,
            masterKey: masterKey,
            in: root
        )
        return transactionID
    }

    public func recoverPendingRemovals(
        masterKey: Data,
        in root: URL
    ) throws -> V2PendingRemovalRecoveryReport {
        var deleted: [UUID] = []
        var alreadyMissing: [UUID] = []

        while true {
            let metadata = try metadataStore.read(masterKey: masterKey, in: root)
            guard let pending = metadata.pendingRemovals.first else {
                return V2PendingRemovalRecoveryReport(
                    deletedTransactionIDs: deleted,
                    finalizedAlreadyMissingTransactionIDs: alreadyMissing
                )
            }

            let removedSomething = try physicallyRemovePending(
                pending,
                masterKey: masterKey,
                in: root
            )
            if removedSomething {
                deleted.append(pending.transactionID)
            } else {
                alreadyMissing.append(pending.transactionID)
            }

            _ = try finalizePendingRemoval(
                transactionID: pending.transactionID,
                masterKey: masterKey,
                in: root
            )
        }
    }

    private func claimRemoval(
        entryID: UUID,
        transactionID: UUID,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessMetadata {
        for _ in 0..<Self.maximumTransitionRetries {
            let current = try metadataStore.read(masterKey: masterKey, in: root)
            guard let entry = current.entries.first(where: { $0.id == entryID }) else {
                throw V2AccessMetadataTransitionError.entryNotFound
            }

            var coverSlots: [V2CoverSlot]?
            if let state = current.fixedCapacity {
                let reserved = Set(
                    current.pendingImports.compactMap(\.coverSlot)
                        + current.pendingChunkImports.flatMap { $0.coverSlots ?? [] }
                        + current.pendingRemovals.flatMap { $0.coverSlots ?? [] }
                )
                coverSlots = try covers.chooseEmptySlots(
                    forObjectsNamed: [entry.opaqueObjectName] + entry.auxiliaryObjectNames,
                    state: state,
                    reserved: reserved,
                    masterKey: masterKey,
                    in: root
                )
                // Covers are written one at a time, each before its object is
                // deleted. Refuse before claiming when the disk cannot hold the
                // largest one, so a full disk never leaves a removal pending.
                let largestCover = coverSlots?.map(\.bucketPlaintextByteCount).max() ?? 0
                try physicalCapacityGuard.validateSpaceReleasingMetadataWrite(
                    physicalWriteByteCount: V2FixedCapacityPool.sealedByteCount(plaintext: largestCover)
                        + V2PhysicalCapacityGuard.controlPlaneHeadroomBytes,
                    at: root
                )
            }

            let next: V2AccessMetadata
            if entry.auxiliaryObjectNames.isEmpty {
                next = try current.beginningRemoval(
                    entryID: entryID,
                    transactionID: transactionID,
                    coverSlots: coverSlots
                )
            } else {
                let manifest = try authenticatedManifest(
                    for: entry,
                    masterKey: masterKey,
                    in: root
                )
                try chunkReader.verifyWholeFile(
                    entry: entry,
                    masterKey: masterKey,
                    in: root
                )
                next = try current.beginningChunkedRemoval(
                    entryID: entryID,
                    transactionID: transactionID,
                    auxiliaryObjectNames: manifest.chunks.map(\.opaqueObjectName),
                    coverSlots: coverSlots
                )
            }

            do {
                try metadataStore.commitSpaceReleasingRemovalTransition(
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
        throw V2RemovalTransactionError.transitionRetryExhausted
    }

    private func physicallyRemovePending(
        _ pending: V2PendingRemoval,
        masterKey: Data,
        in root: URL
    ) throws -> Bool {
        if pending.auxiliaryObjectNames.isEmpty {
            try restoreCover(of: pending, objectIndex: 0, masterKey: masterKey, in: root)
            return try deleteIfPresent(
                named: pending.opaqueObjectName,
                masterKey: masterKey,
                expectedKind: .data,
                expectedLogicalByteCount: pending.logicalByteCount,
                in: root
            )
        }

        let manifestObject: V2PoolObject
        do {
            manifestObject = try objectStore.readObject(
                named: pending.opaqueObjectName,
                masterKey: masterKey,
                in: root
            )
        } catch V2PoolObjectStoreError.objectNotFound {
            try requireAllAuxiliaryObjectsAbsent(
                pending,
                masterKey: masterKey,
                in: root
            )
            try objectStore.confirmAuthenticatedObjectAbsenceDurably(
                named: pending.opaqueObjectName,
                in: root
            )
            for index in pending.allObjectNames.indices {
                try restoreCover(of: pending, objectIndex: index, masterKey: masterKey, in: root)
            }
            return false
        }

        let manifest = try validatePendingManifest(manifestObject, pending: pending)
        var removedSomething = false
        for (index, chunk) in manifest.chunks.enumerated() {
            try restoreCover(of: pending, objectIndex: index + 1, masterKey: masterKey, in: root)
            let removed = try deleteIfPresent(
                named: chunk.opaqueObjectName,
                masterKey: masterKey,
                expectedKind: .data,
                expectedLogicalByteCount: chunk.logicalByteCount,
                in: root
            )
            removedSomething = removedSomething || removed
        }

        try restoreCover(of: pending, objectIndex: 0, masterKey: masterKey, in: root)
        let removedManifest = try deleteIfPresent(
            named: pending.opaqueObjectName,
            masterKey: masterKey,
            expectedKind: .manifest,
            expectedLogicalByteCount: nil,
            in: root
        )
        return removedSomething || removedManifest
    }

    /// Fixed-capacity vaults only: writes the cover for object `objectIndex`
    /// (in `allObjectNames` order) before that object is deleted. Repeating
    /// it after a crash keeps the cover already written.
    private func restoreCover(
        of pending: V2PendingRemoval,
        objectIndex: Int,
        masterKey: Data,
        in root: URL
    ) throws {
        guard let slots = pending.coverSlots else {
            return
        }
        try covers.ensureCoverPresent(slots[objectIndex], masterKey: masterKey, in: root)
    }

    private func authenticatedManifest(
        for entry: V2AccessEntry,
        masterKey: Data,
        in root: URL
    ) throws -> V2ChunkManifest {
        let object = try objectStore.readObject(
            named: entry.opaqueObjectName,
            masterKey: masterKey,
            in: root
        )
        guard object.kind == .manifest else {
            throw V2RemovalTransactionError.pendingManifestKindMismatch
        }
        let manifest = try manifestCodec.decodeContent(object.content)
        guard manifest.fileID == entry.id,
              manifest.logicalByteCount == entry.logicalByteCount,
              manifest.chunks.map(\.opaqueObjectName) == entry.auxiliaryObjectNames else {
            throw V2RemovalTransactionError.pendingManifestMismatch
        }
        return manifest
    }

    private func validatePendingManifest(
        _ object: V2PoolObject,
        pending: V2PendingRemoval
    ) throws -> V2ChunkManifest {
        guard object.kind == .manifest else {
            throw V2RemovalTransactionError.pendingManifestKindMismatch
        }
        let manifest = try manifestCodec.decodeContent(object.content)
        guard manifest.fileID == pending.entryID,
              manifest.logicalByteCount == pending.logicalByteCount,
              manifest.chunks.map(\.opaqueObjectName) == pending.auxiliaryObjectNames else {
            throw V2RemovalTransactionError.pendingManifestMismatch
        }
        return manifest
    }

    private func requireAllAuxiliaryObjectsAbsent(
        _ pending: V2PendingRemoval,
        masterKey: Data,
        in root: URL
    ) throws {
        for name in pending.auxiliaryObjectNames {
            do {
                _ = try objectStore.readObject(
                    named: name,
                    masterKey: masterKey,
                    in: root
                )
                throw V2RemovalTransactionError.manifestMissingWithAuxiliaryObjects
            } catch V2PoolObjectStoreError.objectNotFound {
                try objectStore.confirmAuthenticatedObjectAbsenceDurably(
                    named: name,
                    in: root
                )
            }
        }
    }

    private func deleteIfPresent(
        named opaqueName: String,
        masterKey: Data,
        expectedKind: V2PoolObjectKind,
        expectedLogicalByteCount: UInt64?,
        in root: URL
    ) throws -> Bool {
        do {
            try objectStore.deleteAuthenticatedObject(
                named: opaqueName,
                masterKey: masterKey,
                expectedKind: expectedKind,
                expectedLogicalByteCount: expectedLogicalByteCount,
                in: root
            )
            return true
        } catch V2PoolObjectStoreError.objectNotFound {
            try objectStore.confirmAuthenticatedObjectAbsenceDurably(
                named: opaqueName,
                in: root
            )
            return false
        }
    }

    private func finalizePendingRemoval(
        transactionID: UUID,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessMetadata {
        try commitMetadataMutation(masterKey: masterKey, in: root) { current in
            try current.finalizingRemoval(transactionID: transactionID)
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
                try metadataStore.commitSpaceReleasingRemovalTransition(
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
        throw V2RemovalTransactionError.transitionRetryExhausted
    }
}
