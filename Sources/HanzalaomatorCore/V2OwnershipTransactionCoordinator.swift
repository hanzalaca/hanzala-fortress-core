import Foundation

public enum V2OwnershipTransactionError: Error, Equatable, Sendable {
    case invalidGeneratedObjectName
    case candidateObjectAlreadyExists
    case nameGenerationExhausted
    case transitionRetryExhausted
    case pendingObjectKindMismatch
    case pendingObjectLengthMismatch
    case finalizedEntryMissing
}

public struct V2PendingImportRecoveryReport: Equatable, Sendable {
    public let finalizedTransactionIDs: [UUID]
    public let abortedMissingObjectTransactionIDs: [UUID]

    public init(
        finalizedTransactionIDs: [UUID] = [],
        abortedMissingObjectTransactionIDs: [UUID] = []
    ) {
        self.finalizedTransactionIDs = finalizedTransactionIDs
        self.abortedMissingObjectTransactionIDs = abortedMissingObjectTransactionIDs
    }
}

/// Crash-conscious ownership protocol for v2 data imports.
///
/// Ordering is deliberate:
/// 1. authenticate a pending ownership claim for a fresh opaque name;
/// 2. immutably create the encrypted object at exactly that name;
/// 3. authenticate a generation transition from pending -> live.
///
/// A crash before step 2 leaves a pending claim with no object and recovery may
/// remove only that claim. A crash after step 2 leaves a pending claim plus an
/// authenticated object; recovery can verify and finalize it. No plaintext or
/// public journal is created, and recovery never deletes an unverified object.
///
/// In a fixed-capacity vault the claim also reserves one free cover slot, the
/// object is padded to that slot's bucket, and the slot's cover is removed
/// after the object is written and authenticated. A crash in between leaves
/// one extra object, which recovery resolves from the reserved slot.
public final class V2OwnershipTransactionCoordinator {
    public static let maximumNameGenerationAttempts = 16
    public static let maximumTransitionRetries = 8

    private let metadataStore: V2AccessMetadataStore
    private let objectStore: V2PoolObjectStore
    private let physicalCapacityGuard: V2PhysicalCapacityGuard
    private let nameGenerator: () throws -> String
    private let transactionIDGenerator: () -> UUID
    private let covers: V2FixedCapacityCovers

    public init(
        metadataStore: V2AccessMetadataStore = V2AccessMetadataStore(),
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard(),
        nameGenerator: @escaping () throws -> String = { try V2OpaqueObjectName.generate() },
        transactionIDGenerator: @escaping () -> UUID = { UUID() }
    ) {
        self.metadataStore = metadataStore
        self.objectStore = objectStore
        self.physicalCapacityGuard = physicalCapacityGuard
        self.nameGenerator = nameGenerator
        self.transactionIDGenerator = transactionIDGenerator
        self.covers = V2FixedCapacityCovers(objectStore: objectStore)
    }

    /// Imports one data object. Padding is mandatory at this layer so a caller
    /// cannot accidentally enable an unpadded v2 mutation path. Physical capacity
    /// admission charges the final padded ciphertext size, not logical content.
    public func importData(
        _ content: Data,
        originalName: String,
        masterKey: Data,
        in root: URL,
        paddedPlaintextByteCount: Int
    ) throws -> V2AccessEntry {
        let logicalByteCount = UInt64(content.count)

        for _ in 0..<Self.maximumNameGenerationAttempts {
            let opaqueName = try nameGenerator()
            guard V2OpaqueObjectName.isValid(opaqueName) else {
                throw V2OwnershipTransactionError.invalidGeneratedObjectName
            }
            let transactionID = transactionIDGenerator()
            var pending = V2PendingImport(
                transactionID: transactionID,
                opaqueObjectName: opaqueName,
                originalName: originalName,
                logicalByteCount: logicalByteCount
            )

            let claimedMetadata: V2AccessMetadata
            do {
                claimedMetadata = try commitMetadataMutation(masterKey: masterKey, in: root) { current in
                    guard !current.authenticatedOwnedObjectNames.contains(opaqueName),
                          !self.objectStore.containsObject(named: opaqueName, in: root) else {
                        throw V2OwnershipTransactionError.candidateObjectAlreadyExists
                    }
                    if let state = current.fixedCapacity {
                        guard state.isFilled else {
                            throw V2AccessMetadataTransitionError.fixedCapacityNotFilled
                        }
                        let slot = try self.covers.chooseCoveredSlots(
                            minimumPlaintextByteCounts: [paddedPlaintextByteCount],
                            state: state,
                            masterKey: masterKey,
                            in: root
                        )[0]
                        pending = V2PendingImport(
                            transactionID: transactionID,
                            opaqueObjectName: opaqueName,
                            originalName: originalName,
                            logicalByteCount: logicalByteCount,
                            createdAt: pending.createdAt,
                            coverSlot: slot
                        )
                    }
                    return try current.beginningImport(pending)
                }
            } catch V2OwnershipTransactionError.candidateObjectAlreadyExists {
                continue
            } catch V2AccessMetadataTransitionError.objectNameAlreadyOwned {
                continue
            }

            // The pending ownership claim is authenticated before allocation.
            // Immediately before ciphertext creation, preserve the encrypted
            // role-neutral physical reserve plus bounded control-plane headroom
            // for the pending->live metadata transition that follows.
            // A fixed-capacity object takes its slot's size, which may be larger.
            let objectPlaintextByteCount = pending.coverSlot?.bucketPlaintextByteCount
                ?? paddedPlaintextByteCount
            let sealedByteCount = try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
                paddedPlaintextByteCount: objectPlaintextByteCount
            )
            do {
                try physicalCapacityGuard.validateDataWrite(
                    physicalWriteByteCount: sealedByteCount,
                    budget: claimedMetadata.budget,
                    at: root
                )
            } catch {
                // No pool object exists yet. Best-effort remove only this
                // authenticated pending claim so an ordinary low-space rejection
                // does not unnecessarily block the active session. If even the
                // control-plane cleanup cannot be written, recovery still sees the
                // missing exact object and can safely abort the claim later.
                try? abortPendingImport(
                    transactionID: transactionID,
                    masterKey: masterKey,
                    in: root
                )
                throw error
            }

            do {
                _ = try objectStore.createObject(
                    named: opaqueName,
                    kind: .data,
                    content: content,
                    masterKey: masterKey,
                    in: root,
                    paddedPlaintextByteCount: objectPlaintextByteCount
                )
            } catch V2PoolObjectStoreError.objectAlreadyExists {
                // We authenticated the claim before object creation, but another
                // writer won this extremely unlikely/random-name race. Remove only
                // our pending claim. Never delete or replace the existing object.
                try abortPendingImport(
                    transactionID: transactionID,
                    masterKey: masterKey,
                    in: root
                )
                continue
            }

            // Authenticate the exact object before publishing it as live metadata.
            try verifyPendingObject(pending, masterKey: masterKey, in: root)
            if let slot = pending.coverSlot {
                try covers.ensureCoverRemoved(slot, masterKey: masterKey, in: root)
            }
            let finalized = try finalizePendingImport(
                transactionID: transactionID,
                masterKey: masterKey,
                in: root
            )
            guard let entry = finalized.entries.first(where: { $0.id == transactionID }) else {
                throw V2OwnershipTransactionError.finalizedEntryMissing
            }
            return entry
        }

        throw V2OwnershipTransactionError.nameGenerationExhausted
    }

    /// Repairs only authenticated pending imports. Missing objects cause the
    /// pending metadata claim to be removed; present objects are authenticated
    /// and length-checked before finalization. Any malformed, wrong-key, symlink,
    /// oversized, or wrong-kind object fails closed and remains pending.
    public func recoverPendingImports(
        masterKey: Data,
        in root: URL
    ) throws -> V2PendingImportRecoveryReport {
        var finalized: [UUID] = []
        var aborted: [UUID] = []

        while true {
            let metadata = try metadataStore.read(masterKey: masterKey, in: root)
            guard let pending = metadata.pendingImports.first else {
                return V2PendingImportRecoveryReport(
                    finalizedTransactionIDs: finalized,
                    abortedMissingObjectTransactionIDs: aborted
                )
            }

            do {
                try verifyPendingObject(pending, masterKey: masterKey, in: root)
            } catch V2PoolObjectStoreError.objectNotFound {
                // The cover is removed only after the object exists, so it
                // should still be there; restore it if it is not.
                if let slot = pending.coverSlot {
                    try covers.ensureCoverPresent(slot, masterKey: masterKey, in: root)
                }
                try abortPendingImport(
                    transactionID: pending.transactionID,
                    masterKey: masterKey,
                    in: root
                )
                aborted.append(pending.transactionID)
                continue
            }

            if let slot = pending.coverSlot {
                try covers.ensureCoverRemoved(slot, masterKey: masterKey, in: root)
            }
            _ = try finalizePendingImport(
                transactionID: pending.transactionID,
                masterKey: masterKey,
                in: root
            )
            finalized.append(pending.transactionID)
        }
    }

    private func verifyPendingObject(
        _ pending: V2PendingImport,
        masterKey: Data,
        in root: URL
    ) throws {
        let object = try objectStore.readObject(
            named: pending.opaqueObjectName,
            masterKey: masterKey,
            in: root
        )
        guard object.kind == .data else {
            throw V2OwnershipTransactionError.pendingObjectKindMismatch
        }
        guard UInt64(object.content.count) == pending.logicalByteCount else {
            throw V2OwnershipTransactionError.pendingObjectLengthMismatch
        }
    }

    private func finalizePendingImport(
        transactionID: UUID,
        masterKey: Data,
        in root: URL
    ) throws -> V2AccessMetadata {
        try commitMetadataMutation(masterKey: masterKey, in: root) { current in
            try current.finalizingImport(transactionID: transactionID)
        }
    }

    private func abortPendingImport(
        transactionID: UUID,
        masterKey: Data,
        in root: URL
    ) throws {
        _ = try commitMetadataMutation(masterKey: masterKey, in: root) { current in
            try current.abortingImport(transactionID: transactionID)
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
        throw V2OwnershipTransactionError.transitionRetryExhausted
    }
}
