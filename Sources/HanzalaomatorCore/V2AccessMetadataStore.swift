import Foundation

public enum V2AccessMetadataStoreError: Error, Equatable, Sendable {
    case metadataNotFound
    case anchorAlreadyExists
    case unexpectedObjectKind
    case malformedMetadata
    case poolPathIsNotDirectory
    case poolPathIsSymbolicLink
    case staleMetadata
    case accessIdentityChanged
    case budgetMutationNotAllowed
    case fixedCapacityMutationNotAllowed
    case invalidGenerationTransition
    case invalidSpaceReleasingTransition
    case stagingWriteFailed
    case stagingSyncFailed
    case commitFailed
}

/// Persists the authenticated private metadata anchor for one v2 access path.
///
/// The public anchor name is derived from that access path's master key by
/// `V2StorageNamespaceLocator`. Its contents are sealed with the same generic v2
/// pool-object envelope used for ordinary data and padding, and the ciphertext is
/// AEAD-bound to that derived opaque anchor name.
///
/// On Darwin, initial metadata publication reuses the descriptor-bound immutable
/// pool writer. Generation replacement keeps the root, `objects` directory and
/// current authenticated anchor open as retained no-follow descriptors from the
/// stale-generation check through the final relative rename.
public final class V2AccessMetadataStore {
    /// All key-owning v2 writers live in the main app process. A process-wide
    /// lock serializes metadata replacement across store instances. Generation
    /// comparison then detects stale callers. Hostile external namespace races are
    /// additionally narrowed by descriptor-bound Darwin commits, but a final
    /// fstatat->renameat race still exists and is documented explicitly.
    private static let processMutationLock = NSLock()

    private enum CommitAdmission {
        case standard
        case spaceReleasingRemoval
    }

    private let fileManager: FileManager
    private let codec: V2PoolObjectCodec
    private let locator: V2StorageNamespaceLocator
    private let objectStore: V2PoolObjectStore
    private let physicalCapacityGuard: V2PhysicalCapacityGuard
    private let durableCommitter: V2DurableFileCommitter
    private let descriptorMetadataCommitter: V2DescriptorBoundMetadataCommitter
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    #if canImport(Darwin)
    /// Internal deterministic seams used only by core tests.
    var metadataDescriptorsOpenedHook: (() -> Void)? {
        get { descriptorMetadataCommitter.descriptorsOpenedHook }
        set { descriptorMetadataCommitter.descriptorsOpenedHook = newValue }
    }

    var metadataBeforeNamespaceCommitHook: (() -> Void)? {
        get { descriptorMetadataCommitter.beforeNamespaceCommitHook }
        set { descriptorMetadataCommitter.beforeNamespaceCommitHook = newValue }
    }
    #endif

    public init(
        fileManager: FileManager = .default,
        codec: V2PoolObjectCodec = V2PoolObjectCodec(),
        locator: V2StorageNamespaceLocator = V2StorageNamespaceLocator(),
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard(),
        durableCommitter: V2DurableFileCommitter? = nil
    ) {
        let resolvedCommitter = durableCommitter ?? V2DurableFileCommitter(fileManager: fileManager)
        self.fileManager = fileManager
        self.codec = codec
        self.locator = locator
        self.durableCommitter = resolvedCommitter
        self.objectStore = V2PoolObjectStore(
            fileManager: fileManager,
            codec: codec,
            durableCommitter: resolvedCommitter
        )
        self.physicalCapacityGuard = physicalCapacityGuard
        self.descriptorMetadataCommitter = V2DescriptorBoundMetadataCommitter(
            durableCommitter: resolvedCommitter
        )
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.encoder.outputFormatting = [.sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder.dateDecodingStrategy = .iso8601
    }

    @discardableResult
    public func createInitialEmpty(
        budget: V2StorageBudget,
        masterKey: Data,
        in root: URL,
        accessID: UUID = UUID()
    ) throws -> V2AccessMetadata {
        let metadata = V2AccessMetadata(
            accessID: accessID,
            generation: 0,
            entries: [],
            pendingImports: [],
            pendingRemovals: [],
            tombstonedObjectNames: [],
            budget: budget,
            usage: V2LogicalUsageLedger()
        )
        try metadata.validate()

        let anchorName = try locator.indexObjectName(masterKey: masterKey)
        let payload = try encodedMetadata(metadata)
        let sealedByteCount = try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
            paddedPlaintextByteCount: payload.paddingTarget
        )

        Self.processMutationLock.lock()
        defer { Self.processMutationLock.unlock() }

        try physicalCapacityGuard.validateWrite(
            physicalWriteByteCount: sealedByteCount,
            budget: budget,
            at: root
        )

        do {
            _ = try objectStore.createObject(
                named: anchorName,
                kind: .metadata,
                content: payload.encoded,
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: payload.paddingTarget
            )
        } catch V2PoolObjectStoreError.objectAlreadyExists {
            throw V2AccessMetadataStoreError.anchorAlreadyExists
        } catch V2PoolObjectStoreError.poolPathIsSymbolicLink {
            throw V2AccessMetadataStoreError.poolPathIsSymbolicLink
        } catch V2PoolObjectStoreError.poolPathIsNotDirectory {
            throw V2AccessMetadataStoreError.poolPathIsNotDirectory
        } catch V2PoolObjectStoreError.stagingSyncFailed {
            throw V2AccessMetadataStoreError.stagingSyncFailed
        } catch V2PoolObjectStoreError.stagingWriteFailed {
            throw V2AccessMetadataStoreError.stagingWriteFailed
        } catch let error as V2PoolObjectStoreError {
            _ = error
            throw V2AccessMetadataStoreError.commitFailed
        }

        return metadata
    }

    public func read(masterKey: Data, in root: URL) throws -> V2AccessMetadata {
        try readUnlocked(masterKey: masterKey, in: root)
    }

    /// Commits exactly one ordinary authenticated metadata generation transition.
    func commitTransition(
        from expectedCurrent: V2AccessMetadata,
        to next: V2AccessMetadata,
        masterKey: Data,
        in root: URL
    ) throws {
        try commitTransition(
            from: expectedCurrent,
            to: next,
            masterKey: masterKey,
            in: root,
            admission: .standard
        )
    }

    /// Narrow internal low-space exception used only by authenticated removal.
    func commitSpaceReleasingRemovalTransition(
        from expectedCurrent: V2AccessMetadata,
        to next: V2AccessMetadata,
        masterKey: Data,
        in root: URL
    ) throws {
        guard isExactSpaceReleasingRemovalTransition(
            from: expectedCurrent,
            to: next
        ) else {
            throw V2AccessMetadataStoreError.invalidSpaceReleasingTransition
        }

        try commitTransition(
            from: expectedCurrent,
            to: next,
            masterKey: masterKey,
            in: root,
            admission: .spaceReleasingRemoval
        )
    }

    private func commitTransition(
        from expectedCurrent: V2AccessMetadata,
        to next: V2AccessMetadata,
        masterKey: Data,
        in root: URL,
        admission: CommitAdmission
    ) throws {
        try expectedCurrent.validate()
        try next.validate()

        guard next.accessID == expectedCurrent.accessID else {
            throw V2AccessMetadataStoreError.accessIdentityChanged
        }
        guard next.budget == expectedCurrent.budget else {
            throw V2AccessMetadataStoreError.budgetMutationNotAllowed
        }
        // Fixed capacity can be turned on once and never off; its size never
        // changes and a completed fill never goes back.
        if let current = expectedCurrent.fixedCapacity {
            guard let updated = next.fixedCapacity,
                  updated.capacityBytes == current.capacityBytes,
                  updated.isFilled || !current.isFilled else {
                throw V2AccessMetadataStoreError.fixedCapacityMutationNotAllowed
            }
        }
        let (requiredGeneration, overflow) = expectedCurrent.generation.addingReportingOverflow(1)
        guard !overflow, next.generation == requiredGeneration else {
            throw V2AccessMetadataStoreError.invalidGenerationTransition
        }

        let anchorName = try locator.indexObjectName(masterKey: masterKey)
        let sealed = try seal(
            next,
            masterKey: masterKey,
            objectName: anchorName
        )

        Self.processMutationLock.lock()
        defer { Self.processMutationLock.unlock() }

        #if canImport(Darwin)
        do {
            try descriptorMetadataCommitter.replaceExisting(
                sealed,
                named: anchorName,
                in: root,
                validateCurrent: { [self] currentSealed in
                    let actualCurrent = try decodeSealedMetadata(
                        currentSealed,
                        masterKey: masterKey,
                        objectName: anchorName
                    )
                    guard actualCurrent == expectedCurrent else {
                        throw V2AccessMetadataStoreError.staleMetadata
                    }
                },
                beforeStaging: { [self] in
                    try validateCapacityForMetadataCommit(
                        sealedByteCount: UInt64(sealed.count),
                        budget: next.budget,
                        admission: admission,
                        root: root
                    )
                }
            )
        } catch V2DescriptorBoundMetadataCommitError.stagingSyncFailed {
            throw V2AccessMetadataStoreError.stagingSyncFailed
        } catch V2DescriptorBoundMetadataCommitError.stagingCreateFailed {
            throw V2AccessMetadataStoreError.stagingWriteFailed
        } catch V2DescriptorBoundMetadataCommitError.stagingWriteFailed {
            throw V2AccessMetadataStoreError.stagingWriteFailed
        } catch let error as V2AccessMetadataStoreError {
            throw error
        } catch let error as V2DescriptorBoundMetadataCommitError {
            _ = error
            throw V2AccessMetadataStoreError.commitFailed
        } catch {
            // Preserve authentication, metadata-validation, capacity, and
            // deterministic simulated-power-loss errors.
            throw error
        }
        #else
        let actualCurrent = try readUnlocked(masterKey: masterKey, in: root)
        guard actualCurrent == expectedCurrent else {
            throw V2AccessMetadataStoreError.staleMetadata
        }

        let pool = V2StorageLayout.poolURL(in: root)
        try validateExistingPoolDirectory(pool)
        let destination = V2StorageLayout.objectURL(named: anchorName, in: root)
        try validateCapacityForMetadataCommit(
            sealedByteCount: UInt64(sealed.count),
            budget: next.budget,
            admission: admission,
            root: root
        )

        do {
            try durableCommitter.replaceExisting(
                sealed,
                at: destination,
                stagingPrefix: ".hanzala-v2-metadata-stage-"
            )
        } catch V2DurableFileCommitError.stagingSyncFailed {
            throw V2AccessMetadataStoreError.stagingSyncFailed
        } catch V2DurableFileCommitError.stagingCreateFailed {
            throw V2AccessMetadataStoreError.stagingWriteFailed
        } catch V2DurableFileCommitError.stagingWriteFailed {
            throw V2AccessMetadataStoreError.stagingWriteFailed
        } catch {
            throw V2AccessMetadataStoreError.commitFailed
        }
        #endif
    }

    private func validateCapacityForMetadataCommit(
        sealedByteCount: UInt64,
        budget: V2StorageBudget,
        admission: CommitAdmission,
        root: URL
    ) throws {
        switch admission {
        case .standard:
            try physicalCapacityGuard.validateWrite(
                physicalWriteByteCount: sealedByteCount,
                budget: budget,
                at: root
            )
        case .spaceReleasingRemoval:
            try physicalCapacityGuard.validateSpaceReleasingMetadataWrite(
                physicalWriteByteCount: sealedByteCount,
                at: root
            )
        }
    }

    /// Reconstructs the exact allowed removal transition instead of trusting a
    /// caller-supplied recovery flag.
    private func isExactSpaceReleasingRemovalTransition(
        from current: V2AccessMetadata,
        to next: V2AccessMetadata
    ) -> Bool {
        let currentIDs = Set(current.pendingRemovals.map(\.transactionID))
        let nextIDs = Set(next.pendingRemovals.map(\.transactionID))

        let addedIDs = nextIDs.subtracting(currentIDs)
        let removedIDs = currentIDs.subtracting(nextIDs)

        if addedIDs.count == 1, removedIDs.isEmpty,
           let transactionID = addedIDs.first,
           let pending = next.pendingRemovals.first(where: {
               $0.transactionID == transactionID
           }) {
            do {
                let expected: V2AccessMetadata
                if pending.auxiliaryObjectNames.isEmpty {
                    expected = try current.beginningRemoval(
                        entryID: pending.entryID,
                        transactionID: pending.transactionID,
                        createdAt: pending.createdAt,
                        coverSlots: pending.coverSlots
                    )
                } else {
                    expected = try current.beginningChunkedRemoval(
                        entryID: pending.entryID,
                        transactionID: pending.transactionID,
                        auxiliaryObjectNames: pending.auxiliaryObjectNames,
                        createdAt: pending.createdAt,
                        coverSlots: pending.coverSlots
                    )
                }
                return expected == next
            } catch {
                return false
            }
        }

        if removedIDs.count == 1, addedIDs.isEmpty,
           let transactionID = removedIDs.first {
            do {
                return try current.finalizingRemoval(
                    transactionID: transactionID
                ) == next
            } catch {
                return false
            }
        }

        return false
    }

    private func readUnlocked(masterKey: Data, in root: URL) throws -> V2AccessMetadata {
        let anchorName = try locator.indexObjectName(masterKey: masterKey)

        let object: V2PoolObject
        do {
            object = try objectStore.readObject(
                named: anchorName,
                masterKey: masterKey,
                in: root
            )
        } catch V2PoolObjectStoreError.objectNotFound {
            throw V2AccessMetadataStoreError.metadataNotFound
        }

        return try decodeMetadataObject(object)
    }

    private func decodeSealedMetadata(
        _ sealed: Data,
        masterKey: Data,
        objectName: String
    ) throws -> V2AccessMetadata {
        let object = try codec.open(
            sealed,
            masterKey: masterKey,
            objectName: objectName
        )
        return try decodeMetadataObject(object)
    }

    private func decodeMetadataObject(_ object: V2PoolObject) throws -> V2AccessMetadata {
        guard object.kind == .metadata else {
            throw V2AccessMetadataStoreError.unexpectedObjectKind
        }

        let metadata: V2AccessMetadata
        do {
            metadata = try decoder.decode(V2AccessMetadata.self, from: object.content)
        } catch {
            throw V2AccessMetadataStoreError.malformedMetadata
        }
        try metadata.validate()
        return metadata
    }

    private func encodedMetadata(
        _ metadata: V2AccessMetadata
    ) throws -> (encoded: Data, paddingTarget: Int) {
        let encoded: Data
        do {
            encoded = try encoder.encode(metadata)
        } catch {
            throw V2AccessMetadataStoreError.malformedMetadata
        }
        let paddingTarget = try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
            forEncodedMetadataByteCount: encoded.count
        )
        guard metadata.fixedCapacity != nil else {
            return (encoded, paddingTarget)
        }
        // A fixed-capacity vault's metadata always has the same size, so it
        // does not reveal how many files were added. When it is full, more
        // files cannot be added.
        guard paddingTarget <= V2FixedCapacityPlan.metadataPaddedPlaintextByteCount else {
            throw V2AccessMetadataValidationError.metadataTooLarge
        }
        return (encoded, V2FixedCapacityPlan.metadataPaddedPlaintextByteCount)
    }

    private func seal(
        _ metadata: V2AccessMetadata,
        masterKey: Data,
        objectName: String
    ) throws -> Data {
        let payload = try encodedMetadata(metadata)
        return try codec.seal(
            kind: .metadata,
            content: payload.encoded,
            masterKey: masterKey,
            objectName: objectName,
            paddedPlaintextByteCount: payload.paddingTarget
        )
    }

    private func validateExistingPoolDirectory(_ pool: URL) throws {
        let values: URLResourceValues
        do {
            values = try pool.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        } catch {
            throw V2AccessMetadataStoreError.poolPathIsNotDirectory
        }
        guard values.isSymbolicLink != true else {
            throw V2AccessMetadataStoreError.poolPathIsSymbolicLink
        }
        guard values.isDirectory == true else {
            throw V2AccessMetadataStoreError.poolPathIsNotDirectory
        }
    }
}
