import Foundation

public enum V2VaultSessionError: Error, Equatable, Sendable {
    case envelopeIdentityChanged
    case accessIdentityChanged
    case entryNotFound
    case committedEntryMissing
    case unexpectedObjectKind
    case logicalLengthMismatch
    case invalidReadLength
    case readTooLarge
    case recoveryRequired
    case envelopeBindingFailed
    case passwordChangeUnavailable
    /// Fixed capacity was asked for a vault that already holds files, or with
    /// a different size than the one it was created with.
    case fixedCapacityUnavailable
}

/// What a fixed-capacity vault looks like to the app. Only ever built from
/// the unlocked access path's encrypted metadata.
public struct V2FixedCapacityStatus: Equatable, Sendable {
    public let capacityBytes: UInt64
    /// False while the covers are still being written.
    public let isFilled: Bool
    /// Authenticated plaintext the vault's slots hold in all.
    public let slotPlaintextBytes: UInt64
    /// Of that, the part in free slots.
    public let freePlaintextBytes: UInt64

    public init(capacityBytes: UInt64, isFilled: Bool, slotPlaintextBytes: UInt64, freePlaintextBytes: UInt64) {
        self.capacityBytes = capacityBytes
        self.isFilled = isFilled
        self.slotPlaintextBytes = slotPlaintextBytes
        self.freePlaintextBytes = freePlaintextBytes
    }
}

public enum V2VaultSessionFileImportError: Error, Equatable, Sendable {
    case sourceMetadataReadFailed
    case sourceIsSymbolicLink
    case sourceNotRegularFile
    case sourceSizeUnavailable
    case sourceOpenFailed
    case sourceReadFailed
    case sourceChangedDuringImport
    case sourceTooLarge
}

/// Capability representing exactly one successfully unlocked v2 access path.
///
/// The raw master key and public-envelope binding are intentionally not public.
/// Callers operate through `V2VaultSessionStore` using authenticated entry UUIDs
/// instead of supplying opaque object names or raw keys.
public struct V2VaultSession: Sendable {
    public let root: URL
    public let vaultID: UUID
    public let accessID: UUID
    public let role: VaultAccessRole

    let masterKey: Data
    let envelopeBinding: Data

    init(
        root: URL,
        vaultID: UUID,
        accessID: UUID,
        role: VaultAccessRole,
        masterKey: Data,
        envelopeBinding: Data
    ) {
        self.root = root
        self.vaultID = vaultID
        self.accessID = accessID
        self.role = role
        self.masterKey = masterKey
        self.envelopeBinding = envelopeBinding
    }
}

public struct V2VaultEntryData: Equatable, Sendable {
    public let entry: V2AccessEntry
    public let data: Data

    public init(entry: V2AccessEntry, data: Data) {
        self.entry = entry
        self.data = data
    }
}

public struct V2VaultSessionRecoveryReport: Equatable, Sendable {
    public let imports: V2PendingImportRecoveryReport
    public let chunkImports: V2PendingChunkImportRecoveryReport
    public let removals: V2PendingRemovalRecoveryReport

    public init(
        imports: V2PendingImportRecoveryReport,
        chunkImports: V2PendingChunkImportRecoveryReport = V2PendingChunkImportRecoveryReport(),
        removals: V2PendingRemovalRecoveryReport
    ) {
        self.imports = imports
        self.chunkImports = chunkImports
        self.removals = removals
    }
}

public struct V2OpenedVaultSession: Sendable {
    public let session: V2VaultSession
    public let recovery: V2VaultSessionRecoveryReport

    public init(session: V2VaultSession, recovery: V2VaultSessionRecoveryReport) {
        self.session = session
        self.recovery = recovery
    }
}

/// Integrated but still-disabled v2 session boundary.
///
/// This connects bootstrap/open, authenticated metadata, immutable pool objects,
/// bounded reads, automatic file import routing, authenticated removals, and
/// crash recovery behind one capability-style API. The same code path is used
/// for visible and concealed sessions; role does not select a different storage
/// implementation.
public final class V2VaultSessionStore {
    public static let defaultMaximumReadLength = V2ChunkedFileReader.defaultMaximumReadLength

    private let bootstrapStore: V2VaultBootstrapStore
    private let metadataStore: V2AccessMetadataStore
    private let objectStore: V2PoolObjectStore
    private let chunkReader: V2ChunkedFileReader
    private let ownershipCoordinator: V2OwnershipTransactionCoordinator
    private let chunkOwnershipCoordinator: V2ChunkOwnershipTransactionCoordinator
    private let removalCoordinator: V2RemovalTransactionCoordinator
    private let physicalCapacityGuard: V2PhysicalCapacityGuard
    private let maximumReadLength: Int

    /// Internal deterministic seam used only by core tests to replace a source
    /// pathname after the no-follow descriptor has been opened. Production
    /// callers cannot set this through the public initializer.
    var secureSourceOpenedHook: (() -> Void)?

    public init(
        bootstrapStore: V2VaultBootstrapStore = V2VaultBootstrapStore(),
        metadataStore: V2AccessMetadataStore = V2AccessMetadataStore(),
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        chunkReader: V2ChunkedFileReader? = nil,
        ownershipCoordinator: V2OwnershipTransactionCoordinator? = nil,
        chunkOwnershipCoordinator: V2ChunkOwnershipTransactionCoordinator? = nil,
        removalCoordinator: V2RemovalTransactionCoordinator? = nil,
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard(),
        maximumReadLength: Int = V2VaultSessionStore.defaultMaximumReadLength
    ) {
        precondition(maximumReadLength > 0)
        self.bootstrapStore = bootstrapStore
        self.metadataStore = metadataStore
        self.objectStore = objectStore
        self.physicalCapacityGuard = physicalCapacityGuard
        self.maximumReadLength = maximumReadLength
        self.chunkReader = chunkReader ?? V2ChunkedFileReader(
            objectStore: objectStore,
            maximumReadLength: maximumReadLength
        )
        self.ownershipCoordinator = ownershipCoordinator ?? V2OwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        )
        self.chunkOwnershipCoordinator = chunkOwnershipCoordinator ?? V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        )
        self.removalCoordinator = removalCoordinator ?? V2RemovalTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore,
            physicalCapacityGuard: physicalCapacityGuard
        )
        self.secureSourceOpenedHook = nil
    }

    /// Opens one password-selected access path and completes authenticated crash
    /// recovery before returning a usable session. Malformed/wrong-key pending
    /// objects fail closed; no session is returned in that case.
    public func openSession(
        at root: URL,
        password: String
    ) throws -> V2OpenedVaultSession {
        let opened = try bootstrapStore.openAccess(at: root, password: password)
        let binding = try canonicalEnvelopeData(opened.envelope)
        let session = V2VaultSession(
            root: root,
            vaultID: opened.envelope.vaultID,
            accessID: opened.metadata.accessID,
            role: opened.access.role,
            masterKey: opened.access.masterKey,
            envelopeBinding: binding
        )

        let recovery = try recover(session: session)
        _ = try validatedMetadata(for: session)
        return V2OpenedVaultSession(session: session, recovery: recovery)
    }

    /// Changes the password of a visible access path. Only the public
    /// envelope's visible slot is rewritten; files, metadata and the Recovery
    /// Key are untouched. Works the same for a session opened with the old
    /// password or with the Recovery Key. Returns a session bound to the new
    /// envelope; the old session value fails closed from now on.
    public func changeVisiblePassword(
        in session: V2VaultSession,
        to newPassword: String
    ) throws -> V2VaultSession {
        guard session.role == .visible else {
            throw V2VaultSessionError.passwordChangeUnavailable
        }
        _ = try validatedMetadata(for: session)

        let updated = try bootstrapStore.replaceVisiblePassword(
            at: session.root,
            masterKey: session.masterKey,
            expectedEnvelopeBinding: session.envelopeBinding,
            newPassword: newPassword
        )
        // The new envelope is published. Any failure now must not read as
        // "nothing changed".
        do {
            guard updated.vaultID == session.vaultID else {
                throw V2VaultSessionError.envelopeIdentityChanged
            }
            let refreshed = V2VaultSession(
                root: session.root,
                vaultID: session.vaultID,
                accessID: session.accessID,
                role: session.role,
                masterKey: session.masterKey,
                envelopeBinding: try canonicalEnvelopeData(updated)
            )
            _ = try validatedMetadata(for: refreshed)
            return refreshed
        } catch {
            throw V2VaultBootstrapStoreError.passwordChangeOutcomeUncertain
        }
    }

    /// The fixed-capacity state of this access path, or nil for an ordinary
    /// vault.
    public func fixedCapacityStatus(in session: V2VaultSession) throws -> V2FixedCapacityStatus? {
        guard let state = try validatedMetadata(for: session).fixedCapacity else {
            return nil
        }
        return V2FixedCapacityStatus(
            capacityBytes: state.capacityBytes,
            isFilled: state.isFilled,
            slotPlaintextBytes: try state.plan().slotPlaintextBytes,
            freePlaintextBytes: state.freePlaintextBytes
        )
    }

    /// Makes a new, empty access path fixed-capacity and writes its covers,
    /// which fills `capacityBytes` on disk once. Calling it again with the
    /// same size after an interruption resumes the fill; on a filled vault it
    /// does nothing. `progress` gets (slots done, slots in all).
    public func prepareFixedCapacity(
        capacityBytes: UInt64,
        in session: V2VaultSession,
        progress: ((Int, Int) -> Void)? = nil
    ) throws {
        let metadata = try validatedMetadata(for: session)
        try requireNoPendingRecovery(metadata)
        let plan = try V2FixedCapacityPlan(capacityBytes: capacityBytes)

        if let state = metadata.fixedCapacity {
            guard state.capacityBytes == capacityBytes else {
                throw V2VaultSessionError.fixedCapacityUnavailable
            }
            if state.isFilled {
                return
            }
        } else {
            guard metadata.entries.isEmpty else {
                throw V2VaultSessionError.fixedCapacityUnavailable
            }
        }

        // Refuse up front, for a new fill or a resumed one, rather than
        // failing part way through a fill the device cannot hold.
        let pool = V2FixedCapacityPool(objectStore: objectStore)
        let namer = try pool.coverNamer(masterKey: session.masterKey)
        var missingBytes: UInt64 = 0
        for slots in plan.slots {
            for index in 0..<slots.count
                where !objectStore.containsObject(named: namer(slots.plaintextByteCount, index), in: session.root) {
                missingBytes += V2FixedCapacityPool.sealedByteCount(plaintext: slots.plaintextByteCount)
            }
        }
        try physicalCapacityGuard.validateWrite(
            physicalWriteByteCount: missingBytes,
            budget: metadata.budget,
            at: session.root
        )

        if metadata.fixedCapacity == nil {
            try commitMetadataMutation(in: session) { current in
                try current.beginningFixedCapacity(capacityBytes: capacityBytes)
            }
        }

        _ = try pool.fill(
            plan: plan,
            masterKey: session.masterKey,
            in: session.root,
            progress: progress
        )
        try commitMetadataMutation(in: session) { current in
            try current.completingFixedCapacityFill()
        }
    }

    /// Returns only authenticated live entries for this session's access path.
    /// The shared pool is never scanned to discover additional files.
    public func listEntries(in session: V2VaultSession) throws -> [V2AccessEntry] {
        try validatedMetadata(for: session).entries
    }

    /// Legacy full-value read for bounded single-object entries only. Large
    /// chunked files deliberately stay on `readEntryRange` so they are never
    /// assembled into one giant `Data` value by this API.
    public func readEntry(
        id entryID: UUID,
        in session: V2VaultSession
    ) throws -> V2VaultEntryData {
        let metadata = try validatedMetadata(for: session)
        guard let entry = metadata.entries.first(where: { $0.id == entryID }) else {
            throw V2VaultSessionError.entryNotFound
        }
        guard entry.auxiliaryObjectNames.isEmpty else {
            throw V2VaultSessionError.unexpectedObjectKind
        }

        let object = try objectStore.readObject(
            named: entry.opaqueObjectName,
            masterKey: session.masterKey,
            in: session.root
        )
        try validateSingleObject(object, against: entry)
        return V2VaultEntryData(entry: entry, data: object.content)
    }

    /// Session-bound bounded read for both single-object and chunked live entries.
    ///
    /// The caller supplies only an authenticated entry UUID plus logical range.
    /// Raw master keys, manifest names, and chunk names never cross this API.
    /// The entry is reloaded from authenticated metadata on every call, so a
    /// caller cannot forge a `V2AccessEntry` to redirect a read into the pool.
    public func readEntryRange(
        id entryID: UUID,
        offset: UInt64,
        length: Int,
        in session: V2VaultSession
    ) throws -> Data {
        guard length >= 0 else {
            throw V2VaultSessionError.invalidReadLength
        }
        guard length <= maximumReadLength else {
            throw V2VaultSessionError.readTooLarge
        }

        let metadata = try validatedMetadata(for: session)
        guard let entry = metadata.entries.first(where: { $0.id == entryID }) else {
            throw V2VaultSessionError.entryNotFound
        }

        if !entry.auxiliaryObjectNames.isEmpty {
            return try chunkReader.read(
                entry: entry,
                offset: offset,
                length: length,
                masterKey: session.masterKey,
                in: session.root
            )
        }

        if length == 0 || offset >= entry.logicalByteCount {
            return Data()
        }
        let object = try objectStore.readObject(
            named: entry.opaqueObjectName,
            masterKey: session.masterKey,
            in: session.root
        )
        try validateSingleObject(object, against: entry)

        let available = entry.logicalByteCount - offset
        let requested = min(UInt64(length), available)
        guard requested <= UInt64(Int.max), offset <= UInt64(Int.max) else {
            throw V2VaultSessionError.logicalLengthMismatch
        }
        let start = Int(offset)
        let end = start + Int(requested)
        return Data(object.content[start..<end])
    }

    /// Explicit integrity operation for one authenticated live entry. Chunked
    /// files are verified incrementally against the private whole-file digest;
    /// bounded single objects are authenticated and length-checked once.
    public func verifyEntryIntegrity(
        id entryID: UUID,
        in session: V2VaultSession
    ) throws {
        let metadata = try validatedMetadata(for: session)
        guard let entry = metadata.entries.first(where: { $0.id == entryID }) else {
            throw V2VaultSessionError.entryNotFound
        }

        if !entry.auxiliaryObjectNames.isEmpty {
            try chunkReader.verifyWholeFile(
                entry: entry,
                masterKey: session.masterKey,
                in: session.root
            )
            return
        }

        let object = try objectStore.readObject(
            named: entry.opaqueObjectName,
            masterKey: session.masterKey,
            in: session.root
        )
        try validateSingleObject(object, against: entry)
    }

    /// Imports an already-materialized bounded value through the single-object
    /// authenticated ownership transaction. Callers importing filesystem files
    /// should prefer `importFile`, which automatically chooses this path or the
    /// bounded streaming chunk path based on the authenticated source size.
    @discardableResult
    public func importData(
        _ data: Data,
        originalName: String,
        into session: V2VaultSession
    ) throws -> V2AccessEntry {
        let metadata = try validatedMetadata(for: session)
        try requireNoPendingRecovery(metadata)
        let paddingTarget = try V2DataObjectPaddingPolicy.targetPlaintextByteCount(
            forContentByteCount: data.count
        )

        let committed = try reportingFullFixedVault(metadata) {
            try ownershipCoordinator.importData(
                data,
                originalName: originalName,
                masterKey: session.masterKey,
                in: session.root,
                paddedPlaintextByteCount: paddingTarget
            )
        }
        return try persistedEntry(for: committed, in: session)
    }

    /// Imports one regular non-symlink source file through the session capability.
    ///
    /// The source pathname is opened exactly once through `V2SecureSourceFile`
    /// before small/large routing. Bounded single-object reads and both passes of a
    /// chunked import reuse that same no-follow descriptor. Replacing the pathname
    /// after open therefore cannot redirect plaintext into either import route.
    ///
    /// `trustedSourceDirectory` is a folder the caller owns that holds the
    /// source; the path is then walked from there instead of from `/`, which a
    /// sandboxed app may not be allowed to open.
    @discardableResult
    public func importFile(
        at sourceURL: URL,
        originalName: String? = nil,
        trustedSourceDirectory: URL? = nil,
        into session: V2VaultSession
    ) throws -> V2AccessEntry {
        let metadata = try validatedMetadata(for: session)
        try requireNoPendingRecovery(metadata)

        let secureSource: V2SecureSourceFile
        do {
            secureSource = try V2SecureSourceFile(
                url: sourceURL,
                trustedDirectory: trustedSourceDirectory
            )
        } catch let error as V2SecureSourceFileError {
            throw mapSecureSourceError(error)
        }

        let expectedByteCount = secureSource.byteCount
        let resolvedName = originalName ?? sourceURL.lastPathComponent
        secureSourceOpenedHook?()

        if expectedByteCount <= V2DataObjectPaddingPolicy.maximumLogicalContentByteCount {
            let data = try readBoundedSingleObjectSource(
                secureSource,
                expectedByteCount: expectedByteCount
            )
            return try importData(
                data,
                originalName: resolvedName,
                into: session
            )
        }

        do {
            let committed = try reportingFullFixedVault(metadata) {
                try chunkOwnershipCoordinator.importChunkedFile(
                    source: secureSource,
                    originalName: resolvedName,
                    masterKey: session.masterKey,
                    in: session.root
                )
            }
            return try persistedEntry(for: committed, in: session)
        } catch let error as V2ChunkOwnershipTransactionError {
            switch error {
            case .sourceMetadataReadFailed:
                throw V2VaultSessionFileImportError.sourceMetadataReadFailed
            case .sourceIsSymbolicLink:
                throw V2VaultSessionFileImportError.sourceIsSymbolicLink
            case .sourceNotRegularFile:
                throw V2VaultSessionFileImportError.sourceNotRegularFile
            case .sourceSizeUnavailable:
                throw V2VaultSessionFileImportError.sourceSizeUnavailable
            case .sourceOpenFailed:
                throw V2VaultSessionFileImportError.sourceOpenFailed
            case .sourceReadFailed:
                throw V2VaultSessionFileImportError.sourceReadFailed
            case .sourceChangedDuringImport, .chunkingNotRequired:
                throw V2VaultSessionFileImportError.sourceChangedDuringImport
            case .tooManyChunks:
                throw V2VaultSessionFileImportError.sourceTooLarge
            default:
                throw error
            }
        }
    }

    /// Removes one currently authenticated live entry UUID. The removal
    /// coordinator preflights chunked manifests and whole-file integrity when
    /// auxiliary ownership exists, then persists a multi-object encrypted
    /// tombstone before deleting any manifest/chunk object.
    @discardableResult
    public func removeEntry(
        id entryID: UUID,
        from session: V2VaultSession
    ) throws -> UUID {
        let metadata = try validatedMetadata(for: session)
        try requireNoPendingRecovery(metadata)
        guard metadata.entries.contains(where: { $0.id == entryID }) else {
            throw V2VaultSessionError.entryNotFound
        }

        return try removalCoordinator.removeEntry(
            id: entryID,
            masterKey: session.masterKey,
            in: session.root
        )
    }

    /// Completes only authenticated pending work for this exact access path.
    /// Unknown pool objects are never scanned or deleted.
    @discardableResult
    public func recover(
        session: V2VaultSession
    ) throws -> V2VaultSessionRecoveryReport {
        _ = try validatedMetadata(for: session)

        let imports = try ownershipCoordinator.recoverPendingImports(
            masterKey: session.masterKey,
            in: session.root
        )
        let chunkImports = try chunkOwnershipCoordinator.recoverPendingChunkImports(
            masterKey: session.masterKey,
            in: session.root
        )
        let removals = try removalCoordinator.recoverPendingRemovals(
            masterKey: session.masterKey,
            in: session.root
        )

        _ = try validatedMetadata(for: session)
        return V2VaultSessionRecoveryReport(
            imports: imports,
            chunkImports: chunkImports,
            removals: removals
        )
    }

    /// A fixed-capacity vault's metadata has a fixed size, so running out of
    /// room in it means the vault is full, the same as running out of slots.
    private func reportingFullFixedVault<T>(
        _ metadata: V2AccessMetadata,
        _ work: () throws -> T
    ) throws -> T {
        do {
            return try work()
        } catch V2AccessMetadataValidationError.metadataTooLarge where metadata.fixedCapacity != nil {
            throw V2FixedCapacityPoolError.vaultFull
        }
    }

    private func commitMetadataMutation(
        in session: V2VaultSession,
        mutation: (V2AccessMetadata) throws -> V2AccessMetadata
    ) throws {
        for _ in 0..<V2OwnershipTransactionCoordinator.maximumTransitionRetries {
            let current = try validatedMetadata(for: session)
            let next = try mutation(current)
            do {
                try metadataStore.commitTransition(
                    from: current,
                    to: next,
                    masterKey: session.masterKey,
                    in: session.root
                )
                return
            } catch V2AccessMetadataStoreError.staleMetadata {
                continue
            }
        }
        throw V2OwnershipTransactionError.transitionRetryExhausted
    }

    private func persistedEntry(
        for committed: V2AccessEntry,
        in session: V2VaultSession
    ) throws -> V2AccessEntry {
        let refreshed = try validatedMetadata(for: session)
        guard let persisted = refreshed.entries.first(where: { $0.id == committed.id }) else {
            throw V2VaultSessionError.committedEntryMissing
        }
        return persisted
    }

    private func readBoundedSingleObjectSource(
        _ source: V2SecureSourceFile,
        expectedByteCount: Int
    ) throws -> Data {
        do {
            try source.validateUnchanged()

            var result = Data()
            result.reserveCapacity(expectedByteCount)
            while result.count < expectedByteCount {
                let request = min(
                    V2ChunkOwnershipTransactionCoordinator.maximumStreamingReadByteCount,
                    expectedByteCount - result.count
                )
                let bytes = try source.read(upToCount: request)
                guard !bytes.isEmpty else {
                    throw V2SecureSourceFileError.sourceChanged
                }
                result.append(bytes)
            }

            let extra = try source.read(upToCount: 1)
            guard extra.isEmpty else {
                throw V2SecureSourceFileError.sourceChanged
            }
            try source.validateUnchanged()
            return result
        } catch let error as V2SecureSourceFileError {
            throw mapSecureSourceError(error)
        }
    }

    private func mapSecureSourceError(
        _ error: V2SecureSourceFileError
    ) -> V2VaultSessionFileImportError {
        switch error {
        case .sourceOpenFailed:
            return .sourceOpenFailed
        case .sourceIsSymbolicLink:
            return .sourceIsSymbolicLink
        case .sourceNotRegularFile:
            return .sourceNotRegularFile
        case .sourceSizeUnavailable:
            return .sourceSizeUnavailable
        case .sourceReadFailed:
            return .sourceReadFailed
        case .sourceSeekFailed, .sourceChanged:
            return .sourceChangedDuringImport
        }
    }

    private func validateSingleObject(
        _ object: V2PoolObject,
        against entry: V2AccessEntry
    ) throws {
        guard object.kind == .data else {
            throw V2VaultSessionError.unexpectedObjectKind
        }
        guard UInt64(object.content.count) == entry.logicalByteCount else {
            throw V2VaultSessionError.logicalLengthMismatch
        }
    }

    private func validatedMetadata(for session: V2VaultSession) throws -> V2AccessMetadata {
        let currentEnvelope = try bootstrapStore.readEnvelope(at: session.root)
        let currentBinding = try canonicalEnvelopeData(currentEnvelope)
        guard currentBinding == session.envelopeBinding,
              currentEnvelope.vaultID == session.vaultID else {
            throw V2VaultSessionError.envelopeIdentityChanged
        }

        let metadata = try metadataStore.read(
            masterKey: session.masterKey,
            in: session.root
        )
        guard metadata.accessID == session.accessID else {
            throw V2VaultSessionError.accessIdentityChanged
        }
        return metadata
    }

    private func requireNoPendingRecovery(_ metadata: V2AccessMetadata) throws {
        guard metadata.pendingImports.isEmpty,
              metadata.pendingChunkImports.isEmpty,
              metadata.pendingRemovals.isEmpty else {
            throw V2VaultSessionError.recoveryRequired
        }
    }

    private func canonicalEnvelopeData(_ envelope: DualAccessEnvelopeV2) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        do {
            return try encoder.encode(envelope)
        } catch {
            throw V2VaultSessionError.envelopeBindingFailed
        }
    }
}
