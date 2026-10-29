import Foundation

public enum V2AccessMetadataValidationError: Error, Equatable, Sendable {
    case unsupportedVersion
    case duplicateEntryID
    case duplicatePendingTransactionID
    case duplicatePendingChunkTransactionID
    case duplicatePendingRemovalTransactionID
    case duplicatePendingRemovalEntryID
    case invalidObjectName
    case duplicateObjectName
    case invalidOriginalName
    case invalidPendingChunkImport
    case duplicateTombstone
    case liveObjectIsTombstoned
    case pendingObjectIsTombstoned
    case pendingRemovalObjectConflictsWithLiveObject
    case pendingRemovalObjectConflictsWithPendingImport
    case pendingRemovalObjectIsLegacyTombstoned
    case usageByteMismatch
    case usageObjectCountMismatch
    case usageExceedsBudget
    case arithmeticOverflow
    case metadataTooLarge
    /// The fixed-capacity state does not match its plan, or legacy
    /// tombstones exist in a fixed-capacity vault.
    case invalidFixedCapacity
    /// A pending transaction's cover slots are missing, unknown, still marked
    /// free, or shared with another transaction.
    case coverSlotConflict
    /// Free covers plus owned objects do not add up to the plan's slots.
    case coverCountMismatch
}

public enum V2AccessMetadataTransitionError: Error, Equatable, Sendable {
    case transactionAlreadyExists
    case objectNameAlreadyOwned
    case transactionNotFound
    case entryNotFound
    case removalAlreadyPending
    case chunkedRemovalUnsupported
    case removalPlanMismatch
    case generationOverflow
    /// Cover slots were given for an ordinary vault, missing for a
    /// fixed-capacity one, or the slots are not free.
    case coverSlotMismatch
    /// The fixed-capacity covers are still being written.
    case fixedCapacityNotFilled
    /// Fixed capacity can be turned on only for a new, empty access path.
    case fixedCapacityUnavailable
}

public struct V2AccessEntry: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let opaqueObjectName: String
    public let auxiliaryObjectNames: [String]
    public let originalName: String
    public let logicalByteCount: UInt64
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        opaqueObjectName: String,
        auxiliaryObjectNames: [String] = [],
        originalName: String,
        logicalByteCount: UInt64,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.opaqueObjectName = opaqueObjectName
        self.auxiliaryObjectNames = auxiliaryObjectNames
        self.originalName = originalName
        self.logicalByteCount = logicalByteCount
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case opaqueObjectName
        case auxiliaryObjectNames
        case originalName
        case logicalByteCount
        case createdAt
    }

    /// `auxiliaryObjectNames` was added while v2 remained disabled. Earlier v2
    /// metadata entries decode as single-object entries without migration.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(UUID.self, forKey: .id)
        self.opaqueObjectName = try container.decode(String.self, forKey: .opaqueObjectName)
        self.auxiliaryObjectNames = try container.decodeIfPresent(
            [String].self,
            forKey: .auxiliaryObjectNames
        ) ?? []
        self.originalName = try container.decode(String.self, forKey: .originalName)
        self.logicalByteCount = try container.decode(UInt64.self, forKey: .logicalByteCount)
        self.createdAt = try container.decode(Date.self, forKey: .createdAt)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(opaqueObjectName, forKey: .opaqueObjectName)
        try container.encode(auxiliaryObjectNames, forKey: .auxiliaryObjectNames)
        try container.encode(originalName, forKey: .originalName)
        try container.encode(logicalByteCount, forKey: .logicalByteCount)
        try container.encode(createdAt, forKey: .createdAt)
    }
}

/// A pre-committed ownership claim for one bounded data object that this access
/// path is about to create.
public struct V2PendingImport: Codable, Equatable, Identifiable, Sendable {
    public let transactionID: UUID
    public let opaqueObjectName: String
    public let originalName: String
    public let logicalByteCount: UInt64
    public let createdAt: Date
    /// Fixed-capacity vaults only: the slot whose cover this import replaces.
    /// Absent (and not encoded) in ordinary vaults.
    public let coverSlot: V2CoverSlot?

    public var id: UUID { transactionID }

    public init(
        transactionID: UUID = UUID(),
        opaqueObjectName: String,
        originalName: String,
        logicalByteCount: UInt64,
        createdAt: Date = Date(),
        coverSlot: V2CoverSlot? = nil
    ) {
        self.transactionID = transactionID
        self.opaqueObjectName = opaqueObjectName
        self.originalName = originalName
        self.logicalByteCount = logicalByteCount
        self.createdAt = createdAt
        self.coverSlot = coverSlot
    }
}

/// One chunk name/length reserved inside authenticated private metadata before
/// any corresponding pool object is created.
public struct V2PendingChunkObject: Codable, Equatable, Sendable {
    public let opaqueObjectName: String
    public let logicalByteCount: UInt64

    public init(opaqueObjectName: String, logicalByteCount: UInt64) {
        self.opaqueObjectName = opaqueObjectName
        self.logicalByteCount = logicalByteCount
    }
}

/// Authenticated ownership claim for one future multi-object file.
///
/// The manifest name and every chunk name are committed in private metadata
/// before any of those objects are written. The transaction ID is also the
/// private manifest file ID and becomes the eventual live entry ID.
public struct V2PendingChunkImport: Codable, Equatable, Identifiable, Sendable {
    public let transactionID: UUID
    public let manifestObjectName: String
    public let originalName: String
    public let logicalByteCount: UInt64
    public let chunks: [V2PendingChunkObject]
    public let sha256Digest: Data
    public let createdAt: Date
    /// Fixed-capacity vaults only: one slot per object, in `allObjectNames`
    /// order (manifest first, then chunks).
    public let coverSlots: [V2CoverSlot]?

    public var id: UUID { transactionID }

    public init(
        transactionID: UUID = UUID(),
        manifestObjectName: String,
        originalName: String,
        logicalByteCount: UInt64,
        chunks: [V2PendingChunkObject],
        sha256Digest: Data,
        createdAt: Date = Date(),
        coverSlots: [V2CoverSlot]? = nil
    ) {
        self.transactionID = transactionID
        self.manifestObjectName = manifestObjectName
        self.originalName = originalName
        self.logicalByteCount = logicalByteCount
        self.chunks = chunks
        self.sha256Digest = sha256Digest
        self.createdAt = createdAt
        self.coverSlots = coverSlots
    }

    func withCoverSlots(_ slots: [V2CoverSlot]?) -> V2PendingChunkImport {
        V2PendingChunkImport(
            transactionID: transactionID,
            manifestObjectName: manifestObjectName,
            originalName: originalName,
            logicalByteCount: logicalByteCount,
            chunks: chunks,
            sha256Digest: sha256Digest,
            createdAt: createdAt,
            coverSlots: slots
        )
    }

    func manifest() -> V2ChunkManifest {
        V2ChunkManifest(
            fileID: transactionID,
            logicalByteCount: logicalByteCount,
            chunks: chunks.map {
                V2ChunkReference(
                    opaqueObjectName: $0.opaqueObjectName,
                    logicalByteCount: $0.logicalByteCount
                )
            },
            sha256Digest: sha256Digest
        )
    }

    var allObjectNames: [String] {
        [manifestObjectName] + chunks.map(\.opaqueObjectName)
    }
}

/// Authenticated proof that one formerly-live entry is logically deleted and
/// awaiting physical removal from the shared pool.
///
/// For a bounded single-object entry `auxiliaryObjectNames` is empty. For a
/// chunked entry the primary name is the encrypted manifest and the ordered
/// auxiliary names are copied exactly from the authenticated live entry before
/// that entry is removed from metadata. This preserves ownership of every chunk
/// across crashes without exposing those names outside encrypted metadata.
public struct V2PendingRemoval: Codable, Equatable, Identifiable, Sendable {
    public let transactionID: UUID
    public let entryID: UUID
    public let opaqueObjectName: String
    public let auxiliaryObjectNames: [String]
    public let logicalByteCount: UInt64
    public let createdAt: Date
    /// Fixed-capacity vaults only: the empty slot that receives a new cover
    /// for each object, in `allObjectNames` order.
    public let coverSlots: [V2CoverSlot]?

    public var id: UUID { transactionID }

    init(
        transactionID: UUID,
        entryID: UUID,
        opaqueObjectName: String,
        auxiliaryObjectNames: [String] = [],
        logicalByteCount: UInt64,
        createdAt: Date,
        coverSlots: [V2CoverSlot]? = nil
    ) {
        self.transactionID = transactionID
        self.entryID = entryID
        self.opaqueObjectName = opaqueObjectName
        self.auxiliaryObjectNames = auxiliaryObjectNames
        self.logicalByteCount = logicalByteCount
        self.createdAt = createdAt
        self.coverSlots = coverSlots
    }

    private enum CodingKeys: String, CodingKey {
        case transactionID
        case entryID
        case opaqueObjectName
        case auxiliaryObjectNames
        case logicalByteCount
        case createdAt
        case coverSlots
    }

    /// Chunk-aware removal metadata was added while v2 remained disabled.
    /// Earlier pending single-object removals decode with no auxiliary names.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.transactionID = try container.decode(UUID.self, forKey: .transactionID)
        self.entryID = try container.decode(UUID.self, forKey: .entryID)
        self.opaqueObjectName = try container.decode(String.self, forKey: .opaqueObjectName)
        self.auxiliaryObjectNames = try container.decodeIfPresent(
            [String].self,
            forKey: .auxiliaryObjectNames
        ) ?? []
        self.logicalByteCount = try container.decode(UInt64.self, forKey: .logicalByteCount)
        self.createdAt = try container.decode(Date.self, forKey: .createdAt)
        self.coverSlots = try container.decodeIfPresent([V2CoverSlot].self, forKey: .coverSlots)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(transactionID, forKey: .transactionID)
        try container.encode(entryID, forKey: .entryID)
        try container.encode(opaqueObjectName, forKey: .opaqueObjectName)
        try container.encode(auxiliaryObjectNames, forKey: .auxiliaryObjectNames)
        try container.encode(logicalByteCount, forKey: .logicalByteCount)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encodeIfPresent(coverSlots, forKey: .coverSlots)
    }

    var allObjectNames: [String] {
        [opaqueObjectName] + auxiliaryObjectNames
    }
}

/// Authenticated private metadata for one unlocked v2 access path.
public struct V2AccessMetadata: Codable, Equatable, Sendable {
    public static let formatVersion: UInt32 = 1

    public let formatVersion: UInt32
    public let accessID: UUID
    public let generation: UInt64
    public let entries: [V2AccessEntry]
    public let pendingImports: [V2PendingImport]
    public let pendingChunkImports: [V2PendingChunkImport]
    public let pendingRemovals: [V2PendingRemoval]
    public let tombstonedObjectNames: [String]
    public let budget: V2StorageBudget
    public let usage: V2LogicalUsageLedger
    /// Present only in a fixed-capacity vault. Never encoded otherwise, so
    /// ordinary metadata keeps its exact earlier format.
    public let fixedCapacity: V2FixedCapacityState?

    public init(
        formatVersion: UInt32 = Self.formatVersion,
        accessID: UUID = UUID(),
        generation: UInt64 = 0,
        entries: [V2AccessEntry] = [],
        pendingImports: [V2PendingImport] = [],
        pendingChunkImports: [V2PendingChunkImport] = [],
        pendingRemovals: [V2PendingRemoval] = [],
        tombstonedObjectNames: [String] = [],
        budget: V2StorageBudget,
        usage: V2LogicalUsageLedger = V2LogicalUsageLedger(),
        fixedCapacity: V2FixedCapacityState? = nil
    ) {
        self.formatVersion = formatVersion
        self.accessID = accessID
        self.generation = generation
        self.entries = entries
        self.pendingImports = pendingImports
        self.pendingChunkImports = pendingChunkImports
        self.pendingRemovals = pendingRemovals
        self.tombstonedObjectNames = tombstonedObjectNames
        self.budget = budget
        self.usage = usage
        self.fixedCapacity = fixedCapacity
    }

    private enum CodingKeys: String, CodingKey {
        case formatVersion
        case accessID
        case generation
        case entries
        case pendingImports
        case pendingChunkImports
        case pendingRemovals
        case tombstonedObjectNames
        case budget
        case usage
        case fixedCapacity
    }

    /// Pending fields were added while v2 remained disabled. Missing fields from
    /// immediately preceding v2 foundation builds decode as empty.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.formatVersion = try container.decode(UInt32.self, forKey: .formatVersion)
        self.accessID = try container.decode(UUID.self, forKey: .accessID)
        self.generation = try container.decode(UInt64.self, forKey: .generation)
        self.entries = try container.decode([V2AccessEntry].self, forKey: .entries)
        self.pendingImports = try container.decodeIfPresent(
            [V2PendingImport].self,
            forKey: .pendingImports
        ) ?? []
        self.pendingChunkImports = try container.decodeIfPresent(
            [V2PendingChunkImport].self,
            forKey: .pendingChunkImports
        ) ?? []
        self.pendingRemovals = try container.decodeIfPresent(
            [V2PendingRemoval].self,
            forKey: .pendingRemovals
        ) ?? []
        self.tombstonedObjectNames = try container.decode(
            [String].self,
            forKey: .tombstonedObjectNames
        )
        self.budget = try container.decode(V2StorageBudget.self, forKey: .budget)
        self.usage = try container.decode(V2LogicalUsageLedger.self, forKey: .usage)
        self.fixedCapacity = try container.decodeIfPresent(
            V2FixedCapacityState.self,
            forKey: .fixedCapacity
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(formatVersion, forKey: .formatVersion)
        try container.encode(accessID, forKey: .accessID)
        try container.encode(generation, forKey: .generation)
        try container.encode(entries, forKey: .entries)
        try container.encode(pendingImports, forKey: .pendingImports)
        try container.encode(pendingChunkImports, forKey: .pendingChunkImports)
        try container.encode(pendingRemovals, forKey: .pendingRemovals)
        try container.encode(tombstonedObjectNames, forKey: .tombstonedObjectNames)
        try container.encode(budget, forKey: .budget)
        try container.encode(usage, forKey: .usage)
        try container.encodeIfPresent(fixedCapacity, forKey: .fixedCapacity)
    }

    public var authenticatedOwnedObjectNames: Set<String> {
        var names = Set<String>()
        for entry in entries {
            names.insert(entry.opaqueObjectName)
            names.formUnion(entry.auxiliaryObjectNames)
        }
        names.formUnion(pendingImports.map(\.opaqueObjectName))
        for pending in pendingChunkImports {
            names.formUnion(pending.allObjectNames)
        }
        for removal in pendingRemovals {
            names.formUnion(removal.allObjectNames)
        }
        names.formUnion(tombstonedObjectNames)
        return names
    }

    public var authenticatedTombstonedObjectNames: Set<String> {
        var names = Set(tombstonedObjectNames)
        for removal in pendingRemovals {
            names.formUnion(removal.allObjectNames)
        }
        return names
    }

    public var pendingLogicalBytes: UInt64 {
        let single = pendingImports.reduce(into: UInt64(0)) { partial, pending in
            let (next, overflow) = partial.addingReportingOverflow(pending.logicalByteCount)
            partial = overflow ? UInt64.max : next
        }
        return pendingChunkImports.reduce(into: single) { partial, pending in
            let (next, overflow) = partial.addingReportingOverflow(pending.logicalByteCount)
            partial = overflow ? UInt64.max : next
        }
    }

    public var pendingRemovalLogicalBytes: UInt64 {
        pendingRemovals.reduce(into: UInt64(0)) { partial, pending in
            let (next, overflow) = partial.addingReportingOverflow(pending.logicalByteCount)
            partial = overflow ? UInt64.max : next
        }
    }

    public func validate() throws {
        guard formatVersion == Self.formatVersion else {
            throw V2AccessMetadataValidationError.unsupportedVersion
        }

        var entryIDs = Set<UUID>()
        var liveNames = Set<String>()
        var expectedLogicalBytes: UInt64 = 0

        for entry in entries {
            guard entryIDs.insert(entry.id).inserted else {
                throw V2AccessMetadataValidationError.duplicateEntryID
            }
            guard Self.isSafeOriginalLeafName(entry.originalName) else {
                throw V2AccessMetadataValidationError.invalidOriginalName
            }

            for name in [entry.opaqueObjectName] + entry.auxiliaryObjectNames {
                guard V2OpaqueObjectName.isValid(name) else {
                    throw V2AccessMetadataValidationError.invalidObjectName
                }
                guard liveNames.insert(name).inserted else {
                    throw V2AccessMetadataValidationError.duplicateObjectName
                }
            }

            let (nextBytes, overflow) = expectedLogicalBytes.addingReportingOverflow(
                entry.logicalByteCount
            )
            guard !overflow else {
                throw V2AccessMetadataValidationError.arithmeticOverflow
            }
            expectedLogicalBytes = nextBytes
        }

        var tombstones = Set<String>()
        for name in tombstonedObjectNames {
            guard V2OpaqueObjectName.isValid(name) else {
                throw V2AccessMetadataValidationError.invalidObjectName
            }
            guard tombstones.insert(name).inserted else {
                throw V2AccessMetadataValidationError.duplicateTombstone
            }
            guard !liveNames.contains(name) else {
                throw V2AccessMetadataValidationError.liveObjectIsTombstoned
            }
        }

        var transactionIDs = Set<UUID>()
        var pendingNames = Set<String>()
        var expectedPendingBytes: UInt64 = 0

        func reservePendingName(_ name: String) throws {
            guard V2OpaqueObjectName.isValid(name) else {
                throw V2AccessMetadataValidationError.invalidObjectName
            }
            guard !liveNames.contains(name), pendingNames.insert(name).inserted else {
                throw V2AccessMetadataValidationError.duplicateObjectName
            }
            guard !tombstones.contains(name) else {
                throw V2AccessMetadataValidationError.pendingObjectIsTombstoned
            }
        }

        for pending in pendingImports {
            guard transactionIDs.insert(pending.transactionID).inserted else {
                throw V2AccessMetadataValidationError.duplicatePendingTransactionID
            }
            try reservePendingName(pending.opaqueObjectName)
            guard Self.isSafeOriginalLeafName(pending.originalName) else {
                throw V2AccessMetadataValidationError.invalidOriginalName
            }
            let (nextBytes, overflow) = expectedPendingBytes.addingReportingOverflow(
                pending.logicalByteCount
            )
            guard !overflow else {
                throw V2AccessMetadataValidationError.arithmeticOverflow
            }
            expectedPendingBytes = nextBytes
        }

        for pending in pendingChunkImports {
            guard transactionIDs.insert(pending.transactionID).inserted else {
                throw V2AccessMetadataValidationError.duplicatePendingChunkTransactionID
            }
            guard Self.isSafeOriginalLeafName(pending.originalName) else {
                throw V2AccessMetadataValidationError.invalidOriginalName
            }
            do {
                try pending.manifest().validate()
            } catch {
                throw V2AccessMetadataValidationError.invalidPendingChunkImport
            }
            for name in pending.allObjectNames {
                try reservePendingName(name)
            }
            let (nextBytes, overflow) = expectedPendingBytes.addingReportingOverflow(
                pending.logicalByteCount
            )
            guard !overflow else {
                throw V2AccessMetadataValidationError.arithmeticOverflow
            }
            expectedPendingBytes = nextBytes
        }

        var pendingRemovalEntryIDs = Set<UUID>()
        var pendingRemovalNames = Set<String>()
        var expectedPendingRemovalBytes: UInt64 = 0

        for removal in pendingRemovals {
            guard transactionIDs.insert(removal.transactionID).inserted else {
                throw V2AccessMetadataValidationError.duplicatePendingRemovalTransactionID
            }
            guard !entryIDs.contains(removal.entryID),
                  pendingRemovalEntryIDs.insert(removal.entryID).inserted else {
                throw V2AccessMetadataValidationError.duplicatePendingRemovalEntryID
            }

            for name in removal.allObjectNames {
                guard V2OpaqueObjectName.isValid(name) else {
                    throw V2AccessMetadataValidationError.invalidObjectName
                }
                guard !liveNames.contains(name) else {
                    throw V2AccessMetadataValidationError.pendingRemovalObjectConflictsWithLiveObject
                }
                guard !pendingNames.contains(name) else {
                    throw V2AccessMetadataValidationError.pendingRemovalObjectConflictsWithPendingImport
                }
                guard !tombstones.contains(name) else {
                    throw V2AccessMetadataValidationError.pendingRemovalObjectIsLegacyTombstoned
                }
                guard pendingRemovalNames.insert(name).inserted else {
                    throw V2AccessMetadataValidationError.duplicateObjectName
                }
            }

            let (nextBytes, overflow) = expectedPendingRemovalBytes.addingReportingOverflow(
                removal.logicalByteCount
            )
            guard !overflow else {
                throw V2AccessMetadataValidationError.arithmeticOverflow
            }
            expectedPendingRemovalBytes = nextBytes
        }

        guard usage.logicalBytes == expectedLogicalBytes else {
            throw V2AccessMetadataValidationError.usageByteMismatch
        }
        guard usage.objectCount == UInt64(entries.count) else {
            throw V2AccessMetadataValidationError.usageObjectCountMismatch
        }

        let (liveAndPendingImports, importOverflow) = usage.logicalBytes.addingReportingOverflow(
            expectedPendingBytes
        )
        guard !importOverflow else {
            throw V2AccessMetadataValidationError.arithmeticOverflow
        }
        let (reservedUsage, removalOverflow) = liveAndPendingImports.addingReportingOverflow(
            expectedPendingRemovalBytes
        )
        guard !removalOverflow else {
            throw V2AccessMetadataValidationError.arithmeticOverflow
        }
        do {
            try budget.validateVisibleUsage(reservedUsage)
        } catch {
            throw V2AccessMetadataValidationError.usageExceedsBudget
        }

        try validateFixedCapacity(ownedObjectCount: liveNames.count + pendingNames.count + pendingRemovalNames.count)
    }

    /// In a fixed-capacity vault every slot either holds a free cover (its
    /// ledger bit is set) or belongs to exactly one owned object, so free
    /// covers plus owned objects always equal the plan's slot count. Each
    /// pending transaction names one reserved, not-free slot per object.
    private func validateFixedCapacity(ownedObjectCount: Int) throws {
        let reservations: [(slots: [V2CoverSlot]?, objectCount: Int)] =
            pendingImports.map { ($0.coverSlot.map { [$0] }, 1) }
            + pendingChunkImports.map { ($0.coverSlots, $0.allObjectNames.count) }
            + pendingRemovals.map { ($0.coverSlots, $0.allObjectNames.count) }

        guard let state = fixedCapacity else {
            guard reservations.allSatisfy({ $0.slots == nil }) else {
                throw V2AccessMetadataValidationError.coverSlotConflict
            }
            return
        }

        let plan: V2FixedCapacityPlan
        do {
            plan = try state.plan()
        } catch {
            throw V2AccessMetadataValidationError.invalidFixedCapacity
        }
        guard state.ledger.matches(plan), tombstonedObjectNames.isEmpty else {
            throw V2AccessMetadataValidationError.invalidFixedCapacity
        }
        if !state.isFilled {
            guard ownedObjectCount == 0, state.ledger.freeSlotCount == plan.slotCount else {
                throw V2AccessMetadataValidationError.invalidFixedCapacity
            }
        }

        var reserved = Set<V2CoverSlot>()
        for reservation in reservations {
            guard let slots = reservation.slots, slots.count == reservation.objectCount else {
                throw V2AccessMetadataValidationError.coverSlotConflict
            }
            for slot in slots {
                guard state.ledger.contains(slot),
                      !state.ledger.hasCover(slot),
                      reserved.insert(slot).inserted else {
                    throw V2AccessMetadataValidationError.coverSlotConflict
                }
            }
        }

        guard state.ledger.freeSlotCount + ownedObjectCount == plan.slotCount else {
            throw V2AccessMetadataValidationError.coverCountMismatch
        }
    }

    public func beginningImport(_ pending: V2PendingImport) throws -> V2AccessMetadata {
        try validate()
        guard !pendingImports.contains(where: { $0.transactionID == pending.transactionID }),
              !pendingChunkImports.contains(where: { $0.transactionID == pending.transactionID }),
              !pendingRemovals.contains(where: { $0.transactionID == pending.transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionAlreadyExists
        }
        guard !authenticatedOwnedObjectNames.contains(pending.opaqueObjectName) else {
            throw V2AccessMetadataTransitionError.objectNameAlreadyOwned
        }

        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries,
            pendingImports: pendingImports + [pending],
            pendingChunkImports: pendingChunkImports,
            pendingRemovals: pendingRemovals,
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: usage,
            fixedCapacity: try fixedCapacityTaking(pending.coverSlot.map { [$0] })
        )
        try next.validate()
        return next
    }

    public func finalizingImport(transactionID: UUID) throws -> V2AccessMetadata {
        try validate()
        guard let pending = pendingImports.first(where: { $0.transactionID == transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionNotFound
        }

        let nextUsage = try usage.admittingObject(
            byteCount: pending.logicalByteCount,
            budget: budget
        )
        let entry = V2AccessEntry(
            id: pending.transactionID,
            opaqueObjectName: pending.opaqueObjectName,
            originalName: pending.originalName,
            logicalByteCount: pending.logicalByteCount,
            createdAt: pending.createdAt
        )
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries + [entry],
            pendingImports: pendingImports.filter { $0.transactionID != transactionID },
            pendingChunkImports: pendingChunkImports,
            pendingRemovals: pendingRemovals,
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: nextUsage,
            fixedCapacity: fixedCapacity
        )
        try next.validate()
        return next
    }

    public func abortingImport(transactionID: UUID) throws -> V2AccessMetadata {
        try validate()
        guard let pending = pendingImports.first(where: { $0.transactionID == transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionNotFound
        }
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries,
            pendingImports: pendingImports.filter { $0.transactionID != transactionID },
            pendingChunkImports: pendingChunkImports,
            pendingRemovals: pendingRemovals,
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: usage,
            fixedCapacity: try fixedCapacityReturning(pending.coverSlot.map { [$0] })
        )
        try next.validate()
        return next
    }

    public func beginningChunkImport(_ pending: V2PendingChunkImport) throws -> V2AccessMetadata {
        try validate()
        guard !pendingImports.contains(where: { $0.transactionID == pending.transactionID }),
              !pendingChunkImports.contains(where: { $0.transactionID == pending.transactionID }),
              !pendingRemovals.contains(where: { $0.transactionID == pending.transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionAlreadyExists
        }
        for name in pending.allObjectNames {
            guard !authenticatedOwnedObjectNames.contains(name) else {
                throw V2AccessMetadataTransitionError.objectNameAlreadyOwned
            }
        }

        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries,
            pendingImports: pendingImports,
            pendingChunkImports: pendingChunkImports + [pending],
            pendingRemovals: pendingRemovals,
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: usage,
            fixedCapacity: try fixedCapacityTaking(pending.coverSlots)
        )
        try next.validate()
        return next
    }

    public func finalizingChunkImport(transactionID: UUID) throws -> V2AccessMetadata {
        try validate()
        guard let pending = pendingChunkImports.first(where: { $0.transactionID == transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionNotFound
        }

        let nextUsage = try usage.admittingObject(
            byteCount: pending.logicalByteCount,
            budget: budget
        )
        let entry = V2AccessEntry(
            id: pending.transactionID,
            opaqueObjectName: pending.manifestObjectName,
            auxiliaryObjectNames: pending.chunks.map(\.opaqueObjectName),
            originalName: pending.originalName,
            logicalByteCount: pending.logicalByteCount,
            createdAt: pending.createdAt
        )
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries + [entry],
            pendingImports: pendingImports,
            pendingChunkImports: pendingChunkImports.filter { $0.transactionID != transactionID },
            pendingRemovals: pendingRemovals,
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: nextUsage,
            fixedCapacity: fixedCapacity
        )
        try next.validate()
        return next
    }

    public func abortingChunkImport(transactionID: UUID) throws -> V2AccessMetadata {
        try validate()
        guard let pending = pendingChunkImports.first(where: { $0.transactionID == transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionNotFound
        }
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries,
            pendingImports: pendingImports,
            pendingChunkImports: pendingChunkImports.filter { $0.transactionID != transactionID },
            pendingRemovals: pendingRemovals,
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: usage,
            fixedCapacity: try fixedCapacityReturning(pending.coverSlots)
        )
        try next.validate()
        return next
    }

    /// Moves one authenticated live single-object entry into a pending-removal
    /// tombstone. Multi-object entries continue to fail closed through this
    /// public transition; chunk-aware removal must first authenticate the private
    /// manifest through `V2RemovalTransactionCoordinator`.
    public func beginningRemoval(
        entryID: UUID,
        transactionID: UUID,
        createdAt: Date = Date(),
        coverSlots: [V2CoverSlot]? = nil
    ) throws -> V2AccessMetadata {
        try validate()
        try validateRemovalTransactionAvailability(
            entryID: entryID,
            transactionID: transactionID
        )
        guard let entry = entries.first(where: { $0.id == entryID }) else {
            throw V2AccessMetadataTransitionError.entryNotFound
        }
        guard entry.auxiliaryObjectNames.isEmpty else {
            throw V2AccessMetadataTransitionError.chunkedRemovalUnsupported
        }
        return try beginningRemoval(
            entry: entry,
            transactionID: transactionID,
            auxiliaryObjectNames: [],
            createdAt: createdAt,
            coverSlots: coverSlots
        )
    }

    /// Internal chunk-aware transition. The coordinator must authenticate and
    /// bind the private manifest before reaching this method. The supplied names
    /// are accepted only when they exactly equal the already-authenticated live
    /// entry's ordered auxiliary ownership list, so this transition cannot grant
    /// deletion authority over an arbitrary pool object.
    func beginningChunkedRemoval(
        entryID: UUID,
        transactionID: UUID,
        auxiliaryObjectNames: [String],
        createdAt: Date = Date(),
        coverSlots: [V2CoverSlot]? = nil
    ) throws -> V2AccessMetadata {
        try validate()
        try validateRemovalTransactionAvailability(
            entryID: entryID,
            transactionID: transactionID
        )
        guard let entry = entries.first(where: { $0.id == entryID }) else {
            throw V2AccessMetadataTransitionError.entryNotFound
        }
        guard !entry.auxiliaryObjectNames.isEmpty else {
            throw V2AccessMetadataTransitionError.chunkedRemovalUnsupported
        }
        guard entry.auxiliaryObjectNames == auxiliaryObjectNames else {
            throw V2AccessMetadataTransitionError.removalPlanMismatch
        }
        return try beginningRemoval(
            entry: entry,
            transactionID: transactionID,
            auxiliaryObjectNames: auxiliaryObjectNames,
            createdAt: createdAt,
            coverSlots: coverSlots
        )
    }

    public func finalizingRemoval(transactionID: UUID) throws -> V2AccessMetadata {
        try validate()
        guard let pending = pendingRemovals.first(where: { $0.transactionID == transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionNotFound
        }
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries,
            pendingImports: pendingImports,
            pendingChunkImports: pendingChunkImports,
            pendingRemovals: pendingRemovals.filter { $0.transactionID != transactionID },
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: usage,
            fixedCapacity: try fixedCapacityReturning(pending.coverSlots)
        )
        try next.validate()
        return next
    }

    private func validateRemovalTransactionAvailability(
        entryID: UUID,
        transactionID: UUID
    ) throws {
        guard !pendingImports.contains(where: { $0.transactionID == transactionID }),
              !pendingChunkImports.contains(where: { $0.transactionID == transactionID }),
              !pendingRemovals.contains(where: { $0.transactionID == transactionID }) else {
            throw V2AccessMetadataTransitionError.transactionAlreadyExists
        }
        guard !pendingRemovals.contains(where: { $0.entryID == entryID }) else {
            throw V2AccessMetadataTransitionError.removalAlreadyPending
        }
    }

    private func beginningRemoval(
        entry: V2AccessEntry,
        transactionID: UUID,
        auxiliaryObjectNames: [String],
        createdAt: Date,
        coverSlots: [V2CoverSlot]?
    ) throws -> V2AccessMetadata {
        // The slots stay marked empty until the removal finalizes; `validate`
        // checks they are empty and not used by another transaction.
        guard (fixedCapacity == nil) == (coverSlots == nil) else {
            throw V2AccessMetadataTransitionError.coverSlotMismatch
        }
        let pendingRemoval = V2PendingRemoval(
            transactionID: transactionID,
            entryID: entry.id,
            opaqueObjectName: entry.opaqueObjectName,
            auxiliaryObjectNames: auxiliaryObjectNames,
            logicalByteCount: entry.logicalByteCount,
            createdAt: createdAt,
            coverSlots: coverSlots
        )
        let nextUsage = try usage.removingObject(byteCount: entry.logicalByteCount)
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            entries: entries.filter { $0.id != entry.id },
            pendingImports: pendingImports,
            pendingChunkImports: pendingChunkImports,
            pendingRemovals: pendingRemovals + [pendingRemoval],
            tombstonedObjectNames: tombstonedObjectNames,
            budget: budget,
            usage: nextUsage,
            fixedCapacity: fixedCapacity
        )
        try next.validate()
        return next
    }

    /// Turns on fixed capacity for a new, empty access path. The ledger starts
    /// all covered but `isFilled` stays false until the covers are on disk.
    public func beginningFixedCapacity(capacityBytes: UInt64) throws -> V2AccessMetadata {
        try validate()
        guard fixedCapacity == nil,
              entries.isEmpty,
              pendingImports.isEmpty,
              pendingChunkImports.isEmpty,
              pendingRemovals.isEmpty,
              tombstonedObjectNames.isEmpty else {
            throw V2AccessMetadataTransitionError.fixedCapacityUnavailable
        }
        let plan = try V2FixedCapacityPlan(capacityBytes: capacityBytes)
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            budget: budget,
            usage: usage,
            fixedCapacity: V2FixedCapacityState(
                capacityBytes: capacityBytes,
                isFilled: false,
                ledger: V2CoverLedger(fullFor: plan)
            )
        )
        try next.validate()
        return next
    }

    /// Records that every cover of the plan is on disk.
    public func completingFixedCapacityFill() throws -> V2AccessMetadata {
        try validate()
        guard let state = fixedCapacity, !state.isFilled else {
            throw V2AccessMetadataTransitionError.fixedCapacityUnavailable
        }
        let next = V2AccessMetadata(
            accessID: accessID,
            generation: try nextGeneration(),
            budget: budget,
            usage: usage,
            fixedCapacity: V2FixedCapacityState(
                capacityBytes: state.capacityBytes,
                isFilled: true,
                ledger: state.ledger
            )
        )
        try next.validate()
        return next
    }

    /// Takes free slots out of the ledger for a new import claim.
    private func fixedCapacityTaking(_ slots: [V2CoverSlot]?) throws -> V2FixedCapacityState? {
        guard let state = fixedCapacity else {
            guard slots == nil else {
                throw V2AccessMetadataTransitionError.coverSlotMismatch
            }
            return nil
        }
        guard state.isFilled else {
            throw V2AccessMetadataTransitionError.fixedCapacityNotFilled
        }
        guard let slots,
              Set(slots).count == slots.count,
              slots.allSatisfy({ state.ledger.hasCover($0) }) else {
            throw V2AccessMetadataTransitionError.coverSlotMismatch
        }
        return state.with(ledger: try state.ledger.setting(false, for: slots))
    }

    /// Marks a finished transaction's slots as holding a free cover again.
    private func fixedCapacityReturning(_ slots: [V2CoverSlot]?) throws -> V2FixedCapacityState? {
        guard let state = fixedCapacity else {
            return nil
        }
        guard let slots else {
            throw V2AccessMetadataTransitionError.coverSlotMismatch
        }
        return state.with(ledger: try state.ledger.setting(true, for: slots))
    }

    private func nextGeneration() throws -> UInt64 {
        let (next, overflow) = generation.addingReportingOverflow(1)
        guard !overflow else {
            throw V2AccessMetadataTransitionError.generationOverflow
        }
        return next
    }

    private static func isSafeOriginalLeafName(_ name: String) -> Bool {
        guard !name.isEmpty,
              name != ".",
              name != "..",
              !name.contains("/"),
              !name.contains("\\"),
              !name.contains("\0") else {
            return false
        }
        return URL(fileURLWithPath: name).lastPathComponent == name
    }
}

/// Coarse encrypted-size buckets reduce direct leakage of the number and length
/// of private metadata records while keeping bounded memory use.
public enum V2AccessMetadataPaddingPolicy {
    public static let plaintextBuckets: [Int] = [
        4 * 1024,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        V2PoolObjectCodec.maximumPlaintextByteCount
    ]

    public static func targetPlaintextByteCount(forEncodedMetadataByteCount byteCount: Int) throws -> Int {
        let (minimum, overflow) = byteCount.addingReportingOverflow(
            V2PoolObjectCodec.encryptedPayloadHeaderByteCount
        )
        guard !overflow else {
            throw V2AccessMetadataValidationError.metadataTooLarge
        }
        guard let bucket = plaintextBuckets.first(where: { $0 >= minimum }) else {
            throw V2AccessMetadataValidationError.metadataTooLarge
        }
        return bucket
    }
}
