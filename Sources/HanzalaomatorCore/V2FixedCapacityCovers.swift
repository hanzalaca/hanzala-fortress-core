import Foundation

/// One slot of a fixed-capacity pool: its bucket size and its index there.
public struct V2CoverSlot: Codable, Hashable, Sendable {
    public let bucketPlaintextByteCount: Int
    public let index: Int

    public init(bucketPlaintextByteCount: Int, index: Int) {
        self.bucketPlaintextByteCount = bucketPlaintextByteCount
        self.index = index
    }
}

/// Fixed-capacity state kept inside one access path's encrypted metadata.
///
/// Ledger meaning: a set bit is a slot whose cover is on disk and free to
/// take. A slot named by a pending import or removal is reserved by that
/// transaction and its bit is clear until the transaction finishes, so
/// recovery always knows which cover each interrupted swap was using.
public struct V2FixedCapacityState: Codable, Equatable, Sendable {
    public let capacityBytes: UInt64
    /// False while the covers are still being written. Imports are refused
    /// until the fill completes, and opening the vault resumes it.
    public let isFilled: Bool
    public let ledger: V2CoverLedger

    public init(capacityBytes: UInt64, isFilled: Bool, ledger: V2CoverLedger) {
        self.capacityBytes = capacityBytes
        self.isFilled = isFilled
        self.ledger = ledger
    }

    public func plan() throws -> V2FixedCapacityPlan {
        try V2FixedCapacityPlan(capacityBytes: capacityBytes)
    }

    /// Authenticated plaintext that can still be stored, counting free slots.
    public var freePlaintextBytes: UInt64 { ledger.freePlaintextBytes }

    func with(ledger: V2CoverLedger) -> V2FixedCapacityState {
        V2FixedCapacityState(capacityBytes: capacityBytes, isFilled: isFilled, ledger: ledger)
    }
}

extension V2CoverLedger {
    /// True when the ledger has exactly the plan's buckets and slot counts.
    func matches(_ plan: V2FixedCapacityPlan) -> Bool {
        buckets.count == plan.slots.count
            && zip(buckets, plan.slots).allSatisfy {
                $0.isWellFormed
                    && $0.plaintextByteCount == $1.plaintextByteCount
                    && $0.slotCount == $1.count
            }
    }

    func contains(_ slot: V2CoverSlot) -> Bool {
        guard let bucket = buckets.first(where: { $0.plaintextByteCount == slot.bucketPlaintextByteCount }) else {
            return false
        }
        return slot.index >= 0 && slot.index < bucket.slotCount
    }

    /// Whether `slot` is marked as holding a free cover. The slot must exist.
    func hasCover(_ slot: V2CoverSlot) -> Bool {
        guard contains(slot),
              let bucket = buckets.first(where: { $0.plaintextByteCount == slot.bucketPlaintextByteCount }) else {
            return false
        }
        return bucket.hasCover(at: slot.index)
    }

    func setting(_ covered: Bool, for slots: [V2CoverSlot]) throws -> V2CoverLedger {
        var next = self
        for slot in slots {
            guard contains(slot),
                  let bucketIndex = next.buckets.firstIndex(where: {
                      $0.plaintextByteCount == slot.bucketPlaintextByteCount
                  }) else {
                throw V2FixedCapacityPoolError.invalidSlotReference
            }
            next.buckets[bucketIndex].setCover(covered, at: slot.index)
        }
        return next
    }
}

/// Cover-level operations for a fixed-capacity vault, used by the import and
/// removal coordinators. Every operation is idempotent so that recovery can
/// repeat it after a crash: a cover is created only when its derived name is
/// absent, and removed only after it authenticates as an empty padding object
/// under this vault's key. Anything else found at a cover name fails closed.
struct V2FixedCapacityCovers {
    private let objectStore: V2PoolObjectStore
    private let pool: V2FixedCapacityPool

    init(objectStore: V2PoolObjectStore) {
        self.objectStore = objectStore
        self.pool = V2FixedCapacityPool(objectStore: objectStore)
    }

    func coverName(for slot: V2CoverSlot, masterKey: Data) throws -> String {
        try pool.coverNamer(masterKey: masterKey)(slot.bucketPlaintextByteCount, slot.index)
    }

    /// Picks one distinct free slot for each requested minimum bucket size,
    /// smallest fitting bucket first, random within a bucket. Only slots whose
    /// cover is really on disk are taken.
    func chooseCoveredSlots(
        minimumPlaintextByteCounts: [Int],
        state: V2FixedCapacityState,
        masterKey: Data,
        in root: URL
    ) throws -> [V2CoverSlot] {
        let namer = try pool.coverNamer(masterKey: masterKey)
        var ledger = state.ledger
        var chosen: [V2CoverSlot] = []
        chosen.reserveCapacity(minimumPlaintextByteCounts.count)
        for minimum in minimumPlaintextByteCounts {
            var found: V2CoverSlot?
            search: for bucketIndex in ledger.buckets.indices
                where ledger.buckets[bucketIndex].plaintextByteCount >= minimum {
                let bucket = ledger.buckets[bucketIndex]
                for index in bucket.coveredSlotsInRandomOrder() {
                    if objectStore.containsObject(named: namer(bucket.plaintextByteCount, index), in: root) {
                        found = V2CoverSlot(bucketPlaintextByteCount: bucket.plaintextByteCount, index: index)
                        ledger.buckets[bucketIndex].setCover(false, at: index)
                        break search
                    }
                }
            }
            guard let slot = found else {
                throw V2FixedCapacityPoolError.vaultFull
            }
            chosen.append(slot)
        }
        return chosen
    }

    /// Picks one distinct empty, unreserved slot in the bucket of each named
    /// live object. The bucket is read from the object's size on disk.
    func chooseEmptySlots(
        forObjectsNamed names: [String],
        state: V2FixedCapacityState,
        reserved: Set<V2CoverSlot>,
        masterKey: Data,
        in root: URL
    ) throws -> [V2CoverSlot] {
        let namer = try pool.coverNamer(masterKey: masterKey)
        var taken = reserved
        var chosen: [V2CoverSlot] = []
        chosen.reserveCapacity(names.count)
        for name in names {
            let bucketSize = try bucketPlaintextByteCount(ofObjectNamed: name, state: state, in: root)
            guard let bucket = state.ledger.buckets.first(where: { $0.plaintextByteCount == bucketSize }) else {
                throw V2FixedCapacityPoolError.invalidSlotReference
            }
            var found: V2CoverSlot?
            for index in bucket.emptySlotsInRandomOrder() {
                let slot = V2CoverSlot(bucketPlaintextByteCount: bucketSize, index: index)
                guard !taken.contains(slot) else { continue }
                let coverName = namer(bucketSize, index)
                if !objectStore.containsObject(named: coverName, in: root)
                    || isGenuineCover(named: coverName, slot: slot, masterKey: masterKey, in: root) {
                    found = slot
                    break
                }
            }
            guard let slot = found else {
                throw V2FixedCapacityPoolError.invalidSlotReference
            }
            taken.insert(slot)
            chosen.append(slot)
        }
        return chosen
    }

    /// Makes sure the slot's cover is on disk: absent is created, a genuine
    /// cover is kept, anything else fails closed.
    func ensureCoverPresent(_ slot: V2CoverSlot, masterKey: Data, in root: URL) throws {
        let name = try coverName(for: slot, masterKey: masterKey)
        if objectStore.containsObject(named: name, in: root) {
            guard isGenuineCover(named: name, slot: slot, masterKey: masterKey, in: root) else {
                throw V2FixedCapacityPoolError.unexpectedObject
            }
            return
        }
        do {
            _ = try objectStore.createObject(
                named: name,
                kind: .padding,
                content: Data(),
                masterKey: masterKey,
                in: root,
                paddedPlaintextByteCount: slot.bucketPlaintextByteCount
            )
        } catch V2PoolObjectStoreError.objectAlreadyExists {
            guard isGenuineCover(named: name, slot: slot, masterKey: masterKey, in: root) else {
                throw V2FixedCapacityPoolError.unexpectedObject
            }
        }
    }

    /// Makes sure the slot's cover is gone. Only an authenticated empty
    /// padding object is ever deleted; absence is confirmed durably.
    func ensureCoverRemoved(_ slot: V2CoverSlot, masterKey: Data, in root: URL) throws {
        let name = try coverName(for: slot, masterKey: masterKey)
        do {
            try objectStore.deleteAuthenticatedObject(
                named: name,
                masterKey: masterKey,
                expectedKind: .padding,
                expectedLogicalByteCount: 0,
                in: root
            )
        } catch V2PoolObjectStoreError.objectNotFound {
            try objectStore.confirmAuthenticatedObjectAbsenceDurably(named: name, in: root)
        }
    }

    /// The bucket a live object occupies, from its sealed size on disk.
    func bucketPlaintextByteCount(
        ofObjectNamed name: String,
        state: V2FixedCapacityState,
        in root: URL
    ) throws -> Int {
        guard let sealed = sealedByteCount(named: name, in: root) else {
            throw V2PoolObjectStoreError.objectNotFound
        }
        guard let bucket = state.ledger.buckets.first(where: {
            V2FixedCapacityPool.sealedByteCount(plaintext: $0.plaintextByteCount) == sealed
        }) else {
            throw V2FixedCapacityPoolError.unexpectedObject
        }
        return bucket.plaintextByteCount
    }

    private func sealedByteCount(named name: String, in root: URL) -> UInt64? {
        let path = V2StorageLayout.objectURL(named: name, in: root).path
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              attributes[.type] as? FileAttributeType == .typeRegular else {
            return nil
        }
        return (attributes[.size] as? NSNumber)?.uint64Value
    }

    private func isGenuineCover(named name: String, slot: V2CoverSlot, masterKey: Data, in root: URL) -> Bool {
        guard sealedByteCount(named: name, in: root)
                == V2FixedCapacityPool.sealedByteCount(plaintext: slot.bucketPlaintextByteCount),
              let object = try? objectStore.readObject(named: name, masterKey: masterKey, in: root) else {
            return false
        }
        return object.kind == .padding && object.content.isEmpty
    }
}
