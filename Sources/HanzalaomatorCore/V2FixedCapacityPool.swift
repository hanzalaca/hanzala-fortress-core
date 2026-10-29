import CryptoKit
import Foundation

public enum V2FixedCapacityPoolError: Error, Equatable, Sendable {
    /// The chosen capacity is below `minimumCapacityBytes` or above
    /// `maximumCapacityBytes`.
    case capacityOutOfRange
    /// A slot profile with no slots, an unknown bucket, or a negative count.
    case invalidProfile
    /// No free slot is large enough for this content. The vault must be
    /// enlarged, which is a visible change.
    case vaultFull
    /// Content larger than the biggest pool object.
    case contentTooLarge
    /// Only data and chunk-manifest objects take slots. Metadata has its own
    /// fixed size and padding objects are the covers themselves.
    case unsupportedKind
    /// The reference or ledger does not describe a slot of this pool.
    case invalidSlotReference
    /// A swap failed and undoing its first step failed too, so the pool holds
    /// one extra object. The ledger is unchanged; the caller must reconcile
    /// the pool before relying on its shape again.
    case swapIncomplete
    case invalidMasterKeyLength
    /// A file at a cover's derived name has the wrong size for its bucket.
    case unexpectedObject
}

/// Sessions use it through `V2FixedCapacityCovers` (see Docs/V2-FIXED-CAPACITY-POOL.md).
///
/// A fixed-capacity vault looks the same on disk whatever it holds. When it is
/// created, the whole chosen capacity is filled with encrypted padding objects
/// ("covers"). Covers use the same envelope, the same opaque name format and
/// the same bucket sizes as real objects, so without the key nothing tells
/// them apart. Every later write swaps a real object in for a cover of the
/// same size, and every delete swaps a cover back in. The number of objects,
/// the size of each object and the total size therefore never change.
///
/// The slot profile (how many objects of each bucket size) depends only on
/// the chosen capacity, never on what is stored. Capacity counts authenticated
/// plaintext; every object adds a fixed 48-byte envelope on disk.
public struct V2FixedCapacityPlan: Codable, Equatable, Sendable {
    public static let minimumCapacityBytes: UInt64 = 64 * 1024 * 1024
    /// Bounded so the cover ledger stays small enough for fixed-size metadata.
    public static let maximumCapacityBytes: UInt64 = 256 * 1024 * 1024 * 1024
    /// In a fixed-capacity vault the encrypted metadata is always padded to
    /// this size, so it does not grow into a larger bucket as files are added.
    public static let metadataPaddedPlaintextByteCount = 1024 * 1024

    /// Share of the capacity, in percent, given to each bucket, with a cap on
    /// the number of small slots. The 4 MiB bucket (the chunk size of large
    /// files) takes whatever is left.
    static let bucketShares: [(bucket: Int, percent: UInt64, maximumCount: UInt64)] = [
        (4 * 1024, 1, 4_096),
        (16 * 1024, 1, 2_048),
        (64 * 1024, 2, 1_024),
        (256 * 1024, 4, 512),
        (1024 * 1024, 8, 512),
        (V2PoolObjectCodec.maximumPlaintextByteCount, 16, UInt64.max)
    ]
    static let remainderBucket = V2ChunkManifest.chunkPaddedPlaintextByteCount

    public struct Slots: Codable, Equatable, Sendable {
        /// Authenticated plaintext size of each object in this bucket.
        public let plaintextByteCount: Int
        public let count: Int
    }

    public let capacityBytes: UInt64
    /// Sorted by bucket size, smallest first.
    public let slots: [Slots]

    public init(capacityBytes: UInt64) throws {
        guard capacityBytes >= Self.minimumCapacityBytes,
              capacityBytes <= Self.maximumCapacityBytes else {
            throw V2FixedCapacityPoolError.capacityOutOfRange
        }
        var counts: [Int: Int] = [:]
        var used: UInt64 = 0
        for share in Self.bucketShares {
            let count = min(capacityBytes * share.percent / 100 / UInt64(share.bucket), share.maximumCount)
            counts[share.bucket] = Int(count)
            used += count * UInt64(share.bucket)
        }
        counts[Self.remainderBucket, default: 0] += Int((capacityBytes - used) / UInt64(Self.remainderBucket))
        try self.init(capacityBytes: capacityBytes, counts: counts)
    }

    /// Explicit profile, used by tests to keep pools small.
    init(capacityBytes: UInt64, counts: [Int: Int]) throws {
        guard !counts.isEmpty,
              counts.keys.allSatisfy({ V2DataObjectPaddingPolicy.plaintextBuckets.contains($0) }),
              counts.values.allSatisfy({ $0 >= 0 }),
              counts.values.contains(where: { $0 > 0 }) else {
            throw V2FixedCapacityPoolError.invalidProfile
        }
        self.capacityBytes = capacityBytes
        self.slots = counts
            .filter { $0.value > 0 }
            .sorted { $0.key < $1.key }
            .map { Slots(plaintextByteCount: $0.key, count: $0.value) }
    }

    public var slotCount: Int {
        slots.reduce(0) { $0 + $1.count }
    }

    /// Sum of the authenticated plaintext of every slot; never above the
    /// chosen capacity.
    public var slotPlaintextBytes: UInt64 {
        slots.reduce(0) { $0 + UInt64($1.plaintextByteCount) * UInt64($1.count) }
    }
}

/// Which slots currently hold a cover, one bit per slot. It reveals how full
/// the vault is, so it must only ever be stored inside the access path's
/// encrypted metadata, never in a public file. Cover names are derived from
/// the key and the slot, so the ledger stays a few kilobytes even for the
/// largest capacity.
public struct V2CoverLedger: Codable, Equatable, Sendable {
    public struct Bucket: Codable, Equatable, Sendable {
        public let plaintextByteCount: Int
        public let slotCount: Int
        /// Bit `i` set: slot `i` holds a cover (is free).
        var coverBitmap: Data

        init(plaintextByteCount: Int, slotCount: Int, allCovered: Bool) {
            self.plaintextByteCount = plaintextByteCount
            self.slotCount = slotCount
            self.coverBitmap = Data(repeating: 0, count: (slotCount + 7) / 8)
            if allCovered {
                for index in 0..<slotCount { setCover(true, at: index) }
            }
        }

        func hasCover(at index: Int) -> Bool {
            coverBitmap[index / 8] & (1 << UInt8(index % 8)) != 0
        }

        mutating func setCover(_ covered: Bool, at index: Int) {
            if covered {
                coverBitmap[index / 8] |= 1 << UInt8(index % 8)
            } else {
                coverBitmap[index / 8] &= ~(1 << UInt8(index % 8))
            }
        }

        public var freeSlotCount: Int {
            (0..<slotCount).reduce(0) { $0 + (hasCover(at: $1) ? 1 : 0) }
        }

        /// A uniformly random slot with (or without) a cover, so covers are
        /// not consumed in a predictable order.
        func randomSlot(covered: Bool) -> Int? {
            let candidates = (0..<slotCount).filter { hasCover(at: $0) == covered }
            return candidates.randomElement()
        }

        func coveredSlotsInRandomOrder() -> [Int] {
            (0..<slotCount).filter { hasCover(at: $0) }.shuffled()
        }

        func emptySlotsInRandomOrder() -> [Int] {
            (0..<slotCount).filter { !hasCover(at: $0) }.shuffled()
        }

        var isWellFormed: Bool {
            slotCount > 0 && coverBitmap.count == (slotCount + 7) / 8
        }
    }

    /// Sorted by bucket size, smallest first.
    public internal(set) var buckets: [Bucket]

    /// The ledger of a freshly filled pool: every slot holds a cover.
    public init(fullFor plan: V2FixedCapacityPlan) {
        self.buckets = plan.slots.map {
            Bucket(plaintextByteCount: $0.plaintextByteCount, slotCount: $0.count, allCovered: true)
        }
    }

    public var freeSlotCount: Int {
        buckets.reduce(0) { $0 + $1.freeSlotCount }
    }

    public var freePlaintextBytes: UInt64 {
        buckets.reduce(0) { $0 + UInt64($1.plaintextByteCount) * UInt64($1.freeSlotCount) }
    }

    /// The smallest bucket at or above `minimum` that still has a cover.
    func smallestFreeBucketIndex(atLeast minimum: Int) -> Int? {
        buckets.firstIndex { $0.plaintextByteCount >= minimum && $0.freeSlotCount > 0 }
    }
}

/// A real object occupying one slot.
public struct V2FixedCapacitySlotReference: Codable, Equatable, Sendable {
    public let opaqueName: String
    public let kindRawValue: UInt8
    /// The slot's bucket size, which may be larger than the content needed.
    public let plaintextByteCount: Int
    public let logicalByteCount: UInt64
}

/// Experimental. Swaps real objects and covers one for one, so the pool's
/// public shape stays fixed.
///
/// Crash ordering: the new object is always committed before the old one is
/// removed, so an interruption leaves at most one extra object, never a
/// missing one. Filling is resumable: covers have derived names, so running
/// `fill` again after an interruption writes only the missing ones. The
/// caller records ownership of new real objects before calling (as
/// `V2OwnershipTransactionCoordinator` does for imports) and persists the
/// updated ledger afterwards; reconciling a possible extra object on the next
/// open belongs to that integration.
public final class V2FixedCapacityPool {
    private static let coverNameLabel = Data("hanzala/v2/cover-slot".utf8)

    private let objectStore: V2PoolObjectStore
    private let keyDeriver: DomainKeyDeriver

    public init(
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        keyDeriver: DomainKeyDeriver = DomainKeyDeriver()
    ) {
        self.objectStore = objectStore
        self.keyDeriver = keyDeriver
    }

    /// Fills every slot of `plan` that does not hold a cover yet. This writes
    /// the whole capacity to disk once. `progress` is called after each slot
    /// with (done, total). Only for creating a vault or resuming an
    /// interrupted creation: it returns an all-covered ledger, so it must not
    /// be called on a vault that already holds real objects.
    public func fill(
        plan: V2FixedCapacityPlan,
        masterKey: Data,
        in root: URL,
        progress: ((Int, Int) -> Void)? = nil
    ) throws -> V2CoverLedger {
        let namer = try coverNamer(masterKey: masterKey)
        let total = plan.slotCount
        var done = 0
        for slots in plan.slots {
            for index in 0..<slots.count {
                let name = namer(slots.plaintextByteCount, index)
                if objectStore.containsObject(named: name, in: root) {
                    // Objects are committed by atomic rename, so an existing
                    // name is a whole object; it must also have the bucket's size.
                    guard sealedByteCount(named: name, in: root) == Self.sealedByteCount(plaintext: slots.plaintextByteCount) else {
                        throw V2FixedCapacityPoolError.unexpectedObject
                    }
                } else {
                    try makeCover(named: name, plaintextByteCount: slots.plaintextByteCount, masterKey: masterKey, in: root)
                }
                done += 1
                progress?(done, total)
            }
        }
        return V2CoverLedger(fullFor: plan)
    }

    /// Stores `content` in a random free slot of the smallest bucket that fits
    /// it, replacing that slot's cover. If the right-sized bucket is used up,
    /// a larger slot is used rather than changing the pool's shape.
    public func store(
        kind: V2PoolObjectKind,
        content: Data,
        masterKey: Data,
        in root: URL,
        ledger: inout V2CoverLedger
    ) throws -> V2FixedCapacitySlotReference {
        guard kind == .data || kind == .manifest else {
            throw V2FixedCapacityPoolError.unsupportedKind
        }
        guard ledger.buckets.allSatisfy(\.isWellFormed) else {
            throw V2FixedCapacityPoolError.invalidSlotReference
        }
        let minimum: Int
        do {
            minimum = try V2DataObjectPaddingPolicy.targetPlaintextByteCount(forContentByteCount: content.count)
        } catch {
            throw V2FixedCapacityPoolError.contentTooLarge
        }
        let namer = try coverNamer(masterKey: masterKey)
        // A crash after an earlier swap removed a cover but before the ledger
        // was saved leaves a slot marked covered with no cover. Such slots are
        // skipped here; correcting the ledger belongs to reconciliation, so a
        // wrong key (no cover names match) cannot wipe the ledger.
        var choice: (bucketIndex: Int, slot: Int, coverName: String)?
        search: for bucketIndex in ledger.buckets.indices
            where ledger.buckets[bucketIndex].plaintextByteCount >= minimum {
            let bucket = ledger.buckets[bucketIndex]
            for slot in bucket.coveredSlotsInRandomOrder() {
                let name = namer(bucket.plaintextByteCount, slot)
                if objectStore.containsObject(named: name, in: root) {
                    choice = (bucketIndex, slot, name)
                    break search
                }
            }
        }
        guard let (bucketIndex, slot, coverName) = choice else {
            throw V2FixedCapacityPoolError.vaultFull
        }
        let plaintextByteCount = ledger.buckets[bucketIndex].plaintextByteCount

        let stored = try objectStore.createObject(
            kind: kind,
            content: content,
            masterKey: masterKey,
            in: root,
            paddedPlaintextByteCount: plaintextByteCount
        )
        do {
            try objectStore.deleteAuthenticatedObject(
                named: coverName,
                masterKey: masterKey,
                expectedKind: .padding,
                expectedLogicalByteCount: 0,
                in: root
            )
        } catch {
            // Leave the pool as it was: remove the object just written.
            do {
                try objectStore.deleteAuthenticatedObject(
                    named: stored.opaqueName,
                    masterKey: masterKey,
                    expectedKind: kind,
                    expectedLogicalByteCount: UInt64(content.count),
                    in: root
                )
            } catch {
                throw V2FixedCapacityPoolError.swapIncomplete
            }
            throw error
        }
        ledger.buckets[bucketIndex].setCover(false, at: slot)
        return V2FixedCapacitySlotReference(
            opaqueName: stored.opaqueName,
            kindRawValue: kind.rawValue,
            plaintextByteCount: plaintextByteCount,
            logicalByteCount: stored.logicalByteCount
        )
    }

    /// Frees a slot: writes a cover into a random empty slot of the same
    /// bucket, then removes the real object after authenticating it.
    public func release(
        _ reference: V2FixedCapacitySlotReference,
        masterKey: Data,
        in root: URL,
        ledger: inout V2CoverLedger
    ) throws {
        guard let kind = V2PoolObjectKind(rawValue: reference.kindRawValue),
              kind == .data || kind == .manifest,
              let bucketIndex = ledger.buckets.firstIndex(where: {
                  $0.plaintextByteCount == reference.plaintextByteCount
              }),
              ledger.buckets[bucketIndex].isWellFormed else {
            throw V2FixedCapacityPoolError.invalidSlotReference
        }
        let namer = try coverNamer(masterKey: masterKey)
        // A crash after an earlier release wrote a cover but before the ledger
        // was saved leaves a cover in a slot marked empty. A genuine cover
        // there is reused; anything else at that name is left alone.
        var chosen: (slot: Int, coverName: String)?
        for slot in ledger.buckets[bucketIndex].emptySlotsInRandomOrder() {
            let name = namer(reference.plaintextByteCount, slot)
            if !objectStore.containsObject(named: name, in: root) {
                try makeCover(named: name, plaintextByteCount: reference.plaintextByteCount, masterKey: masterKey, in: root)
                chosen = (slot, name)
                break
            }
            if isGenuineCover(named: name, plaintextByteCount: reference.plaintextByteCount, masterKey: masterKey, in: root) {
                chosen = (slot, name)
                break
            }
        }
        guard let (slot, coverName) = chosen else {
            throw V2FixedCapacityPoolError.invalidSlotReference
        }
        do {
            try objectStore.deleteAuthenticatedObject(
                named: reference.opaqueName,
                masterKey: masterKey,
                expectedKind: kind,
                expectedLogicalByteCount: reference.logicalByteCount,
                in: root
            )
        } catch {
            do {
                try objectStore.deleteAuthenticatedObject(
                    named: coverName,
                    masterKey: masterKey,
                    expectedKind: .padding,
                    expectedLogicalByteCount: 0,
                    in: root
                )
            } catch {
                throw V2FixedCapacityPoolError.swapIncomplete
            }
            throw error
        }
        ledger.buckets[bucketIndex].setCover(true, at: slot)
    }

    /// The opaque name of a slot's cover: HMAC-SHA256 under the access path's
    /// namespace key over a fixed label, the bucket size and the slot index.
    /// Without the key the names are indistinguishable from random ones.
    func coverNamer(masterKey: Data) throws -> (Int, Int) -> String {
        let namespaceKey: Data
        do {
            namespaceKey = try keyDeriver.derive(masterKey: masterKey, purpose: .namespaceV2)
        } catch {
            throw V2FixedCapacityPoolError.invalidMasterKeyLength
        }
        let key = SymmetricKey(data: namespaceKey)
        return { bucket, index in
            var message = Self.coverNameLabel
            message.append(0)
            for value in [UInt64(bucket), UInt64(index)] {
                withUnsafeBytes(of: value.bigEndian) { message.append(contentsOf: $0) }
            }
            let code = HMAC<SHA256>.authenticationCode(for: message, using: key)
            return Data(code).map { String(format: "%02x", $0) }.joined()
        }
    }

    static func sealedByteCount(plaintext: Int) -> UInt64 {
        UInt64(V2PoolObjectCodec.maximumEnvelopeByteCount - V2PoolObjectCodec.maximumPlaintextByteCount + plaintext)
    }

    private func sealedByteCount(named name: String, in root: URL) -> UInt64? {
        let path = V2StorageLayout.objectURL(named: name, in: root).path
        return (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? NSNumber)?.uint64Value
    }

    private func isGenuineCover(named name: String, plaintextByteCount: Int, masterKey: Data, in root: URL) -> Bool {
        guard sealedByteCount(named: name, in: root) == Self.sealedByteCount(plaintext: plaintextByteCount),
              let object = try? objectStore.readObject(named: name, masterKey: masterKey, in: root) else {
            return false
        }
        return object.kind == .padding && object.content.isEmpty
    }

    private func makeCover(named name: String, plaintextByteCount: Int, masterKey: Data, in root: URL) throws {
        _ = try objectStore.createObject(
            named: name,
            kind: .padding,
            content: Data(),
            masterKey: masterKey,
            in: root,
            paddedPlaintextByteCount: plaintextByteCount
        )
    }
}
