package com.hanzala.fortress.vault

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import java.util.UUID

/** §8.1 one file in an access path. */
data class VaultEntry(
    val id: UUID,
    val opaqueObjectName: String,
    val auxiliaryObjectNames: List<String>,
    val originalName: String,
    val logicalByteCount: Long,
    val createdAt: Instant,
) {
    val isChunked get() = auxiliaryObjectNames.isNotEmpty()

    /** Manifest (or data object) first, then the chunks in order. */
    val allObjectNames get() = listOf(opaqueObjectName) + auxiliaryObjectNames
}

/** §8.1 `V2StorageBudget`. */
data class StorageBudget(val totalBytes: Long, val reserveBytes: Long, val safetyMarginBytes: Long = 0) {
    val visibleWritableLimit get() = totalBytes - reserveBytes - safetyMarginBytes

    /** The same checks as Swift's initializer and decoder (§14.6). */
    fun validate() {
        if (totalBytes <= 0 || reserveBytes < 0 || safetyMarginBytes < 0 || reserveBytes >= totalBytes ||
            safetyMarginBytes > totalBytes - reserveBytes
        ) {
            throw VaultFormatException("bad budget")
        }
    }

    companion object {
        /**
         * The iPhone app's budget for both slots of a new vault: a 64 GiB
         * logical ceiling with a 256 MiB reserve (`MobileVaultModel.budget`).
         * The physical free-space guard still refuses what the device cannot hold.
         */
        val APP_DEFAULT = StorageBudget(64L * 1024 * 1024 * 1024, 256L * 1024 * 1024, 0)
    }
}

/** §8.1 `V2LogicalUsageLedger`. */
data class UsageLedger(val logicalBytes: Long = 0, val objectCount: Long = 0) {
    /** Swift `admittingObject`: refuses before any write when the budget would be exceeded. */
    fun admitting(byteCount: Long, budget: StorageBudget): UsageLedger {
        if (logicalBytes > budget.visibleWritableLimit) throw VaultFormatException("usage exceeds budget")
        val next = checkedAdd(logicalBytes, byteCount)
        if (next > budget.visibleWritableLimit) throw VaultFullException()
        return UsageLedger(next, checkedAdd(objectCount, 1))
    }

    /** Swift `removingObject`: fails closed instead of clamping. */
    fun removing(byteCount: Long): UsageLedger {
        if (objectCount <= 0 || byteCount > logicalBytes) throw VaultFormatException("usage underflow")
        return UsageLedger(logicalBytes - byteCount, objectCount - 1)
    }
}

/** §8.1 `CoverSlot`: one slot of a fixed-capacity pool. */
data class CoverSlot(val bucketPlaintextByteCount: Long, val index: Long)

/** One bucket of the cover ledger. Bit `i` set: slot `i` holds a free cover (§8.1). */
class CoverLedgerBucket(val plaintextByteCount: Long, val slotCount: Long, coverBitmap: ByteArray) {
    private val bitmap = coverBitmap.copyOf()

    val coverBitmap: ByteArray get() = bitmap.copyOf()

    val isWellFormed get() = slotCount > 0 && bitmap.size.toLong() == (slotCount + 7) / 8

    fun hasCover(index: Long) = (bitmap[(index / 8).toInt()].toInt() and (1 shl (index % 8).toInt())) != 0

    val freeSlotCount: Long get() = (0 until slotCount).count { hasCover(it) }.toLong()

    fun coveredSlots(): List<Long> = (0 until slotCount).filter { hasCover(it) }

    fun emptySlots(): List<Long> = (0 until slotCount).filter { !hasCover(it) }

    internal fun with(covered: Boolean, index: Long): CoverLedgerBucket {
        val next = bitmap.copyOf()
        val i = (index / 8).toInt()
        val mask = 1 shl (index % 8).toInt()
        next[i] = (if (covered) next[i].toInt() or mask else next[i].toInt() and mask.inv()).toByte()
        return CoverLedgerBucket(plaintextByteCount, slotCount, next)
    }

    override fun equals(other: Any?) = other is CoverLedgerBucket && other.plaintextByteCount == plaintextByteCount &&
        other.slotCount == slotCount && other.bitmap.contentEquals(bitmap)

    override fun hashCode() = 31 * (31 * plaintextByteCount.hashCode() + slotCount.hashCode()) + bitmap.contentHashCode()
}

/** §11 `V2CoverLedger`, smallest bucket first. */
data class CoverLedger(val buckets: List<CoverLedgerBucket>) {
    val freeSlotCount get() = buckets.sumOf { it.freeSlotCount }
    val freePlaintextBytes get() = buckets.sumOf { it.plaintextByteCount * it.freeSlotCount }

    fun matches(plan: List<FixedCapacityPlan.Bucket>) = buckets.size == plan.size &&
        buckets.zip(plan).all { (b, p) -> b.isWellFormed && b.plaintextByteCount == p.plaintextByteCount && b.slotCount == p.slotCount }

    fun bucket(size: Long) = buckets.firstOrNull { it.plaintextByteCount == size }

    operator fun contains(slot: CoverSlot): Boolean {
        val bucket = bucket(slot.bucketPlaintextByteCount) ?: return false
        return slot.index >= 0 && slot.index < bucket.slotCount
    }

    fun hasCover(slot: CoverSlot) = slot in this && bucket(slot.bucketPlaintextByteCount)!!.hasCover(slot.index)

    fun setting(covered: Boolean, slots: List<CoverSlot>): CoverLedger {
        var next = buckets
        for (slot in slots) {
            if (slot !in this) throw VaultFormatException("invalid cover slot")
            next = next.map { if (it.plaintextByteCount == slot.bucketPlaintextByteCount) it.with(covered, slot.index) else it }
        }
        return CoverLedger(next)
    }

    companion object {
        /** Every slot of [plan] holds a cover. */
        fun fullFor(plan: List<FixedCapacityPlan.Bucket>) = CoverLedger(
            plan.map { p ->
                var bucket = CoverLedgerBucket(p.plaintextByteCount, p.slotCount, ByteArray(((p.slotCount + 7) / 8).toInt()))
                for (i in 0 until p.slotCount) bucket = bucket.with(true, i)
                bucket
            },
        )
    }
}

/** §8.1 `FixedCapacityState`. */
data class FixedCapacityState(val capacityBytes: Long, val isFilled: Boolean, val ledger: CoverLedger) {
    fun plan() = FixedCapacityPlan.slots(capacityBytes)

    internal fun with(ledger: CoverLedger) = FixedCapacityState(capacityBytes, isFilled, ledger)
}

/** §8.1 a pending single-object import claim. */
data class PendingImport(
    val transactionID: UUID,
    val opaqueObjectName: String,
    val originalName: String,
    val logicalByteCount: Long,
    val createdAt: Instant,
    /** Fixed-capacity vaults only: the slot whose cover this import replaces. */
    val coverSlot: CoverSlot? = null,
)

data class PendingChunkObject(val opaqueObjectName: String, val logicalByteCount: Long)

/** §8.1 a pending chunked import claim; the transaction ID becomes the manifest file ID and the entry ID. */
class PendingChunkImport(
    val transactionID: UUID,
    val manifestObjectName: String,
    val originalName: String,
    val logicalByteCount: Long,
    val chunks: List<PendingChunkObject>,
    sha256Digest: ByteArray,
    val createdAt: Instant,
    /** Fixed-capacity vaults only: one slot per object, manifest first then chunks. */
    val coverSlots: List<CoverSlot>? = null,
) {
    private val digest = sha256Digest.copyOf()
    val sha256Digest: ByteArray get() = digest.copyOf()

    val allObjectNames get() = listOf(manifestObjectName) + chunks.map { it.opaqueObjectName }

    fun manifest() = ChunkManifest(transactionID, chunks.map { it.opaqueObjectName to it.logicalByteCount }, logicalByteCount, digest)

    fun withCoverSlots(slots: List<CoverSlot>?) =
        PendingChunkImport(transactionID, manifestObjectName, originalName, logicalByteCount, chunks, digest, createdAt, slots)
}

/** §8.1 a committed removal waiting for its objects to be deleted. */
data class PendingRemoval(
    val transactionID: UUID,
    val entryID: UUID,
    val opaqueObjectName: String,
    val auxiliaryObjectNames: List<String>,
    val logicalByteCount: Long,
    val createdAt: Instant,
    /** Fixed-capacity vaults only: the empty slot receiving each object's cover, in [allObjectNames] order. */
    val coverSlots: List<CoverSlot>? = null,
) {
    val allObjectNames get() = listOf(opaqueObjectName) + auxiliaryObjectNames
}

/**
 * §8 access metadata of one access path: every field, so a writer can round
 * trip it. [encode] produces the exact bytes Swift's `V2AccessMetadataStore`
 * writes (`.sortedKeys`, slashes escaped, §14.5).
 *
 * The transitions mirror Swift's `V2AccessMetadata` one for one: each validates
 * the current value, builds the next generation (+1) and validates it.
 */
class AccessMetadata(
    val accessID: UUID,
    val generation: Long,
    val entries: List<VaultEntry>,
    val budget: StorageBudget,
    val usage: UsageLedger = UsageLedger(),
    val pendingImports: List<PendingImport> = emptyList(),
    val pendingChunkImports: List<PendingChunkImport> = emptyList(),
    val pendingRemovals: List<PendingRemoval> = emptyList(),
    val tombstonedObjectNames: List<String> = emptyList(),
    /** Present only when fixed capacity is on (never encoded otherwise). */
    val fixedCapacity: FixedCapacityState? = null,
    val formatVersion: Long = FORMAT_VERSION,
) {
    val logicalBytes get() = usage.logicalBytes
    val objectCount get() = usage.objectCount
    val fixedCapacityBytes get() = fixedCapacity?.capacityBytes

    val hasPendingWork get() = pendingImports.isNotEmpty() || pendingChunkImports.isNotEmpty() || pendingRemovals.isNotEmpty()

    /** Every name this access path owns (live, pending, removing, tombstoned). */
    val ownedObjectNames: Set<String>
        get() = buildSet {
            entries.forEach { addAll(it.allObjectNames) }
            pendingImports.forEach { add(it.opaqueObjectName) }
            pendingChunkImports.forEach { addAll(it.allObjectNames) }
            pendingRemovals.forEach { addAll(it.allObjectNames) }
            addAll(tombstonedObjectNames)
        }

    /** Cover slots held by pending transactions. */
    val reservedCoverSlots: Set<CoverSlot>
        get() = buildSet {
            pendingImports.forEach { it.coverSlot?.let(::add) }
            pendingChunkImports.forEach { addAll(it.coverSlots ?: emptyList()) }
            pendingRemovals.forEach { addAll(it.coverSlots ?: emptyList()) }
        }

    /** Byte-equal metadata (Swift compares decoded values; every field round trips). */
    fun sameAs(other: AccessMetadata) = encode().contentEquals(other.encode())

    /** §8.1/§9: the JSON Swift writes for this value. */
    fun encode(): ByteArray {
        val fields = linkedMapOf<String, JsonElement>(
            "formatVersion" to JsonPrimitive(formatVersion),
            "accessID" to JsonPrimitive(Uuids.upper(accessID)),
            "generation" to JsonPrimitive(generation),
            "entries" to JsonArray(entries.map(::entryJson)),
            "pendingImports" to JsonArray(pendingImports.map(::pendingImportJson)),
            "pendingChunkImports" to JsonArray(pendingChunkImports.map(::pendingChunkImportJson)),
            "pendingRemovals" to JsonArray(pendingRemovals.map(::pendingRemovalJson)),
            "tombstonedObjectNames" to JsonArray(tombstonedObjectNames.map(::JsonPrimitive)),
            "budget" to obj(
                "totalBytes" to JsonPrimitive(budget.totalBytes),
                "reserveBytes" to JsonPrimitive(budget.reserveBytes),
                "safetyMarginBytes" to JsonPrimitive(budget.safetyMarginBytes),
            ),
            "usage" to obj("logicalBytes" to JsonPrimitive(usage.logicalBytes), "objectCount" to JsonPrimitive(usage.objectCount)),
        )
        fixedCapacity?.let { fields["fixedCapacity"] = fixedCapacityJson(it) }
        return SwiftJson.encode(JsonObject(fields), escapeSlashes = true)
    }

    /** Swift `V2AccessMetadata.validate` (§8.2). */
    fun validate() {
        if (formatVersion != FORMAT_VERSION) throw VaultFormatException("unsupported metadata version")
        budget.validate()

        val entryIDs = HashSet<UUID>()
        val liveNames = HashSet<String>()
        var liveBytes = 0L
        for (entry in entries) {
            if (!entryIDs.add(entry.id)) throw VaultFormatException("duplicate entry ID")
            validateOriginalName(entry.originalName)
            for (name in entry.allObjectNames) {
                if (!V2Format.isObjectName(name)) throw VaultFormatException("bad object name in metadata")
                if (!liveNames.add(name)) throw VaultFormatException("object owned twice")
            }
            liveBytes = add(liveBytes, entry.logicalByteCount)
        }

        val tombstones = HashSet<String>()
        for (name in tombstonedObjectNames) {
            if (!V2Format.isObjectName(name)) throw VaultFormatException("bad object name in metadata")
            if (!tombstones.add(name) || name in liveNames) throw VaultFormatException("bad tombstone")
        }

        val transactionIDs = HashSet<UUID>()
        val pendingNames = HashSet<String>()
        var pendingBytes = 0L
        fun reserve(name: String) {
            if (!V2Format.isObjectName(name)) throw VaultFormatException("bad object name in metadata")
            if (name in liveNames || !pendingNames.add(name)) throw VaultFormatException("object owned twice")
            if (name in tombstones) throw VaultFormatException("pending object is tombstoned")
        }
        for (p in pendingImports) {
            if (!transactionIDs.add(p.transactionID)) throw VaultFormatException("duplicate transaction")
            reserve(p.opaqueObjectName)
            validateOriginalName(p.originalName)
            pendingBytes = add(pendingBytes, p.logicalByteCount)
        }
        for (p in pendingChunkImports) {
            if (!transactionIDs.add(p.transactionID)) throw VaultFormatException("duplicate transaction")
            validateOriginalName(p.originalName)
            val m = p.manifest()
            ChunkManifest.validate(m.chunks, m.logicalByteCount, m.sha256Digest)
            p.allObjectNames.forEach(::reserve)
            pendingBytes = add(pendingBytes, p.logicalByteCount)
        }

        // A committed removal has already left `entries`; its objects wait for deletion.
        val removalEntryIDs = HashSet<UUID>()
        val removalNames = HashSet<String>()
        var removalBytes = 0L
        for (p in pendingRemovals) {
            if (!transactionIDs.add(p.transactionID)) throw VaultFormatException("duplicate transaction")
            if (p.entryID in entryIDs || !removalEntryIDs.add(p.entryID)) throw VaultFormatException("duplicate removal")
            for (name in p.allObjectNames) {
                if (!V2Format.isObjectName(name)) throw VaultFormatException("bad object name in metadata")
                if (name in liveNames || name in pendingNames || name in tombstones || !removalNames.add(name)) {
                    throw VaultFormatException("removal conflicts with another object")
                }
            }
            removalBytes = add(removalBytes, p.logicalByteCount)
        }

        if (usage.logicalBytes != liveBytes || usage.objectCount != entries.size.toLong()) throw VaultFormatException("usage mismatch")
        if (add(add(usage.logicalBytes, pendingBytes), removalBytes) > budget.visibleWritableLimit) {
            throw VaultFormatException("usage exceeds budget")
        }
        validateFixedCapacity(liveNames.size + pendingNames.size + removalNames.size)
    }

    /**
     * Every slot holds either a free cover (its ledger bit is set) or exactly
     * one owned object, and each pending transaction reserves one distinct,
     * non-free slot per object (Swift `validateFixedCapacity`).
     */
    private fun validateFixedCapacity(ownedObjectCount: Int) {
        val reservations: List<Pair<List<CoverSlot>?, Int>> =
            pendingImports.map { p -> p.coverSlot?.let { listOf(it) } to 1 } +
                pendingChunkImports.map { it.coverSlots to it.allObjectNames.size } +
                pendingRemovals.map { it.coverSlots to it.allObjectNames.size }
        val state = fixedCapacity
        if (state == null) {
            if (reservations.any { it.first != null }) throw VaultFormatException("cover slot without fixed capacity")
            return
        }
        val plan = try {
            state.plan()
        } catch (e: VaultFormatException) {
            throw VaultFormatException("invalid fixed capacity")
        }
        if (!state.ledger.matches(plan) || tombstonedObjectNames.isNotEmpty()) throw VaultFormatException("invalid fixed capacity")
        val planSlots = plan.sumOf { it.slotCount }
        if (!state.isFilled && (ownedObjectCount != 0 || state.ledger.freeSlotCount != planSlots)) {
            throw VaultFormatException("invalid fixed capacity")
        }
        val reserved = HashSet<CoverSlot>()
        for ((slots, objectCount) in reservations) {
            if (slots == null || slots.size != objectCount) throw VaultFormatException("cover slot conflict")
            for (slot in slots) {
                if (slot !in state.ledger || state.ledger.hasCover(slot) || !reserved.add(slot)) {
                    throw VaultFormatException("cover slot conflict")
                }
            }
        }
        if (state.ledger.freeSlotCount + ownedObjectCount != planSlots) throw VaultFormatException("cover count mismatch")
    }

    // Transitions (Swift `V2AccessMetadata`).

    fun beginningImport(pending: PendingImport): AccessMetadata {
        validate()
        requireNewTransaction(pending.transactionID)
        if (pending.opaqueObjectName in ownedObjectNames) throw CandidateNameTakenException()
        admitPending(pending.logicalByteCount)
        return next(
            pendingImports = pendingImports + pending,
            fixedCapacity = fixedCapacityTaking(pending.coverSlot?.let { listOf(it) }),
        )
    }

    fun finalizingImport(transactionID: UUID): AccessMetadata {
        validate()
        val p = pendingImports.firstOrNull { it.transactionID == transactionID } ?: throw VaultFormatException("transaction not found")
        val entry = VaultEntry(p.transactionID, p.opaqueObjectName, emptyList(), p.originalName, p.logicalByteCount, p.createdAt)
        return next(
            entries = entries + entry,
            pendingImports = pendingImports.filter { it.transactionID != transactionID },
            usage = usage.admitting(p.logicalByteCount, budget),
        )
    }

    fun abortingImport(transactionID: UUID): AccessMetadata {
        validate()
        val p = pendingImports.firstOrNull { it.transactionID == transactionID } ?: throw VaultFormatException("transaction not found")
        return next(
            pendingImports = pendingImports.filter { it.transactionID != transactionID },
            fixedCapacity = fixedCapacityReturning(p.coverSlot?.let { listOf(it) }),
        )
    }

    fun beginningChunkImport(pending: PendingChunkImport): AccessMetadata {
        validate()
        requireNewTransaction(pending.transactionID)
        val owned = ownedObjectNames
        if (pending.allObjectNames.any { it in owned }) throw CandidateNameTakenException()
        admitPending(pending.logicalByteCount)
        return next(
            pendingChunkImports = pendingChunkImports + pending,
            fixedCapacity = fixedCapacityTaking(pending.coverSlots),
        )
    }

    fun finalizingChunkImport(transactionID: UUID): AccessMetadata {
        validate()
        val p = pendingChunkImports.firstOrNull { it.transactionID == transactionID }
            ?: throw VaultFormatException("transaction not found")
        val entry = VaultEntry(
            p.transactionID, p.manifestObjectName, p.chunks.map { it.opaqueObjectName }, p.originalName, p.logicalByteCount, p.createdAt,
        )
        return next(
            entries = entries + entry,
            pendingChunkImports = pendingChunkImports.filter { it.transactionID != transactionID },
            usage = usage.admitting(p.logicalByteCount, budget),
        )
    }

    fun abortingChunkImport(transactionID: UUID): AccessMetadata {
        validate()
        val p = pendingChunkImports.firstOrNull { it.transactionID == transactionID }
            ?: throw VaultFormatException("transaction not found")
        return next(
            pendingChunkImports = pendingChunkImports.filter { it.transactionID != transactionID },
            fixedCapacity = fixedCapacityReturning(p.coverSlots),
        )
    }

    /** Single-object entries only; chunked entries go through [beginningChunkedRemoval]. */
    fun beginningRemoval(entryID: UUID, transactionID: UUID, createdAt: Instant, coverSlots: List<CoverSlot>?): AccessMetadata {
        validate()
        requireRemovalAvailable(entryID, transactionID)
        val entry = entries.firstOrNull { it.id == entryID } ?: throw EntryNotFoundException()
        if (entry.isChunked) throw VaultFormatException("chunked removal needs its manifest")
        return beginningRemoval(entry, transactionID, emptyList(), createdAt, coverSlots)
    }

    /** The names must equal the live entry's authenticated chunk list. */
    fun beginningChunkedRemoval(
        entryID: UUID,
        transactionID: UUID,
        auxiliaryObjectNames: List<String>,
        createdAt: Instant,
        coverSlots: List<CoverSlot>?,
    ): AccessMetadata {
        validate()
        requireRemovalAvailable(entryID, transactionID)
        val entry = entries.firstOrNull { it.id == entryID } ?: throw EntryNotFoundException()
        if (!entry.isChunked) throw VaultFormatException("not a chunked entry")
        if (entry.auxiliaryObjectNames != auxiliaryObjectNames) throw VaultFormatException("removal plan mismatch")
        return beginningRemoval(entry, transactionID, auxiliaryObjectNames, createdAt, coverSlots)
    }

    fun finalizingRemoval(transactionID: UUID): AccessMetadata {
        validate()
        val p = pendingRemovals.firstOrNull { it.transactionID == transactionID } ?: throw VaultFormatException("transaction not found")
        return next(
            pendingRemovals = pendingRemovals.filter { it.transactionID != transactionID },
            fixedCapacity = fixedCapacityReturning(p.coverSlots),
        )
    }

    /** Fixed capacity for a new, empty access path; `isFilled` stays false until the covers are on disk. */
    fun beginningFixedCapacity(capacityBytes: Long): AccessMetadata {
        validate()
        if (fixedCapacity != null || entries.isNotEmpty() || hasPendingWork || tombstonedObjectNames.isNotEmpty()) {
            throw VaultFormatException("fixed capacity unavailable")
        }
        val plan = FixedCapacityPlan.slots(capacityBytes)
        return AccessMetadata(accessID, nextGeneration(), emptyList(), budget, usage,
            fixedCapacity = FixedCapacityState(capacityBytes, false, CoverLedger.fullFor(plan))).also { it.validate() }
    }

    /** Records that every cover of the plan is on disk. */
    fun completingFixedCapacityFill(): AccessMetadata {
        validate()
        val state = fixedCapacity
        if (state == null || state.isFilled) throw VaultFormatException("fixed capacity unavailable")
        return AccessMetadata(accessID, nextGeneration(), emptyList(), budget, usage,
            fixedCapacity = FixedCapacityState(state.capacityBytes, true, state.ledger)).also { it.validate() }
    }

    private fun beginningRemoval(
        entry: VaultEntry,
        transactionID: UUID,
        auxiliary: List<String>,
        createdAt: Instant,
        coverSlots: List<CoverSlot>?,
    ): AccessMetadata {
        // The slots stay marked empty until the removal finalizes.
        if ((fixedCapacity == null) != (coverSlots == null)) throw VaultFormatException("cover slot mismatch")
        val removal = PendingRemoval(
            transactionID, entry.id, entry.opaqueObjectName, auxiliary, entry.logicalByteCount, createdAt, coverSlots,
        )
        return next(
            entries = entries.filter { it.id != entry.id },
            pendingRemovals = pendingRemovals + removal,
            usage = usage.removing(entry.logicalByteCount),
        )
    }

    private fun requireNewTransaction(id: UUID) {
        if (pendingImports.any { it.transactionID == id } || pendingChunkImports.any { it.transactionID == id } ||
            pendingRemovals.any { it.transactionID == id }
        ) {
            throw VaultFormatException("transaction already exists")
        }
    }

    private fun requireRemovalAvailable(entryID: UUID, transactionID: UUID) {
        requireNewTransaction(transactionID)
        if (pendingRemovals.any { it.entryID == entryID }) throw VaultFormatException("removal already pending")
    }

    /**
     * A claim that would not fit the budget is refused as "vault full" before
     * any write (Swift fails the same claim through `validate`).
     */
    private fun admitPending(byteCount: Long) {
        val reserved = add(add(add(usage.logicalBytes, pendingImports.sumOf { it.logicalByteCount }),
            pendingChunkImports.sumOf { it.logicalByteCount }), pendingRemovals.sumOf { it.logicalByteCount })
        if (add(reserved, byteCount) > budget.visibleWritableLimit) throw VaultFullException()
    }

    /** Takes free slots out of the ledger for a new import claim. */
    private fun fixedCapacityTaking(slots: List<CoverSlot>?): FixedCapacityState? {
        val state = fixedCapacity
        if (state == null) {
            if (slots != null) throw VaultFormatException("cover slot mismatch")
            return null
        }
        if (!state.isFilled) throw VaultFormatException("fixed capacity not filled")
        if (slots == null || slots.toSet().size != slots.size || !slots.all { state.ledger.hasCover(it) }) {
            throw VaultFormatException("cover slot mismatch")
        }
        return state.with(state.ledger.setting(false, slots))
    }

    /** Marks a finished transaction's slots as holding a free cover again. */
    private fun fixedCapacityReturning(slots: List<CoverSlot>?): FixedCapacityState? {
        val state = fixedCapacity ?: return null
        if (slots == null) throw VaultFormatException("cover slot mismatch")
        return state.with(state.ledger.setting(true, slots))
    }

    private fun nextGeneration() = try {
        Math.addExact(generation, 1L)
    } catch (e: ArithmeticException) {
        throw VaultFormatException("generation overflow")
    }

    private fun next(
        entries: List<VaultEntry> = this.entries,
        pendingImports: List<PendingImport> = this.pendingImports,
        pendingChunkImports: List<PendingChunkImport> = this.pendingChunkImports,
        pendingRemovals: List<PendingRemoval> = this.pendingRemovals,
        usage: UsageLedger = this.usage,
        fixedCapacity: FixedCapacityState? = this.fixedCapacity,
    ) = AccessMetadata(
        accessID, nextGeneration(), entries, budget, usage, pendingImports, pendingChunkImports, pendingRemovals,
        tombstonedObjectNames, fixedCapacity,
    ).also { it.validate() }

    companion object {
        const val FORMAT_VERSION = 1L

        /** Parses and runs every check of Swift's `V2AccessMetadata.validate` (§8.2). */
        fun parse(bytes: ByteArray): AccessMetadata = decode(bytes).also { it.validate() }

        /** Swift's decoder: missing pending lists and `auxiliaryObjectNames` read as empty. */
        private fun decode(bytes: ByteArray): AccessMetadata {
            val json = JsonFields(SwiftJson.parse(bytes), "metadata")
            val formatVersion = json.unsigned("formatVersion")
            if (formatVersion != FORMAT_VERSION) throw VaultFormatException("unsupported metadata version")
            val entries = json.objects("entries").map { e ->
                VaultEntry(
                    id = e.uuid("id"),
                    opaqueObjectName = e.string("opaqueObjectName"),
                    auxiliaryObjectNames = e.strings("auxiliaryObjectNames", optional = true),
                    originalName = e.string("originalName"),
                    logicalByteCount = e.unsigned("logicalByteCount"),
                    createdAt = e.date("createdAt"),
                )
            }
            val pendingImports = json.objects("pendingImports", optional = true).map { p ->
                PendingImport(
                    transactionID = p.uuid("transactionID"),
                    opaqueObjectName = p.string("opaqueObjectName"),
                    originalName = p.string("originalName"),
                    logicalByteCount = p.unsigned("logicalByteCount"),
                    createdAt = p.date("createdAt"),
                    coverSlot = if (p.present("coverSlot")) coverSlot(p.obj("coverSlot")) else null,
                )
            }
            val pendingChunkImports = json.objects("pendingChunkImports", optional = true).map { p ->
                PendingChunkImport(
                    transactionID = p.uuid("transactionID"),
                    manifestObjectName = p.string("manifestObjectName"),
                    originalName = p.string("originalName"),
                    logicalByteCount = p.unsigned("logicalByteCount"),
                    chunks = p.objects("chunks").map { PendingChunkObject(it.string("opaqueObjectName"), it.unsigned("logicalByteCount")) },
                    sha256Digest = p.bytes("sha256Digest"),
                    createdAt = p.date("createdAt"),
                    coverSlots = coverSlots(p),
                )
            }
            val pendingRemovals = json.objects("pendingRemovals", optional = true).map { p ->
                PendingRemoval(
                    transactionID = p.uuid("transactionID"),
                    entryID = p.uuid("entryID"),
                    opaqueObjectName = p.string("opaqueObjectName"),
                    auxiliaryObjectNames = p.strings("auxiliaryObjectNames", optional = true),
                    logicalByteCount = p.unsigned("logicalByteCount"),
                    createdAt = p.date("createdAt"),
                    coverSlots = coverSlots(p),
                )
            }
            val tombstoned = json.strings("tombstonedObjectNames")
            val b = json.obj("budget")
            val budget = StorageBudget(b.unsigned("totalBytes"), b.unsigned("reserveBytes"), b.unsigned("safetyMarginBytes"))
            budget.validate()
            val u = json.obj("usage")
            val usage = UsageLedger(u.unsigned("logicalBytes"), u.unsigned("objectCount"))
            val fixedCapacity = if (json.present("fixedCapacity")) {
                val fc = json.obj("fixedCapacity")
                FixedCapacityState(
                    capacityBytes = fc.unsigned("capacityBytes"),
                    isFilled = fc.bool("isFilled"),
                    ledger = CoverLedger(
                        fc.obj("ledger").objects("buckets").map {
                            CoverLedgerBucket(it.unsigned("plaintextByteCount"), it.unsigned("slotCount"), it.bytes("coverBitmap"))
                        },
                    ),
                )
            } else {
                null
            }
            return AccessMetadata(
                accessID = json.uuid("accessID"),
                generation = json.unsigned("generation"),
                entries = entries,
                budget = budget,
                usage = usage,
                pendingImports = pendingImports,
                pendingChunkImports = pendingChunkImports,
                pendingRemovals = pendingRemovals,
                tombstonedObjectNames = tombstoned,
                fixedCapacity = fixedCapacity,
                formatVersion = formatVersion,
            )
        }

        private fun coverSlot(slot: JsonFields) = CoverSlot(slot.unsigned("bucketPlaintextByteCount"), slot.unsigned("index"))

        private fun coverSlots(p: JsonFields): List<CoverSlot>? =
            if (p.present("coverSlots")) p.objects("coverSlots").map(::coverSlot) else null

        fun validateOriginalName(name: String) {
            if (name.isEmpty() || name == "." || name == ".." || name.any { it == '/' || it == '\\' || it == '\u0000' }) {
                throw VaultFormatException("bad original name")
            }
        }

        private fun add(a: Long, b: Long): Long = checkedAdd(a, b)

        private fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(mapOf(*fields))

        private fun date(instant: Instant) = JsonPrimitive(Codings.formatDate(instant))

        private fun strings(names: List<String>) = JsonArray(names.map(::JsonPrimitive))

        private fun coverSlotJson(slot: CoverSlot) =
            obj("bucketPlaintextByteCount" to JsonPrimitive(slot.bucketPlaintextByteCount), "index" to JsonPrimitive(slot.index))

        private fun entryJson(e: VaultEntry) = obj(
            "id" to JsonPrimitive(Uuids.upper(e.id)),
            "opaqueObjectName" to JsonPrimitive(e.opaqueObjectName),
            "auxiliaryObjectNames" to strings(e.auxiliaryObjectNames),
            "originalName" to JsonPrimitive(e.originalName),
            "logicalByteCount" to JsonPrimitive(e.logicalByteCount),
            "createdAt" to date(e.createdAt),
        )

        private fun pendingImportJson(p: PendingImport): JsonObject {
            val fields = linkedMapOf<String, JsonElement>(
                "transactionID" to JsonPrimitive(Uuids.upper(p.transactionID)),
                "opaqueObjectName" to JsonPrimitive(p.opaqueObjectName),
                "originalName" to JsonPrimitive(p.originalName),
                "logicalByteCount" to JsonPrimitive(p.logicalByteCount),
                "createdAt" to date(p.createdAt),
            )
            p.coverSlot?.let { fields["coverSlot"] = coverSlotJson(it) }
            return JsonObject(fields)
        }

        private fun pendingChunkImportJson(p: PendingChunkImport): JsonObject {
            val fields = linkedMapOf<String, JsonElement>(
                "transactionID" to JsonPrimitive(Uuids.upper(p.transactionID)),
                "manifestObjectName" to JsonPrimitive(p.manifestObjectName),
                "originalName" to JsonPrimitive(p.originalName),
                "logicalByteCount" to JsonPrimitive(p.logicalByteCount),
                "chunks" to JsonArray(p.chunks.map {
                    obj("opaqueObjectName" to JsonPrimitive(it.opaqueObjectName), "logicalByteCount" to JsonPrimitive(it.logicalByteCount))
                }),
                "sha256Digest" to JsonPrimitive(Codings.base64(p.sha256Digest)),
                "createdAt" to date(p.createdAt),
            )
            p.coverSlots?.let { slots -> fields["coverSlots"] = JsonArray(slots.map(::coverSlotJson)) }
            return JsonObject(fields)
        }

        private fun pendingRemovalJson(p: PendingRemoval): JsonObject {
            val fields = linkedMapOf<String, JsonElement>(
                "transactionID" to JsonPrimitive(Uuids.upper(p.transactionID)),
                "entryID" to JsonPrimitive(Uuids.upper(p.entryID)),
                "opaqueObjectName" to JsonPrimitive(p.opaqueObjectName),
                "auxiliaryObjectNames" to strings(p.auxiliaryObjectNames),
                "logicalByteCount" to JsonPrimitive(p.logicalByteCount),
                "createdAt" to date(p.createdAt),
            )
            p.coverSlots?.let { slots -> fields["coverSlots"] = JsonArray(slots.map(::coverSlotJson)) }
            return JsonObject(fields)
        }

        private fun fixedCapacityJson(fc: FixedCapacityState) = obj(
            "capacityBytes" to JsonPrimitive(fc.capacityBytes),
            "isFilled" to JsonPrimitive(fc.isFilled),
            "ledger" to obj(
                "buckets" to JsonArray(fc.ledger.buckets.map {
                    obj(
                        "plaintextByteCount" to JsonPrimitive(it.plaintextByteCount),
                        "slotCount" to JsonPrimitive(it.slotCount),
                        "coverBitmap" to JsonPrimitive(Codings.base64(it.coverBitmap)),
                    )
                }),
            ),
        )
    }
}

/** §10 chunk manifest. */
class ChunkManifest(
    val fileID: UUID,
    val chunks: List<Pair<String, Long>>,
    val logicalByteCount: Long,
    val sha256Digest: ByteArray,
) {
    /** §10 JSON (`.sortedKeys`, `.withoutEscapingSlashes`). */
    fun encode(): ByteArray = SwiftJson.encode(
        JsonObject(
            mapOf(
                "chunks" to JsonArray(chunks.map { (name, length) ->
                    JsonObject(mapOf("logicalByteCount" to JsonPrimitive(length), "opaqueObjectName" to JsonPrimitive(name)))
                }),
                "fileID" to JsonPrimitive(Uuids.upper(fileID)),
                "formatVersion" to JsonPrimitive(1),
                "logicalByteCount" to JsonPrimitive(logicalByteCount),
                "sha256Digest" to JsonPrimitive(Codings.base64(sha256Digest)),
            ),
        ),
        escapeSlashes = false,
    )

    fun sameAs(other: ChunkManifest) = fileID == other.fileID && chunks == other.chunks &&
        logicalByteCount == other.logicalByteCount && sha256Digest.contentEquals(other.sha256Digest)

    companion object {
        fun parse(bytes: ByteArray): ChunkManifest {
            val json = JsonFields(SwiftJson.parse(bytes), "manifest")
            if (json.unsigned("formatVersion") != 1L) throw VaultFormatException("unsupported manifest version")
            val fileID = json.uuid("fileID")
            val chunks = json.objects("chunks").map { it.string("opaqueObjectName") to it.unsigned("logicalByteCount") }
            val total = json.unsigned("logicalByteCount")
            val digest = json.bytes("sha256Digest")
            validate(chunks, total, digest)
            return ChunkManifest(fileID, chunks, total, digest)
        }

        /** Swift `V2ChunkManifest.validate`. */
        fun validate(chunks: List<Pair<String, Long>>, logicalByteCount: Long, sha256Digest: ByteArray) {
            if (chunks.size < 2 || chunks.size > V2Format.MAX_CHUNKS || sha256Digest.size != 32 ||
                logicalByteCount <= V2Format.MAX_SINGLE_CONTENT
            ) {
                throw VaultFormatException("bad chunk manifest")
            }
            val names = HashSet<String>()
            var total = 0L
            chunks.forEachIndexed { index, (name, length) ->
                if (!V2Format.isObjectName(name) || !names.add(name) ||
                    length !in 1..V2Format.CHUNK_CONTENT.toLong() ||
                    (index < chunks.size - 1 && length != V2Format.CHUNK_CONTENT.toLong())
                ) {
                    throw VaultFormatException("bad chunk manifest")
                }
                total += length
            }
            if (total != logicalByteCount) throw VaultFormatException("bad chunk manifest")
        }
    }
}

/** Not enough room: the fixed-capacity vault has no free slot (or metadata room), or the budget is used up. */
class VaultFullException : Exception("the vault is full")

/** The entry is not (or no longer) in this access path. */
class EntryNotFoundException : Exception("entry not found")

/** A randomly chosen name is already owned or present; the caller picks another. */
internal class CandidateNameTakenException : Exception("object name already taken")

internal fun checkedAdd(a: Long, b: Long): Long = try {
    Math.addExact(a, b)
} catch (e: ArithmeticException) {
    throw VaultFormatException("size overflow")
}

internal fun JsonFields.present(key: String) = has(key) && raw(key) !is JsonNull
