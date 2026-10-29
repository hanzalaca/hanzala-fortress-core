package com.hanzala.fortress.vault

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID

/** §2 staging name prefixes (`<prefix><UUID_UPPER>.tmp`). */
internal object StagingPrefix {
    const val ENVELOPE = ".hanzala-v2-envelope-stage-"
    const val METADATA = ".hanzala-v2-metadata-stage-"
    const val OBJECT = ".hanzala-v2-stage-"
}

/** Cut points of a durable commit, for crash-simulation tests (Swift `V2DurableCommitCrashPoint`). */
enum class CrashPoint { AFTER_STAGING_CREATE, AFTER_STAGING_WRITE, AFTER_STAGING_SYNC, AFTER_NAMESPACE_COMMIT, AFTER_NAMESPACE_DELETE }

/**
 * Called at every [CrashPoint]. Tests throw [SimulatedCrash] to model power
 * loss; production writers never install one.
 */
fun interface FaultInjector {
    fun reached(point: CrashPoint, destination: Path)
}

/** Simulated process death: no cooperative cleanup runs after it (it is an [Error], not an [Exception]). */
class SimulatedCrash(val point: CrashPoint) : Error("simulated power loss at $point")

private val NOFOLLOW = arrayOf(LinkOption.NOFOLLOW_LINKS)

internal fun entryExists(path: Path) = Files.exists(path, *NOFOLLOW)

/**
 * Swift `V2DurableFileCommitter`: same-directory staging, file sync
 * (`FileChannel.force`), atomic rename, then a directory sync. Deletion must
 * sync the directory before it counts as durable.
 *
 * Directory sync opens the directory read-only and forces it, which works on
 * Linux and Android. Where a platform cannot open a directory at all the sync
 * is skipped, as Swift does off Darwin.
 */
internal class DurableFileCommitter(private val faultInjector: FaultInjector? = null) {
    fun writeNew(data: ByteArray, destination: Path, stagingPrefix: String) {
        if (entryExists(destination)) throw FileAlreadyExistsException(destination.toString())
        val staging = writeSynchronizedStaging(data, destination, stagingPrefix)
        var keepStaging = false
        try {
            try {
                // No REPLACE_EXISTING: an existing destination fails instead of being replaced.
                Files.move(staging, destination)
            } catch (e: FileAlreadyExistsException) {
                throw e
            } catch (e: IOException) {
                if (entryExists(destination)) throw FileAlreadyExistsException(destination.toString())
                throw IOException("commit failed", e)
            }
            try {
                inject(CrashPoint.AFTER_NAMESPACE_COMMIT, destination)
            } catch (crash: SimulatedCrash) {
                keepStaging = true
                throw crash
            }
            syncDirectory(destination.parent, required = false)
        } finally {
            if (!keepStaging) Files.deleteIfExists(staging)
        }
    }

    fun replaceExisting(data: ByteArray, destination: Path, stagingPrefix: String) {
        if (!entryExists(destination)) throw NoSuchFileException(destination.toString())
        val staging = writeSynchronizedStaging(data, destination, stagingPrefix)
        var keepStaging = false
        try {
            try {
                Files.move(staging, destination, StandardCopyOption.ATOMIC_MOVE)
            } catch (e: AtomicMoveNotSupportedException) {
                throw IOException("atomic replace not supported", e)
            }
            try {
                inject(CrashPoint.AFTER_NAMESPACE_COMMIT, destination)
            } catch (crash: SimulatedCrash) {
                keepStaging = true
                throw crash
            }
            syncDirectory(destination.parent, required = false)
        } finally {
            if (!keepStaging) Files.deleteIfExists(staging)
        }
    }

    /** Unlinks one exact path; the directory must sync before success is reported. */
    fun removeExisting(destination: Path) {
        if (!entryExists(destination)) throw NoSuchFileException(destination.toString())
        try {
            Files.delete(destination)
        } catch (e: NoSuchFileException) {
            // Already gone: the desired state.
        }
        inject(CrashPoint.AFTER_NAMESPACE_DELETE, destination)
        syncDirectory(destination.parent, required = true)
    }

    /** Recovery: an authenticated name that is already absent is confirmed by a directory sync. */
    fun confirmAbsentDurably(destination: Path) {
        if (entryExists(destination)) throw IOException("object still exists")
        syncDirectory(destination.parent, required = true)
    }

    private fun writeSynchronizedStaging(data: ByteArray, destination: Path, prefix: String): Path {
        val parent = destination.parent
        val staging = parent.resolve("$prefix${UUID.randomUUID().toString().uppercase()}.tmp")
        val options = setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
        val channel = if ("posix" in parent.fileSystem.supportedFileAttributeViews()) {
            FileChannel.open(staging, options, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } else {
            FileChannel.open(staging, options)
        }
        var keep = false
        try {
            channel.use {
                inject(CrashPoint.AFTER_STAGING_CREATE, destination)
                val buffer = ByteBuffer.wrap(data)
                while (buffer.hasRemaining()) it.write(buffer)
                inject(CrashPoint.AFTER_STAGING_WRITE, destination)
                it.force(true)
                inject(CrashPoint.AFTER_STAGING_SYNC, destination)
            }
            keep = true
            return staging
        } catch (crash: SimulatedCrash) {
            keep = true
            throw crash
        } finally {
            if (!keep) Files.deleteIfExists(staging)
        }
    }

    private fun syncDirectory(directory: Path, required: Boolean) {
        val channel = try {
            FileChannel.open(directory, StandardOpenOption.READ)
        } catch (e: IOException) {
            // A required sync is a durability promise: never report success without it.
            if (required) throw IOException("directory sync failed", e)
            return
        }
        channel.use {
            try {
                it.force(true)
            } catch (e: IOException) {
                if (required) throw IOException("directory sync failed", e)
            }
        }
    }

    private fun inject(point: CrashPoint, destination: Path) {
        faultInjector?.reached(point, destination)
    }
}

/** Host free space, in bytes, or null when it cannot be measured. */
fun interface AvailableSpaceProvider {
    fun availableBytes(root: Path): Long?

    companion object {
        /** `File.usableSpace` (0 also for a missing path, so a missing root reads as unknown). */
        val SYSTEM = AvailableSpaceProvider { root -> if (Files.isDirectory(root)) root.toFile().usableSpace else null }
    }
}

/** The device has too little free space for this write (Swift `insufficientPhysicalCapacity`). */
class InsufficientSpaceException(val requiredBytes: Long, val availableBytes: Long) :
    IOException("not enough free space: need $requiredBytes bytes, have $availableBytes")

/**
 * Swift `V2PhysicalCapacityGuard`: refuses an ordinary write that would eat
 * into the budget's reserve and safety margin; data writes also keep room for
 * the metadata transition that follows. Removals may use the reserve.
 */
internal class PhysicalCapacityGuard(private val provider: AvailableSpaceProvider) {
    fun validateWrite(physicalBytes: Long, budget: StorageBudget, root: Path) =
        measure(checkedAdd(physicalBytes, checkedAdd(budget.reserveBytes, budget.safetyMarginBytes)), root)

    fun validateDataWrite(physicalBytes: Long, budget: StorageBudget, root: Path) =
        validateWrite(checkedAdd(physicalBytes, CONTROL_PLANE_HEADROOM), budget, root)

    fun validateSpaceReleasingWrite(physicalBytes: Long, root: Path) = measure(physicalBytes, root)

    private fun measure(required: Long, root: Path) {
        val available = try {
            provider.availableBytes(root)
        } catch (e: Exception) {
            null
        } ?: throw IOException("free space unavailable")
        if (available < required) throw InsufficientSpaceException(required, available)
    }

    companion object {
        /** One maximum-size sealed object (`V2PoolObjectCodec.maximumEnvelopeByteCount`). */
        val CONTROL_PLANE_HEADROOM = (V2Format.MAX_POOL_PLAINTEXT + V2Format.POOL_OVERHEAD).toLong()

        fun sealedSize(paddedPlaintext: Long) = paddedPlaintext + V2Format.POOL_OVERHEAD
    }
}

internal class PoolObjectNotFoundException : IOException("object not found")

internal class PoolObjectExistsException : IOException("object already exists")

/**
 * Swift `V2PoolObjectStore`: objects are created only by staged atomic rename,
 * read without following links, and deleted only after they authenticate as
 * the expected kind. Objects are found by name only; `objects/` is never listed.
 */
internal class PoolObjectStore(sodium: Sodium, val root: Path, private val committer: DurableFileCommitter) {
    val codec = PoolObjectCodec(sodium)
    private val pool: Path = root.resolve(V2Format.POOL_DIRECTORY)

    fun path(name: String): Path {
        if (!V2Format.isObjectName(name)) throw VaultFormatException("invalid object name")
        return pool.resolve(name)
    }

    fun contains(name: String) =
        V2Format.isObjectName(name) && Files.isDirectory(pool, *NOFOLLOW) && Files.isRegularFile(pool.resolve(name), *NOFOLLOW)

    /** Size on disk of a regular object file, or null. */
    fun sealedSize(name: String): Long? {
        val path = path(name)
        if (!Files.isDirectory(pool, *NOFOLLOW) || !Files.isRegularFile(path, *NOFOLLOW)) return null
        return try {
            Files.size(path)
        } catch (e: IOException) {
            null
        }
    }

    /** Opens one object; the caller wipes the returned content. */
    fun read(name: String, key: ByteArray): PoolObjectCodec.Opened {
        val path = path(name)
        if (!entryExists(pool)) throw PoolObjectNotFoundException()
        requirePool()
        if (!entryExists(path)) throw PoolObjectNotFoundException()
        if (!Files.isRegularFile(path, *NOFOLLOW)) throw VaultFormatException("object is not a regular file")
        val sealed = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val size = channel.size()
            if (size > V2Format.POOL_OVERHEAD + V2Format.MAX_POOL_PLAINTEXT) throw VaultFormatException("object too large")
            val buffer = ByteBuffer.allocate(size.toInt())
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) throw VaultFormatException("object changed while reading")
            }
            buffer.array()
        }
        return codec.open(sealed, key, name)
    }

    fun readOrNull(name: String, key: ByteArray): PoolObjectCodec.Opened? = try {
        read(name, key)
    } catch (e: PoolObjectNotFoundException) {
        null
    }

    /** Seals and creates [name]; an existing entry is never replaced. Returns the sealed size. */
    fun create(name: String, kind: PoolObjectKind, content: ByteArray, key: ByteArray, paddedPlaintext: Long): Long {
        val path = path(name)
        val sealed = codec.seal(kind, content, key, name, paddedPlaintext.toInt())
        requirePool()
        try {
            committer.writeNew(sealed, path, StagingPrefix.OBJECT)
        } catch (e: FileAlreadyExistsException) {
            throw PoolObjectExistsException()
        }
        return sealed.size.toLong()
    }

    /** Deletes [name] only after it authenticates under [key] as [kind] (and [expectedLength] when given). */
    fun deleteAuthenticated(name: String, key: ByteArray, kind: PoolObjectKind, expectedLength: Long?) {
        val opened = read(name, key)
        try {
            if (opened.kind != kind) throw VaultFormatException("object kind mismatch")
            if (expectedLength != null && opened.content.size.toLong() != expectedLength) {
                throw VaultFormatException("object length mismatch")
            }
        } finally {
            opened.content.wipe()
        }
        requirePool()
        val path = path(name)
        if (!entryExists(path)) throw PoolObjectNotFoundException()
        if (!Files.isRegularFile(path, *NOFOLLOW)) throw VaultFormatException("object is not a regular file")
        try {
            committer.removeExisting(path)
        } catch (e: NoSuchFileException) {
            throw PoolObjectNotFoundException()
        }
    }

    /** Recovery only: [name] comes from authenticated metadata. A symlink counts as present. */
    fun confirmAbsentDurably(name: String) {
        val path = path(name)
        requirePool()
        committer.confirmAbsentDurably(path)
    }

    fun requirePool() {
        if (Files.isSymbolicLink(pool)) throw VaultFormatException("objects is a symbolic link")
        if (!Files.isDirectory(pool, *NOFOLLOW)) throw VaultFormatException("objects is not a folder")
    }
}

internal class StaleMetadataException : Exception("metadata changed underneath")

/**
 * Swift `V2AccessMetadataStore`: one encrypted metadata anchor per access path,
 * replaced generation by generation (+1) with a compare-and-swap against the
 * metadata on disk.
 */
internal class MetadataStore(
    private val store: PoolObjectStore,
    private val guard: PhysicalCapacityGuard,
    private val committer: DurableFileCommitter,
) {
    enum class Admission { STANDARD, SPACE_RELEASING_REMOVAL }

    fun read(key: ByteArray): AccessMetadata {
        val name = ObjectNames.metadataAnchor(key)
        val opened = try {
            store.read(name, key)
        } catch (e: PoolObjectNotFoundException) {
            throw VaultFormatException("metadata not found")
        }
        try {
            if (opened.kind != PoolObjectKind.METADATA) throw VaultFormatException("not a metadata anchor")
            return AccessMetadata.parse(opened.content)
        } finally {
            opened.content.wipe()
        }
    }

    fun createInitialEmpty(budget: StorageBudget, key: ByteArray, accessID: UUID = UUID.randomUUID()): AccessMetadata {
        val metadata = AccessMetadata(accessID, 0, emptyList(), budget)
        metadata.validate()
        val (encoded, target) = encoded(metadata)
        try {
            synchronized(LOCK) {
                guard.validateWrite(PhysicalCapacityGuard.sealedSize(target), budget, store.root)
                try {
                    store.create(ObjectNames.metadataAnchor(key), PoolObjectKind.METADATA, encoded, key, target)
                } catch (e: PoolObjectExistsException) {
                    throw VaultFormatException("metadata anchor already exists")
                }
            }
        } finally {
            encoded.wipe()
        }
        return metadata
    }

    /** Commits exactly one generation transition; [StaleMetadataException] when [expected] is not on disk. */
    fun commit(expected: AccessMetadata, next: AccessMetadata, key: ByteArray, admission: Admission = Admission.STANDARD) {
        if (admission == Admission.SPACE_RELEASING_REMOVAL && !isExactSpaceReleasingRemoval(expected, next)) {
            throw VaultFormatException("not a space-releasing removal transition")
        }
        expected.validate()
        next.validate()
        if (next.accessID != expected.accessID) throw VaultFormatException("access identity changed")
        if (next.budget != expected.budget) throw VaultFormatException("budget cannot change")
        // Fixed capacity is turned on once and never off; its size never changes
        // and a completed fill never goes back.
        expected.fixedCapacity?.let { current ->
            val updated = next.fixedCapacity
            if (updated == null || updated.capacityBytes != current.capacityBytes || (current.isFilled && !updated.isFilled)) {
                throw VaultFormatException("fixed capacity cannot change")
            }
        }
        if (expected.generation == Long.MAX_VALUE || next.generation != expected.generation + 1) {
            throw VaultFormatException("invalid generation transition")
        }

        val name = ObjectNames.metadataAnchor(key)
        val (encoded, target) = encoded(next)
        val sealed = try {
            store.codec.seal(PoolObjectKind.METADATA, encoded, key, name, target.toInt())
        } finally {
            encoded.wipe()
        }
        synchronized(LOCK) {
            if (!read(key).sameAs(expected)) throw StaleMetadataException()
            store.requirePool()
            when (admission) {
                Admission.STANDARD -> guard.validateWrite(sealed.size.toLong(), next.budget, store.root)
                Admission.SPACE_RELEASING_REMOVAL -> guard.validateSpaceReleasingWrite(sealed.size.toLong(), store.root)
            }
            committer.replaceExisting(sealed, store.path(name), StagingPrefix.METADATA)
        }
    }

    /** Reads, mutates and commits, retrying a stale read (Swift `commitMetadataMutation`). */
    fun mutate(
        key: ByteArray,
        admission: Admission = Admission.STANDARD,
        mutation: (AccessMetadata) -> AccessMetadata,
    ): AccessMetadata {
        repeat(MAXIMUM_TRANSITION_RETRIES) {
            val current = read(key)
            val next = mutation(current)
            try {
                commit(current, next, key, admission)
                return next
            } catch (e: StaleMetadataException) {
                // Another writer moved the generation; read again.
            }
        }
        throw VaultFormatException("metadata transition retries exhausted")
    }

    /** §6.1: the smallest bucket, or always 1 MiB in a fixed-capacity access path ("vault full" beyond it). */
    private fun encoded(metadata: AccessMetadata): Pair<ByteArray, Long> {
        val encoded = metadata.encode()
        val target = try {
            Padding.metadataTarget(encoded.size.toLong())
        } catch (e: VaultFormatException) {
            if (metadata.fixedCapacity != null) throw VaultFullException()
            throw VaultFormatException("metadata too large")
        }
        if (metadata.fixedCapacity == null) return encoded to target
        if (target > V2Format.FIXED_METADATA_PLAINTEXT) throw VaultFullException()
        return encoded to V2Format.FIXED_METADATA_PLAINTEXT.toLong()
    }

    /** Rebuilds the one allowed removal claim or finalization instead of trusting the caller. */
    private fun isExactSpaceReleasingRemoval(current: AccessMetadata, next: AccessMetadata): Boolean {
        val currentIDs = current.pendingRemovals.map { it.transactionID }.toSet()
        val nextIDs = next.pendingRemovals.map { it.transactionID }.toSet()
        val added = nextIDs - currentIDs
        val removed = currentIDs - nextIDs
        return try {
            if (added.size == 1 && removed.isEmpty()) {
                val p = next.pendingRemovals.first { it.transactionID == added.first() }
                val expected = if (p.auxiliaryObjectNames.isEmpty()) {
                    current.beginningRemoval(p.entryID, p.transactionID, p.createdAt, p.coverSlots)
                } else {
                    current.beginningChunkedRemoval(p.entryID, p.transactionID, p.auxiliaryObjectNames, p.createdAt, p.coverSlots)
                }
                expected.sameAs(next)
            } else if (removed.size == 1 && added.isEmpty()) {
                current.finalizingRemoval(removed.first()).sameAs(next)
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    companion object {
        const val MAXIMUM_TRANSITION_RETRIES = 8

        /**
         * All writers live in one process; one lock serializes metadata replacement (Swift `processMutationLock`).
         * A vault must not be opened for writing by two processes at once: this lock does not cross processes,
         * and neither does the read-then-replace compare-and-swap in [commit].
         */
        private val LOCK = Any()
    }
}

/**
 * Swift `V2FixedCapacityCovers` (+ `V2FixedCapacityPool.fill`): every cover
 * operation is idempotent so recovery can repeat it. A cover is created only
 * when its derived name is absent and removed only after it authenticates as
 * an empty padding object; anything else at a cover name fails closed.
 */
internal class Covers(private val store: PoolObjectStore) {
    private val random = java.security.SecureRandom()

    fun name(slot: CoverSlot, key: ByteArray) = ObjectNames.cover(key, slot.bucketPlaintextByteCount, slot.index)

    /**
     * One distinct free slot per requested minimum size: smallest fitting
     * bucket first, random within a bucket, and only slots whose cover is on disk.
     */
    fun chooseCoveredSlots(minimums: List<Long>, state: FixedCapacityState, key: ByteArray): List<CoverSlot> {
        CoverNamer(key).use { namer ->
            var ledger = state.ledger
            return minimums.map { minimum ->
                var found: CoverSlot? = null
                search@ for (bucket in ledger.buckets) {
                    if (bucket.plaintextByteCount < minimum) continue
                    for (index in bucket.coveredSlots().shuffled(random)) {
                        if (store.contains(namer.name(bucket.plaintextByteCount, index))) {
                            found = CoverSlot(bucket.plaintextByteCount, index)
                            break@search
                        }
                    }
                }
                val slot = found ?: throw VaultFullException()
                ledger = ledger.setting(false, listOf(slot))
                slot
            }
        }
    }

    /** One distinct empty, unreserved slot in the bucket of each named live object (bucket read from its size). */
    fun chooseEmptySlots(names: List<String>, state: FixedCapacityState, reserved: Set<CoverSlot>, key: ByteArray): List<CoverSlot> {
        CoverNamer(key).use { namer ->
            val taken = reserved.toHashSet()
            return names.map { name ->
                val size = bucketOf(name, state)
                val bucket = state.ledger.bucket(size) ?: throw VaultFormatException("invalid cover slot")
                var found: CoverSlot? = null
                for (index in bucket.emptySlots().shuffled(random)) {
                    val slot = CoverSlot(size, index)
                    if (slot in taken) continue
                    val coverName = namer.name(size, index)
                    if (!store.contains(coverName) || isGenuineCover(coverName, slot, key)) {
                        found = slot
                        break
                    }
                }
                val slot = found ?: throw VaultFormatException("invalid cover slot")
                taken += slot
                slot
            }
        }
    }

    fun ensureCoverPresent(slot: CoverSlot, key: ByteArray) {
        val name = name(slot, key)
        if (store.contains(name)) {
            if (!isGenuineCover(name, slot, key)) throw VaultFormatException("unexpected object at a cover name")
            return
        }
        try {
            store.create(name, PoolObjectKind.PADDING, ByteArray(0), key, slot.bucketPlaintextByteCount)
        } catch (e: PoolObjectExistsException) {
            if (!isGenuineCover(name, slot, key)) throw VaultFormatException("unexpected object at a cover name")
        }
    }

    fun ensureCoverRemoved(slot: CoverSlot, key: ByteArray) {
        val name = name(slot, key)
        try {
            store.deleteAuthenticated(name, key, PoolObjectKind.PADDING, 0)
        } catch (e: PoolObjectNotFoundException) {
            store.confirmAbsentDurably(name)
        }
    }

    /** The bucket a live object occupies, from its sealed size on disk. */
    fun bucketOf(name: String, state: FixedCapacityState): Long {
        val sealed = store.sealedSize(name) ?: throw PoolObjectNotFoundException()
        return state.ledger.buckets.firstOrNull { PhysicalCapacityGuard.sealedSize(it.plaintextByteCount) == sealed }
            ?.plaintextByteCount ?: throw VaultFormatException("unexpected object size")
    }

    /** Sealed bytes still to write to fill [plan]. */
    fun missingBytes(plan: List<FixedCapacityPlan.Bucket>, key: ByteArray): Long = CoverNamer(key).use { namer ->
        plan.sumOf { b ->
            (0 until b.slotCount).count { !store.contains(namer.name(b.plaintextByteCount, it)) } *
                PhysicalCapacityGuard.sealedSize(b.plaintextByteCount)
        }
    }

    /**
     * Writes every cover of [plan] not on disk yet (resumable: names are
     * derived). Only for a new or interrupted fill. [progress] gets (done, total).
     */
    fun fill(plan: List<FixedCapacityPlan.Bucket>, key: ByteArray, progress: ((Long, Long) -> Unit)?) {
        CoverNamer(key).use { namer ->
            val total = plan.sumOf { it.slotCount }
            var done = 0L
            for (b in plan) {
                for (index in 0 until b.slotCount) {
                    val name = namer.name(b.plaintextByteCount, index)
                    if (store.contains(name)) {
                        // Objects appear by atomic rename, so an existing name is whole; check its size.
                        if (store.sealedSize(name) != PhysicalCapacityGuard.sealedSize(b.plaintextByteCount)) {
                            throw VaultFormatException("unexpected object at a cover name")
                        }
                    } else {
                        store.create(name, PoolObjectKind.PADDING, ByteArray(0), key, b.plaintextByteCount)
                    }
                    done++
                    progress?.invoke(done, total)
                }
            }
        }
    }

    private fun isGenuineCover(name: String, slot: CoverSlot, key: ByteArray): Boolean {
        if (store.sealedSize(name) != PhysicalCapacityGuard.sealedSize(slot.bucketPlaintextByteCount)) return false
        val opened = try {
            store.read(name, key)
        } catch (e: Exception) {
            return false
        }
        val genuine = opened.kind == PoolObjectKind.PADDING && opened.content.isEmpty()
        opened.content.wipe()
        return genuine
    }
}
