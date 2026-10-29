package com.hanzala.fortress.vault

import java.io.IOException
import java.io.InputStream
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * A file to import. A chunked import reads it twice, as Swift does: a pre-hash
 * pass (the digest is committed in the pending claim before any chunk is
 * written, §8.1) and a write pass. A source that changes in between is
 * detected by the digest and the import is rolled back.
 */
interface ImportSource : AutoCloseable {
    /** Byte length; decides single-object vs chunked (§10). */
    val size: Long

    /** A new sequential read from the first byte. The caller closes it. */
    fun openStream(): InputStream

    override fun close() {}

    companion object {
        /**
         * A regular file, opened once without following links; both passes read
         * the same open channel, so replacing the path cannot redirect the
         * second pass (Swift `V2SecureSourceFile`).
         */
        fun of(path: Path): ImportSource {
            if (Files.isSymbolicLink(path)) throw ImportSourceException("source is a symbolic link")
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw ImportSourceException("source is not a regular file")
            val channel = try {
                FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
            } catch (e: IOException) {
                throw ImportSourceException("source could not be opened", e)
            }
            val size = channel.size()
            return object : ImportSource {
                override val size = size

                override fun openStream(): InputStream {
                    channel.position(0)
                    val stream = Channels.newInputStream(channel)
                    // Closing a pass must not close the retained channel.
                    return object : java.io.FilterInputStream(stream) {
                        override fun close() {}
                    }
                }

                override fun close() = channel.close()
            }
        }
    }
}

/** The source could not be read, or changed while it was being imported. */
class ImportSourceException(message: String, cause: Throwable? = null) : IOException(message, cause)

/** What crash recovery did when a session opened (Swift `V2VaultSessionRecoveryReport`). */
data class RecoveryReport(
    val finalizedImports: List<UUID> = emptyList(),
    val abortedImports: List<UUID> = emptyList(),
    val finalizedChunkImports: List<UUID> = emptyList(),
    val abortedChunkImports: List<UUID> = emptyList(),
    val deletedRemovals: List<UUID> = emptyList(),
    val alreadyMissingRemovals: List<UUID> = emptyList(),
) {
    val isEmpty get() = listOf(finalizedImports, abortedImports, finalizedChunkImports, abortedChunkImports,
        deletedRemovals, alreadyMissingRemovals).all { it.isEmpty() }
}

internal fun nowWholeSeconds(): Instant = Instant.now().truncatedTo(ChronoUnit.SECONDS)

/**
 * Swift's three ownership coordinators for one access path:
 *
 * - single import (`V2OwnershipTransactionCoordinator`): claim committed in
 *   metadata, object written at the claimed name, claim moved to `entries`;
 * - chunked import (`V2ChunkOwnershipTransactionCoordinator`): manifest and
 *   chunk names claimed, chunks written, digest verified, manifest written,
 *   claim moved to `entries`;
 * - removal (`V2RemovalTransactionCoordinator`): entry moved to a pending
 *   removal, objects deleted after authenticating, removal finalized.
 *
 * In a fixed-capacity vault each claim also reserves cover slots and every
 * write swaps one cover for one object, so the pool's shape never changes.
 * Recovery follows only names committed in authenticated metadata; it never
 * lists the pool. Every metadata commit is generation + 1.
 */
internal class Transactions(
    private val sodium: Sodium,
    private val store: PoolObjectStore,
    private val metadata: MetadataStore,
    private val guard: PhysicalCapacityGuard,
    private val covers: Covers,
) {
    private val root get() = store.root

    private fun newName() = Hex.encode(sodium.randomBytes(32))

    // MARK: single-object import

    fun importData(content: ByteArray, originalName: String, key: ByteArray, padded: Long): VaultEntry {
        repeat(MAXIMUM_NAME_ATTEMPTS) {
            val name = newName()
            val transactionID = UUID.randomUUID()
            var pending = PendingImport(transactionID, name, originalName, content.size.toLong(), nowWholeSeconds())
            val claimed = try {
                metadata.mutate(key) { current ->
                    if (name in current.ownedObjectNames || store.contains(name)) throw CandidateNameTakenException()
                    current.fixedCapacity?.let { state ->
                        if (!state.isFilled) throw VaultFormatException("fixed capacity not filled")
                        pending = pending.copy(coverSlot = covers.chooseCoveredSlots(listOf(padded), state, key)[0])
                    }
                    current.beginningImport(pending)
                }
            } catch (e: CandidateNameTakenException) {
                return@repeat
            }

            // A fixed-capacity object takes its slot's size, which may be larger.
            val objectPlaintext = pending.coverSlot?.bucketPlaintextByteCount ?: padded
            try {
                guard.validateDataWrite(PhysicalCapacityGuard.sealedSize(objectPlaintext), claimed.budget, root)
            } catch (e: Exception) {
                // No object exists yet: drop only this claim (recovery would too).
                try {
                    abortImport(transactionID, key)
                } catch (ignored: Exception) {
                }
                throw e
            }
            try {
                store.create(name, PoolObjectKind.DATA, content, key, objectPlaintext)
            } catch (e: PoolObjectExistsException) {
                // Another writer won the random name: drop our claim, never touch that object.
                abortImport(transactionID, key)
                return@repeat
            }
            verifyPendingObject(pending, key)
            pending.coverSlot?.let { covers.ensureCoverRemoved(it, key) }
            val finalized = metadata.mutate(key) { it.finalizingImport(transactionID) }
            return finalized.entries.firstOrNull { it.id == transactionID } ?: throw VaultFormatException("finalized entry missing")
        }
        throw VaultFormatException("name generation exhausted")
    }

    /** Missing object: put the cover back and abort. Present object: authenticate, remove the cover, finalize. */
    fun recoverPendingImports(key: ByteArray, report: RecoveryReport): RecoveryReport {
        var finalized = report.finalizedImports
        var aborted = report.abortedImports
        while (true) {
            val pending = metadata.read(key).pendingImports.firstOrNull()
                ?: return report.copy(finalizedImports = finalized, abortedImports = aborted)
            try {
                verifyPendingObject(pending, key)
            } catch (e: PoolObjectNotFoundException) {
                // The cover is removed only after the object exists, so it should still be there.
                pending.coverSlot?.let { covers.ensureCoverPresent(it, key) }
                abortImport(pending.transactionID, key)
                aborted = aborted + pending.transactionID
                continue
            }
            pending.coverSlot?.let { covers.ensureCoverRemoved(it, key) }
            metadata.mutate(key) { it.finalizingImport(pending.transactionID) }
            finalized = finalized + pending.transactionID
        }
    }

    private fun verifyPendingObject(pending: PendingImport, key: ByteArray) {
        val opened = store.read(pending.opaqueObjectName, key)
        try {
            if (opened.kind != PoolObjectKind.DATA) throw VaultFormatException("pending object kind mismatch")
            if (opened.content.size.toLong() != pending.logicalByteCount) throw VaultFormatException("pending object length mismatch")
        } finally {
            opened.content.wipe()
        }
    }

    private fun abortImport(transactionID: UUID, key: ByteArray) {
        metadata.mutate(key) { it.abortingImport(transactionID) }
    }

    // MARK: chunked import

    fun importChunked(source: ImportSource, originalName: String, key: ByteArray): VaultEntry {
        val byteCount = source.size
        val lengths = canonicalChunkLengths(byteCount)
        val digest = hashSource(source, byteCount)
        val pending = claimPendingChunkImport(originalName, byteCount, lengths, digest, key)
        val budget = metadata.read(key).budget
        try {
            val written = writeChunks(source, byteCount, pending, budget, key)
            if (!MessageDigest.isEqual(written, digest)) throw ImportSourceException("source changed during import")
        } catch (e: IOException) {
            // No manifest exists on this path: roll back only claimed, authenticated chunks,
            // so reserved cover slots come back now rather than at the next session open.
            // If the rollback itself fails, recovery at the next open cleans up.
            try {
                rollbackSourceFailure(pending, key)
            } catch (rollback: Exception) {
                e.addSuppressed(rollback)
            }
            throw e
        }
        return publishWrittenChunkImport(pending, key)
    }

    fun recoverPendingChunkImports(key: ByteArray, report: RecoveryReport): RecoveryReport {
        var finalized = report.finalizedChunkImports
        var aborted = report.abortedChunkImports
        while (true) {
            val pending = metadata.read(key).pendingChunkImports.firstOrNull()
                ?: return report.copy(finalizedChunkImports = finalized, abortedChunkImports = aborted)
            val manifest = store.readOrNull(pending.manifestObjectName, key)
            val (allPresent, present) = inspectChunks(pending, key)
            if (manifest != null) {
                try {
                    verifyManifestObject(manifest, pending)
                } finally {
                    manifest.content.wipe()
                }
                // Past the publish boundary: a missing chunk fails closed.
                if (!allPresent) throw VaultFormatException("manifest present but a chunk is missing")
                removeAllCovers(pending, key)
                metadata.mutate(key) { it.finalizingChunkImport(pending.transactionID) }
                finalized = finalized + pending.transactionID
                continue
            }
            if (allPresent) {
                createManifestIfAbsent(pending, key)
                verifyManifest(pending, key)
                removeAllCovers(pending, key)
                metadata.mutate(key) { it.finalizingChunkImport(pending.transactionID) }
                finalized = finalized + pending.transactionID
                continue
            }
            // No manifest and an incomplete chunk set: roll back. A written chunk's
            // cover goes back before the chunk is deleted.
            for (chunk in present) {
                val index = pending.chunks.indexOf(chunk)
                pending.coverSlots?.get(index + 1)?.let { covers.ensureCoverPresent(it, key) }
                try {
                    store.deleteAuthenticated(chunk.opaqueObjectName, key, PoolObjectKind.DATA, chunk.logicalByteCount)
                } catch (e: PoolObjectNotFoundException) {
                    // Already rolled back.
                }
            }
            metadata.mutate(key) { it.abortingChunkImport(pending.transactionID) }
            aborted = aborted + pending.transactionID
        }
    }

    private fun claimPendingChunkImport(
        originalName: String,
        byteCount: Long,
        lengths: List<Long>,
        digest: ByteArray,
        key: ByteArray,
    ): PendingChunkImport {
        if (lengths.size > V2Format.MAX_CHUNKS) throw VaultFormatException("too many chunks")
        repeat(MAXIMUM_NAME_ATTEMPTS) {
            val manifestName = newName()
            val chunkNames = lengths.map { newName() }
            val allNames = listOf(manifestName) + chunkNames
            if (allNames.toSet().size != allNames.size) return@repeat
            var pending = PendingChunkImport(
                UUID.randomUUID(), manifestName, originalName, byteCount,
                chunkNames.zip(lengths).map { (n, l) -> PendingChunkObject(n, l) }, digest, nowWholeSeconds(),
            )
            pending.manifest().let { ChunkManifest.validate(it.chunks, it.logicalByteCount, it.sha256Digest) }
            try {
                metadata.mutate(key) { current ->
                    val owned = current.ownedObjectNames
                    if (allNames.any { it in owned || store.contains(it) }) throw CandidateNameTakenException()
                    val state = current.fixedCapacity
                    pending = if (state != null) {
                        if (!state.isFilled) throw VaultFormatException("fixed capacity not filled")
                        val manifestTarget = Padding.metadataTarget(pending.manifest().encode().size.toLong())
                        val minimums = listOf(manifestTarget) + List(pending.chunks.size) { V2Format.CHUNK_PLAINTEXT.toLong() }
                        pending.withCoverSlots(covers.chooseCoveredSlots(minimums, state, key))
                    } else {
                        pending.withCoverSlots(null)
                    }
                    current.beginningChunkImport(pending)
                }
                return pending
            } catch (e: CandidateNameTakenException) {
                return@repeat
            }
        }
        throw VaultFormatException("name generation exhausted")
    }

    /** Pass one: SHA-256 of the whole source in bounded reads; the source must end exactly at [byteCount]. */
    private fun hashSource(source: ImportSource, byteCount: Long): ByteArray {
        val hasher = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(V2Format.CHUNK_PLAINTEXT)
        try {
            openSource(source).use { stream ->
                var remaining = byteCount
                while (remaining > 0) {
                    val n = readFully(stream, buffer, minOf(buffer.size.toLong(), remaining).toInt())
                    hasher.update(buffer, 0, n)
                    remaining -= n
                }
                requireEnd(stream)
            }
        } finally {
            buffer.wipe()
        }
        return hasher.digest()
    }

    /** Pass two: each chunk is read, hashed and written, then its plaintext wiped. */
    private fun writeChunks(
        source: ImportSource,
        byteCount: Long,
        pending: PendingChunkImport,
        budget: StorageBudget,
        key: ByteArray,
    ): ByteArray {
        val hasher = MessageDigest.getInstance("SHA-256")
        var total = 0L
        openSource(source).use { stream ->
            pending.chunks.forEachIndexed { index, chunk ->
                val bytes = ByteArray(chunk.logicalByteCount.toInt())
                try {
                    readFully(stream, bytes, bytes.size)
                    hasher.update(bytes)
                    total += bytes.size
                    writeChunk(bytes, index, pending, budget, key)
                } finally {
                    bytes.wipe()
                }
            }
            if (total != byteCount) throw ImportSourceException("source changed during import")
            requireEnd(stream)
        }
        return hasher.digest()
    }

    /** Writes chunk [index] padded to its slot's bucket (or 4 MiB), then removes that slot's cover. */
    private fun writeChunk(bytes: ByteArray, index: Int, pending: PendingChunkImport, budget: StorageBudget, key: ByteArray) {
        val slot = pending.coverSlots?.get(index + 1)
        val padded = slot?.bucketPlaintextByteCount ?: V2Format.CHUNK_PLAINTEXT.toLong()
        guard.validateDataWrite(PhysicalCapacityGuard.sealedSize(padded), budget, root)
        store.create(pending.chunks[index].opaqueObjectName, PoolObjectKind.DATA, bytes, key, padded)
        slot?.let { covers.ensureCoverRemoved(it, key) }
    }

    private fun rollbackSourceFailure(pending: PendingChunkImport, key: ByteArray) {
        // A manifest at the claimed name was never written by this path: keep the claim for recovery.
        if (store.contains(pending.manifestObjectName)) return
        pending.chunks.forEachIndexed { index, chunk ->
            val opened = store.readOrNull(chunk.opaqueObjectName, key) ?: return@forEachIndexed
            try {
                if (opened.kind != PoolObjectKind.DATA) throw VaultFormatException("pending chunk kind mismatch")
                if (opened.content.size.toLong() != chunk.logicalByteCount) throw VaultFormatException("pending chunk length mismatch")
            } finally {
                opened.content.wipe()
            }
            pending.coverSlots?.get(index + 1)?.let { covers.ensureCoverPresent(it, key) }
            try {
                store.deleteAuthenticated(chunk.opaqueObjectName, key, PoolObjectKind.DATA, chunk.logicalByteCount)
            } catch (e: PoolObjectNotFoundException) {
                // Already gone.
            }
        }
        metadata.mutate(key) { it.abortingChunkImport(pending.transactionID) }
    }

    private fun publishWrittenChunkImport(pending: PendingChunkImport, key: ByteArray): VaultEntry {
        inspectChunks(pending, key)
        createManifestIfAbsent(pending, key)
        verifyManifest(pending, key)
        pending.coverSlots?.first()?.let { covers.ensureCoverRemoved(it, key) }
        metadata.mutate(key) { it.finalizingChunkImport(pending.transactionID) }
        return metadata.read(key).entries.firstOrNull { it.id == pending.transactionID }
            ?: throw VaultFormatException("finalized entry missing")
    }

    /** Authenticates every present chunk; when all are present, also the whole-file digest. */
    private fun inspectChunks(pending: PendingChunkImport, key: ByteArray): Pair<Boolean, List<PendingChunkObject>> {
        val hasher = MessageDigest.getInstance("SHA-256")
        val present = ArrayList<PendingChunkObject>()
        var allPresent = true
        for (chunk in pending.chunks) {
            val opened = store.readOrNull(chunk.opaqueObjectName, key)
            if (opened == null) {
                allPresent = false
                continue
            }
            try {
                if (opened.kind != PoolObjectKind.DATA) throw VaultFormatException("pending chunk kind mismatch")
                if (opened.content.size.toLong() != chunk.logicalByteCount) throw VaultFormatException("pending chunk length mismatch")
                hasher.update(opened.content)
            } finally {
                opened.content.wipe()
            }
            present += chunk
        }
        if (allPresent && !MessageDigest.isEqual(hasher.digest(), pending.sha256Digest)) {
            throw VaultFormatException("chunk digest mismatch")
        }
        return allPresent to present
    }

    private fun createManifestIfAbsent(pending: PendingChunkImport, key: ByteArray) {
        store.readOrNull(pending.manifestObjectName, key)?.let { existing ->
            try {
                verifyManifestObject(existing, pending)
            } finally {
                existing.content.wipe()
            }
            return
        }
        val encoded = pending.manifest().encode()
        val padded = pending.coverSlots?.first()?.bucketPlaintextByteCount ?: Padding.metadataTarget(encoded.size.toLong())
        guard.validateDataWrite(PhysicalCapacityGuard.sealedSize(padded), metadata.read(key).budget, root)
        try {
            store.create(pending.manifestObjectName, PoolObjectKind.MANIFEST, encoded, key, padded)
        } catch (e: PoolObjectExistsException) {
            // Must authenticate as the exact manifest below, or recovery fails closed.
        } finally {
            encoded.wipe()
        }
    }

    private fun verifyManifest(pending: PendingChunkImport, key: ByteArray) {
        val opened = store.read(pending.manifestObjectName, key)
        try {
            verifyManifestObject(opened, pending)
        } finally {
            opened.content.wipe()
        }
    }

    private fun verifyManifestObject(opened: PoolObjectCodec.Opened, pending: PendingChunkImport) {
        if (opened.kind != PoolObjectKind.MANIFEST) throw VaultFormatException("pending manifest kind mismatch")
        if (!ChunkManifest.parse(opened.content).sameAs(pending.manifest())) throw VaultFormatException("pending manifest mismatch")
    }

    private fun removeAllCovers(pending: PendingChunkImport, key: ByteArray) {
        pending.coverSlots?.forEach { covers.ensureCoverRemoved(it, key) }
    }

    // MARK: removal

    fun removeEntry(entryID: UUID, key: ByteArray): UUID {
        val transactionID = UUID.randomUUID()
        val claimed = claimRemoval(entryID, transactionID, key)
        val pending = claimed.pendingRemovals.firstOrNull { it.transactionID == transactionID }
            ?: throw VaultFormatException("pending removal missing")
        physicallyRemove(pending, key)
        metadata.mutate(key, MetadataStore.Admission.SPACE_RELEASING_REMOVAL) { it.finalizingRemoval(transactionID) }
        return transactionID
    }

    fun recoverPendingRemovals(key: ByteArray, report: RecoveryReport): RecoveryReport {
        var deleted = report.deletedRemovals
        var missing = report.alreadyMissingRemovals
        while (true) {
            val pending = metadata.read(key).pendingRemovals.firstOrNull()
                ?: return report.copy(deletedRemovals = deleted, alreadyMissingRemovals = missing)
            if (physicallyRemove(pending, key)) deleted = deleted + pending.transactionID else missing = missing + pending.transactionID
            metadata.mutate(key, MetadataStore.Admission.SPACE_RELEASING_REMOVAL) { it.finalizingRemoval(pending.transactionID) }
        }
    }

    private fun claimRemoval(entryID: UUID, transactionID: UUID, key: ByteArray): AccessMetadata {
        repeat(MetadataStore.MAXIMUM_TRANSITION_RETRIES) {
            val current = metadata.read(key)
            val entry = current.entries.firstOrNull { it.id == entryID } ?: throw EntryNotFoundException()
            var coverSlots: List<CoverSlot>? = null
            current.fixedCapacity?.let { state ->
                coverSlots = covers.chooseEmptySlots(entry.allObjectNames, state, current.reservedCoverSlots, key)
                // Covers are written one at a time before their objects are deleted:
                // refuse up front when the disk cannot hold the largest one.
                val largest = coverSlots!!.maxOf { it.bucketPlaintextByteCount }
                guard.validateSpaceReleasingWrite(
                    PhysicalCapacityGuard.sealedSize(largest) + PhysicalCapacityGuard.CONTROL_PLANE_HEADROOM, root,
                )
            }
            val next = if (!entry.isChunked) {
                current.beginningRemoval(entryID, transactionID, nowWholeSeconds(), coverSlots)
            } else {
                val manifest = authenticatedManifest(entry, key)
                verifyWholeFile(manifest, key)
                current.beginningChunkedRemoval(entryID, transactionID, manifest.chunks.map { it.first }, nowWholeSeconds(), coverSlots)
            }
            try {
                metadata.commit(current, next, key, MetadataStore.Admission.SPACE_RELEASING_REMOVAL)
                return next
            } catch (e: StaleMetadataException) {
                // Retry on the newer generation.
            }
        }
        throw VaultFormatException("metadata transition retries exhausted")
    }

    /** Deletes the removal's objects, each after its cover is back. Returns whether anything was deleted. */
    private fun physicallyRemove(pending: PendingRemoval, key: ByteArray): Boolean {
        if (pending.auxiliaryObjectNames.isEmpty()) {
            restoreCover(pending, 0, key)
            return deleteIfPresent(pending.opaqueObjectName, key, PoolObjectKind.DATA, pending.logicalByteCount)
        }
        val manifestObject = store.readOrNull(pending.opaqueObjectName, key)
        if (manifestObject == null) {
            for (name in pending.auxiliaryObjectNames) {
                store.readOrNull(name, key)?.let {
                    it.content.wipe()
                    throw VaultFormatException("manifest missing but a chunk remains")
                }
                store.confirmAbsentDurably(name)
            }
            store.confirmAbsentDurably(pending.opaqueObjectName)
            pending.allObjectNames.indices.forEach { restoreCover(pending, it, key) }
            return false
        }
        val manifest = try {
            if (manifestObject.kind != PoolObjectKind.MANIFEST) throw VaultFormatException("pending manifest kind mismatch")
            ChunkManifest.parse(manifestObject.content)
        } finally {
            manifestObject.content.wipe()
        }
        if (manifest.fileID != pending.entryID || manifest.logicalByteCount != pending.logicalByteCount ||
            manifest.chunks.map { it.first } != pending.auxiliaryObjectNames
        ) {
            throw VaultFormatException("pending manifest mismatch")
        }
        var removed = false
        manifest.chunks.forEachIndexed { index, (name, length) ->
            restoreCover(pending, index + 1, key)
            removed = deleteIfPresent(name, key, PoolObjectKind.DATA, length) || removed
        }
        restoreCover(pending, 0, key)
        return deleteIfPresent(pending.opaqueObjectName, key, PoolObjectKind.MANIFEST, null) || removed
    }

    /** Fixed capacity only: the cover of object [index] goes back before that object is deleted. */
    private fun restoreCover(pending: PendingRemoval, index: Int, key: ByteArray) {
        pending.coverSlots?.let { covers.ensureCoverPresent(it[index], key) }
    }

    private fun deleteIfPresent(name: String, key: ByteArray, kind: PoolObjectKind, length: Long?): Boolean = try {
        store.deleteAuthenticated(name, key, kind, length)
        true
    } catch (e: PoolObjectNotFoundException) {
        store.confirmAbsentDurably(name)
        false
    }

    private fun authenticatedManifest(entry: VaultEntry, key: ByteArray): ChunkManifest {
        val opened = store.read(entry.opaqueObjectName, key)
        val manifest = try {
            if (opened.kind != PoolObjectKind.MANIFEST) throw VaultFormatException("manifest kind mismatch")
            ChunkManifest.parse(opened.content)
        } finally {
            opened.content.wipe()
        }
        if (manifest.fileID != entry.id || manifest.logicalByteCount != entry.logicalByteCount ||
            manifest.chunks.map { it.first } != entry.auxiliaryObjectNames
        ) {
            throw VaultFormatException("manifest mismatch")
        }
        return manifest
    }

    /** Swift `V2ChunkedFileReader.verifyWholeFile`: every chunk of this one file and its digest. */
    private fun verifyWholeFile(manifest: ChunkManifest, key: ByteArray) {
        val hasher = MessageDigest.getInstance("SHA-256")
        for ((name, length) in manifest.chunks) {
            val opened = store.read(name, key)
            try {
                if (opened.kind != PoolObjectKind.DATA || opened.content.size.toLong() != length) {
                    throw VaultFormatException("chunk mismatch")
                }
                hasher.update(opened.content)
            } finally {
                opened.content.wipe()
            }
        }
        if (!MessageDigest.isEqual(hasher.digest(), manifest.sha256Digest)) throw VaultFormatException("digest mismatch")
    }

    companion object {
        const val MAXIMUM_NAME_ATTEMPTS = 16

        /** §10: full 4 194 294-byte chunks and a shorter last one; only above the single-object limit. */
        fun canonicalChunkLengths(byteCount: Long): List<Long> {
            if (byteCount <= V2Format.MAX_SINGLE_CONTENT) throw VaultFormatException("chunking not required")
            val chunk = V2Format.CHUNK_CONTENT.toLong()
            val count = (byteCount + chunk - 1) / chunk
            if (count > V2Format.MAX_CHUNKS) throw VaultFormatException("too many chunks")
            return List(count.toInt()) { i -> if (i < count - 1) chunk else byteCount - chunk * (count - 1) }
        }

        private fun openSource(source: ImportSource): InputStream = try {
            source.openStream()
        } catch (e: IOException) {
            throw ImportSourceException("source could not be read", e)
        }

        /** Reads exactly [count] bytes; a short source is a changed source. */
        private fun readFully(stream: InputStream, buffer: ByteArray, count: Int): Int {
            var offset = 0
            while (offset < count) {
                val n = try {
                    stream.read(buffer, offset, count - offset)
                } catch (e: IOException) {
                    throw ImportSourceException("source could not be read", e)
                }
                if (n < 0) throw ImportSourceException("source changed during import")
                offset += n
            }
            return count
        }

        private fun requireEnd(stream: InputStream) {
            val extra = try {
                stream.read()
            } catch (e: IOException) {
                throw ImportSourceException("source could not be read", e)
            }
            if (extra >= 0) throw ImportSourceException("source changed during import")
        }
    }
}
