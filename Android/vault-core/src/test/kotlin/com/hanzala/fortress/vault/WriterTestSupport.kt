package com.hanzala.fortress.vault

import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Cheap Argon2id and unlimited free space keep writer tests fast. */
internal object WriterTestSupport {
    val FAST_KDF = KdfParameters(1, 8192)
    val PLENTY = AvailableSpaceProvider { Long.MAX_VALUE / 4 }

    fun writer(root: Path, injector: FaultInjector? = null) = V2VaultWriter(JvmSodium, root, FAST_KDF, PLENTY, injector)

    /** Content that is easy to tell apart and compress-proof enough for tests. */
    fun bytes(size: Int, seed: Int) = ByteArray(size) { ((it * 31 + seed * 7) xor (it ushr 9)).toByte() }

    /** The master key held by a recovery anchor (tests only; the app never needs it). */
    fun masterKey(root: Path, recoveryKey: String): ByteArray {
        val reader = V2VaultReader(JvmSodium, root)
        val (key, _) = reader.recoverAccess(reader.readEnvelope(), recoveryKey)
        return key.masterKey.copyOf().also { key.close() }
    }

    /** Raw metadata JSON of an access path. */
    fun metadataBytes(root: Path, masterKey: ByteArray): ByteArray {
        val name = ObjectNames.metadataAnchor(masterKey)
        val opened = PoolObjectCodec(JvmSodium).open(Files.readAllBytes(root.resolve("objects").resolve(name)), masterKey, name)
        assertEquals(PoolObjectKind.METADATA, opened.kind)
        return opened.content
    }

    fun metadata(root: Path, masterKey: ByteArray) = AccessMetadata.parse(metadataBytes(root, masterKey))

    /** Every 64-hex object file; staging leftovers must carry a spec prefix and are skipped. */
    fun objectFiles(root: Path): Map<String, Long> {
        val result = HashMap<String, Long>()
        for (path in root.resolve("objects").listDirectoryEntries()) {
            val name = path.name
            if (name.startsWith(".")) {
                assertTrue(name.startsWith(".hanzala-v2-stage-") || name.startsWith(".hanzala-v2-metadata-stage-"), name)
                continue
            }
            assertTrue(V2Format.isObjectName(name), name)
            result[name] = Files.size(path)
        }
        return result
    }

    /**
     * No orphans: the pool holds exactly both metadata anchors, both recovery
     * anchors, the visible path's owned objects and (fixed capacity) the covers
     * the ledger marks free. [otherAnchors] are the dummy slot's two anchors.
     */
    fun assertNoOrphans(root: Path, masterKey: ByteArray, otherAnchors: Set<String>) {
        val m = metadata(root, masterKey)
        val expected = HashSet<String>(otherAnchors)
        expected += ObjectNames.metadataAnchor(masterKey)
        expected += m.ownedObjectNames
        m.fixedCapacity?.let { state ->
            for (bucket in state.ledger.buckets) {
                for (i in bucket.coveredSlots()) expected += ObjectNames.cover(masterKey, bucket.plaintextByteCount, i)
            }
        }
        assertEquals(expected.sorted(), objectFiles(root).keys.sorted())
    }

    /** Pool objects that are neither this key's metadata nor owned: the other anchors at creation time. */
    fun otherAnchors(root: Path, masterKey: ByteArray): Set<String> {
        val m = metadata(root, masterKey)
        val mine = m.ownedObjectNames + ObjectNames.metadataAnchor(masterKey)
        val covers = m.fixedCapacity?.let { state ->
            state.ledger.buckets.flatMap { b -> (0 until b.slotCount).map { ObjectNames.cover(masterKey, b.plaintextByteCount, it) } }
        }.orEmpty().toSet()
        return objectFiles(root).keys.filter { it !in mine && it !in covers }.toSet()
    }

    /** Objects are never modified in place, so a hard-linked copy is an exact, cheap snapshot. */
    fun linkCopy(from: Path, to: Path) {
        Files.createDirectories(to.resolve("objects"))
        Files.createLink(to.resolve(V2Format.ENVELOPE_NAME), from.resolve(V2Format.ENVELOPE_NAME))
        for (path in from.resolve("objects").listDirectoryEntries()) {
            if (!path.name.startsWith(".")) Files.createLink(to.resolve("objects").resolve(path.name), path)
        }
    }

    fun readAll(root: Path, password: String, entry: VaultEntry): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        V2VaultReader(JvmSodium, root).unlock(password).use { it.readEntry(entry, out) }
        return out.toByteArray()
    }

    fun newID(): UUID = UUID.randomUUID()
}
