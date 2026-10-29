package com.hanzala.fortress.vault

import com.hanzala.fortress.vault.WriterTestSupport.bytes
import com.hanzala.fortress.vault.WriterTestSupport.masterKey
import com.hanzala.fortress.vault.WriterTestSupport.metadata
import com.hanzala.fortress.vault.WriterTestSupport.metadataBytes
import com.hanzala.fortress.vault.WriterTestSupport.objectFiles
import com.hanzala.fortress.vault.WriterTestSupport.readAll
import com.hanzala.fortress.vault.WriterTestSupport.writer
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Create, import, read back, remove and change the password, checked through the reader. */
class WriterRoundTripTest {
    private val temp: Path = Files.createTempDirectory("hanzala-writer-test")
    private val vault = temp.resolve("vault")
    private val password = "كلمة سر طويلة"

    @AfterTest
    fun cleanUp() {
        temp.toFile().deleteRecursively()
    }

    private val big = bytes(V2Format.MAX_SINGLE_CONTENT + 1000, 1)

    private fun bigFile(): Path = temp.resolve("big.bin").also { if (!Files.exists(it)) Files.write(it, big) }

    @Test
    fun createsAVaultTheReaderOpensWithPasswordAndRecoveryKey() {
        val created = writer(vault).createVault(password)
        val reader = V2VaultReader(JvmSodium, vault)
        assertEquals(VaultFormatVersion.V2, reader.detectFormat())
        for (open in listOf({ reader.unlock(password) }, { reader.recover(created.recoveryKey) })) {
            open().use {
                assertEquals(created.vaultID, it.vaultID)
                assertEquals(AccessRole.VISIBLE, it.role)
                assertEquals(0, it.metadata.generation)
                assertTrue(it.entries.isEmpty())
            }
        }
        // §13: two metadata anchors and two recovery anchors, all 4 KiB, nothing staged.
        val files = objectFiles(vault)
        assertEquals(4, files.size)
        assertTrue(files.values.all { it == 4096L + V2Format.POOL_OVERHEAD })
        assertEquals(listOf("objects", "vault.hanzala"), Files.list(vault).use { s -> s.map { it.fileName.toString() }.sorted().toList() })
        // Slot 1 is a dummy: a random password, never the user's.
        assertFailsWith<VaultFormatException> { reader.unlock("wrong") }
        val envelope = reader.readEnvelope()
        assertEquals(listOf(1L, 1L), envelope.slots.map { it.opsLimit })
        assertFalse(envelope.slots[0].salt.contentEquals(envelope.slots[1].salt))
        assertFailsWith<VaultFormatException> { writer(vault).createVault(password) }
    }

    @Test
    fun importsReadsAndRemovesSmallAndChunkedFiles() {
        val created = writer(vault).createVault(password)
        val small = "hello android".toByteArray()
        val medium = bytes(100_000, 2)
        Files.write(temp.resolve("medium.bin"), medium)
        val ids = writer(vault).openSession(password).use { s ->
            assertTrue(s.recovery.isEmpty)
            val a = s.importData(small, "hello.txt")
            val b = s.importFile(temp.resolve("medium.bin"), "مستند.bin")
            val c = s.importFile(bigFile())
            assertTrue(c.isChunked)
            assertEquals(5, c.auxiliaryObjectNames.size)
            assertEquals(6, s.metadata().generation)
            val out = temp.resolve("out.bin")
            s.readEntryToFile(c, out)
            assertContentEquals(big, Files.readAllBytes(out))
            listOf(a, b, c)
        }
        // Readers see the same files, with the password and the recovery key.
        val reader = V2VaultReader(JvmSodium, vault)
        for (open in listOf({ reader.unlock(password) }, { reader.recover(created.recoveryKey) })) {
            open().use { v ->
                assertEquals(listOf("hello.txt", "مستند.bin", "big.bin"), v.entries.map { it.originalName })
                assertEquals(ids, v.entries)
            }
        }
        assertContentEquals(small, readAll(vault, password, ids[0]))
        assertContentEquals(medium, readAll(vault, password, ids[1]))
        assertContentEquals(big, readAll(vault, password, ids[2]))

        // Sizes on disk: §6.1 buckets, chunks at 4 MiB.
        val files = objectFiles(vault)
        assertEquals(4096L + 48, files[ids[0].opaqueObjectName])
        assertEquals(262144L + 48, files[ids[1].opaqueObjectName])
        ids[2].auxiliaryObjectNames.forEach { assertEquals(4194304L + 48, files[it]) }

        writer(vault).openSession(password).use { s ->
            s.removeEntry(ids[2].id)
            s.removeEntry(ids[0].id)
            assertFailsWith<EntryNotFoundException> { s.removeEntry(ids[0].id) }
            val m = s.metadata()
            assertEquals(10, m.generation)
            assertEquals(listOf(ids[1]), m.entries)
            assertEquals(UsageLedger(100_000, 1), m.usage)
            assertFalse(m.hasPendingWork)
        }
        val remaining = objectFiles(vault).keys
        (ids[2].allObjectNames + ids[0].opaqueObjectName).forEach { assertFalse(it in remaining) }
        assertEquals(5, remaining.size)
        assertContentEquals(medium, readAll(vault, password, ids[1]))
    }

    @Test
    fun writtenJsonReencodesToTheSameBytes() {
        val created = writer(vault).createVault(password)
        writer(vault).openSession(password).use { s ->
            s.importData("a/b".toByteArray(), "x.txt")
            s.importFile(bigFile())
        }
        val key = masterKey(vault, created.recoveryKey)
        val metadata = metadataBytes(vault, key)
        assertContentEquals(metadata, SwiftJson.encode(SwiftJson.parse(metadata), escapeSlashes = true))
        assertContentEquals(metadata, AccessMetadata.parse(metadata).encode())
        val envelope = Files.readAllBytes(vault.resolve(V2Format.ENVELOPE_NAME))
        assertContentEquals(envelope, SwiftJson.encode(SwiftJson.parse(envelope), escapeSlashes = false))
        assertContentEquals(envelope, AccessEnvelope.parse(envelope).encode())

        val reader = V2VaultReader(JvmSodium, vault)
        val secret = RecoveryKeyText.parse(created.recoveryKey)
        val anchor = ObjectNames.recoveryAnchor(secret, created.vaultID)
        val recovery = PoolObjectCodec(JvmSodium).open(Files.readAllBytes(vault.resolve("objects").resolve(anchor)), secret, anchor)
        assertContentEquals(recovery.content, SwiftJson.encode(SwiftJson.parse(recovery.content), escapeSlashes = false))
        assertEquals(setOf("accessID", "formatVersion", "masterKey", "roleRawValue", "vaultID"), SwiftJson.parse(recovery.content).keys)

        val entry = reader.unlock(password).use { it.entries[1] }
        val manifest = PoolObjectCodec(JvmSodium).open(
            Files.readAllBytes(vault.resolve("objects").resolve(entry.opaqueObjectName)), key, entry.opaqueObjectName,
        ).content
        assertContentEquals(manifest, SwiftJson.encode(SwiftJson.parse(manifest), escapeSlashes = false))
        assertContentEquals(manifest, ChunkManifest.parse(manifest).encode())
    }

    @Test
    fun fixtureMetadataRoundTripsThroughTheFullModel() {
        val fixture = Paths.get(System.getProperty("hanzala.vectors.dir"))
        val vectors = SwiftJson.parse(Files.readAllBytes(fixture.resolve("vectors.json")))
        val hex = JsonFields(vectors, "v").obj("fixtureVault").string("metadataJSONHex")
        val bytes = Hex.decode(hex)
        assertContentEquals(bytes, AccessMetadata.parse(bytes).encode())
    }

    @Test
    fun changesThePasswordAndKeepsTheRecoveryKey() {
        val created = writer(vault).createVault(password)
        val before = V2VaultReader(JvmSodium, vault).readEnvelope()
        writer(vault).openSession(password).use { s ->
            s.importData("kept".toByteArray(), "kept.txt")
            s.changePassword("new password")
            // The session stays usable after its own change.
            s.importData("after".toByteArray(), "after.txt")
        }
        val reader = V2VaultReader(JvmSodium, vault)
        assertFailsWith<VaultFormatException> { reader.unlock(password) }
        reader.unlock("new password").use { assertEquals(listOf("kept.txt", "after.txt"), it.entries.map { e -> e.originalName }) }
        reader.recover(created.recoveryKey).use { assertEquals(2, it.entries.size) }
        val after = reader.readEnvelope()
        assertEquals(before.vaultID, after.vaultID)
        assertEquals(before.createdAt, after.createdAt)
        assertContentEquals(before.slots[1].wrappedPayload, after.slots[1].wrappedPayload)
        assertContentEquals(before.slots[1].salt, after.slots[1].salt)
        assertFalse(before.slots[0].salt.contentEquals(after.slots[0].salt))
        assertFalse(before.slots[0].wrappedPayload.copyOfRange(0, 24).contentEquals(after.slots[0].wrappedPayload.copyOfRange(0, 24)))

        // From a recovery-key session too, e.g. after a forgotten password.
        writer(vault).openSessionWithRecoveryKey(created.recoveryKey).use { it.changePassword("third password") }
        assertFailsWith<VaultFormatException> { reader.unlock("new password") }
        reader.unlock("third password").use { assertEquals(2, it.entries.size) }

        // A session bound to the old envelope fails closed.
        val stale = writer(vault).openSession("third password")
        writer(vault).openSession("third password").use { it.changePassword("fourth password") }
        assertFailsWith<SessionInvalidatedException> { stale.importData("x".toByteArray(), "x") }
        stale.close()
    }

    @Test
    fun fixedCapacityKeepsThePoolShape() {
        val progress = ArrayList<Pair<Long, Long>>()
        val created = writer(vault).createVault(password, FixedCapacityPlan.MIN_CAPACITY) { done, total -> progress += done to total }
        val plan = FixedCapacityPlan.slots(FixedCapacityPlan.MIN_CAPACITY)
        val slots = plan.sumOf { it.slotCount }
        assertEquals((1..slots).map { it to slots }, progress)
        val key = masterKey(vault, created.recoveryKey)
        val shape = objectFiles(vault).values.sorted()
        assertEquals(slots.toInt() + 4, shape.size)
        assertEquals(1048576L + 48, objectFiles(vault)[ObjectNames.metadataAnchor(key)])
        val initial = metadata(vault, key)
        assertEquals(2, initial.generation)
        assertEquals(true, initial.fixedCapacity?.isFilled)

        val small = bytes(5000, 3)
        val entries = writer(vault).openSession(password).use { s ->
            val status = s.fixedCapacityStatus()!!
            assertEquals(status.slotPlaintextBytes, status.freePlaintextBytes)
            val a = s.importData(small, "small.bin")
            assertEquals(shape, objectFiles(vault).values.sorted())
            val b = s.importFile(bigFile())
            assertEquals(shape, objectFiles(vault).values.sorted())
            // Five chunks plus a manifest and one 16 KiB object took seven slots.
            val m = s.metadata()
            assertEquals(slots - 7, m.fixedCapacity!!.ledger.freeSlotCount)
            assertEquals(16384L + 48, objectFiles(vault)[a.opaqueObjectName])
            assertTrue(s.fixedCapacityStatus()!!.freePlaintextBytes < status.freePlaintextBytes)
            listOf(a, b)
        }
        assertContentEquals(small, readAll(vault, password, entries[0]))
        assertContentEquals(big, readAll(vault, password, entries[1]))
        WriterTestSupport.assertNoOrphans(vault, key, WriterTestSupport.otherAnchors(vault, key))

        // Nine more chunks than the eight free 4 MiB slots: refused before any write.
        val tooBig = temp.resolve("too-big.bin")
        Files.write(tooBig, bytes(V2Format.CHUNK_CONTENT * 8 + 1, 4))
        val generation = metadata(vault, key).generation
        writer(vault).openSession(password).use { s ->
            assertFailsWith<VaultFullException> { s.importFile(tooBig) }
            assertEquals(generation, s.metadata().generation)
            assertEquals(shape, objectFiles(vault).values.sorted())
            s.removeEntry(entries[1].id)
            assertEquals(shape, objectFiles(vault).values.sorted())
            s.removeEntry(entries[0].id)
            assertEquals(shape, objectFiles(vault).values.sorted())
            assertEquals(slots, s.metadata().fixedCapacity!!.ledger.freeSlotCount)
            assertNotNull(s.fixedCapacityStatus())
            // Resuming a finished fill is a no-op.
            s.prepareFixedCapacity(FixedCapacityPlan.MIN_CAPACITY)
        }
        WriterTestSupport.assertNoOrphans(vault, key, WriterTestSupport.otherAnchors(vault, key))
        V2VaultReader(JvmSodium, vault).recover(created.recoveryKey).use { assertTrue(it.entries.isEmpty()) }
    }

    @Test
    fun aSourceThatChangesBetweenPassesIsRolledBack() {
        val created = writer(vault).createVault(password, FixedCapacityPlan.MIN_CAPACITY)
        val key = masterKey(vault, created.recoveryKey)
        val shape = objectFiles(vault).values.sorted()
        var passes = 0
        val changing = object : ImportSource {
            override val size = big.size.toLong()
            override fun openStream(): InputStream {
                passes++
                val content = if (passes == 1) big else big.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
                return content.inputStream()
            }
        }
        writer(vault).openSession(password).use { s ->
            assertFailsWith<ImportSourceException> { s.importSource(changing, "changing.bin") }
            val m = s.metadata()
            assertFalse(m.hasPendingWork)
            assertTrue(m.entries.isEmpty())
            assertEquals(m.fixedCapacity!!.plan().sumOf { it.slotCount }, m.fixedCapacity!!.ledger.freeSlotCount)
        }
        assertEquals(shape, objectFiles(vault).values.sorted())
        WriterTestSupport.assertNoOrphans(vault, key, WriterTestSupport.otherAnchors(vault, key))
    }

    @Test
    fun refusesUnsafeNamesAndSymlinks() {
        writer(vault).createVault(password)
        writer(vault).openSession(password).use { s ->
            for (bad in listOf("", ".", "..", "a/b", "a\\b")) {
                assertFailsWith<VaultFormatException>(bad) { s.importData(byteArrayOf(1), bad) }
            }
            val target = temp.resolve("target.txt").also { Files.write(it, byteArrayOf(1)) }
            val link = Files.createSymbolicLink(temp.resolve("link.txt"), target)
            assertFailsWith<ImportSourceException> { s.importFile(link) }
            assertTrue(s.entries.isEmpty())
        }
        assertNull(V2VaultReader(JvmSodium, vault).unlock(password).use { it.entries.firstOrNull() })
    }

    @Test
    fun productionKdfIsSwiftsModerateSetting() {
        assertEquals(KdfParameters(3, 268_435_456), KdfParameters.PRODUCTION)
        assertEquals(StorageBudget(64L shl 30, 256L shl 20, 0), StorageBudget.APP_DEFAULT)
    }
}
