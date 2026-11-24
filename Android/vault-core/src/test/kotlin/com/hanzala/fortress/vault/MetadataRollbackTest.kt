package com.hanzala.fortress.vault

import com.hanzala.fortress.vault.WriterTestSupport.FAST_KDF
import com.hanzala.fortress.vault.WriterTestSupport.PLENTY
import com.hanzala.fortress.vault.WriterTestSupport.bytes
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Rollback protection (Swift `V2MetadataRollbackTests`): putting back an older
 * copy of the vault folder, for example to bring back a deleted file, is
 * refused on a device that already saw a newer copy, unless the owner opens
 * the older copy on purpose.
 */
class MetadataRollbackTest {
    private val temp: Path = Files.createTempDirectory("hanzala-rollback-test")
    private val vault = temp.resolve("vault")
    private val snapshot = temp.resolve("snapshot")
    private val password = "كلمة سر طويلة"

    @AfterTest
    fun cleanUp() {
        temp.toFile().deleteRecursively()
    }

    private fun writer(store: MetadataWatermarkStore?) =
        V2VaultWriter(JvmSodium, vault, FAST_KDF, PLENTY, null, store)

    private fun takeSnapshot() {
        snapshot.toFile().deleteRecursively()
        vault.toFile().copyRecursively(snapshot.toFile())
    }

    private fun restoreSnapshot() {
        vault.toFile().deleteRecursively()
        snapshot.toFile().copyRecursively(vault.toFile())
    }

    /** A vault with one file, snapshotted, then the file removed (a newer generation). */
    private fun vaultWithRemovedFile(store: MetadataWatermarkStore): String {
        writer(store).createVault(password)
        writer(store).openSession(password).use { it.importData(bytes(100, 1), "secret.txt") }
        takeSnapshot()
        writer(store).openSession(password).use { session ->
            session.removeEntry(session.entries.single().id)
            assertTrue(session.entries.isEmpty())
        }
        return "secret.txt"
    }

    @Test
    fun olderCopyIsRefusedWithThePassword() {
        val store = InMemoryMetadataWatermarkStore()
        vaultWithRemovedFile(store)
        restoreSnapshot()
        assertFailsWith<OlderCopyDetectedException> { writer(store).openSession(password) }
    }

    @Test
    fun olderCopyIsRefusedWithTheRecoveryKey() {
        val store = InMemoryMetadataWatermarkStore()
        val created = writer(store).createVault(password)
        writer(store).openSession(password).use { it.importData(bytes(50, 2), "a.txt") }
        takeSnapshot()
        writer(store).openSession(password).use { it.importData(bytes(50, 3), "b.txt") }
        restoreSnapshot()
        assertFailsWith<OlderCopyDetectedException> { writer(store).openSessionWithRecoveryKey(created.recoveryKey) }
    }

    @Test
    fun ownerCanOpenTheOlderCopyOnPurposeAndThenItOpensNormally() {
        val store = InMemoryMetadataWatermarkStore()
        val name = vaultWithRemovedFile(store)
        restoreSnapshot()
        writer(store).openSession(password, acceptingOlderCopy = true).use {
            assertEquals(listOf(name), it.entries.map { e -> e.originalName })
        }
        // Accepted once: the device now remembers this copy.
        writer(store).openSession(password).use { assertEquals(1, it.entries.size) }
    }

    @Test
    fun refusedOpenWritesNothingToTheVault() {
        val store = InMemoryMetadataWatermarkStore()
        vaultWithRemovedFile(store)
        restoreSnapshot()
        val before = WriterTestSupport.objectFiles(vault)
        assertFailsWith<OlderCopyDetectedException> { writer(store).openSession(password) }
        assertEquals(before, WriterTestSupport.objectFiles(vault))
    }

    @Test
    fun aNewDeviceWithoutAWatermarkOpensAnyCopy() {
        vaultWithRemovedFile(InMemoryMetadataWatermarkStore())
        restoreSnapshot()
        writer(InMemoryMetadataWatermarkStore()).openSession(password).use { assertEquals(1, it.entries.size) }
    }

    @Test
    fun withoutAStoreNothingIsChecked() {
        vaultWithRemovedFile(InMemoryMetadataWatermarkStore())
        restoreSnapshot()
        writer(null).openSession(password).use { assertEquals(1, it.entries.size) }
    }

    @Test
    fun aBrokenStoreNeverLocksTheOwnerOut() {
        val broken = object : MetadataWatermarkStore {
            override fun generation(key: String): Long? = throw java.io.IOException("unavailable")
            override fun setGeneration(key: String, generation: Long) = throw java.io.IOException("unavailable")
        }
        writer(broken).createVault(password)
        writer(broken).openSession(password).use { it.importData(bytes(10, 4), "x.txt") }
        writer(broken).openSession(password).use { assertEquals(1, it.entries.size) }
    }

    @Test
    fun anOlderCopyPutBackWhileTheVaultIsOpenIsNoticed() {
        val store = InMemoryMetadataWatermarkStore()
        writer(store).createVault(password)
        writer(store).openSession(password).use { it.importData(bytes(20, 5), "a.txt") }
        takeSnapshot()
        val session = writer(store).openSession(password)
        session.use {
            it.importData(bytes(20, 6), "b.txt")
            restoreSnapshot()
            assertFailsWith<OlderCopyDetectedException> { it.entries }
        }
    }

    @Test
    fun keysAreOpaqueAndDifferPerAccessPath() {
        val key = ByteArray(32) { it.toByte() }
        val vaultID = java.util.UUID.randomUUID()
        val a = MetadataWatermarkGuard.key(key, vaultID, java.util.UUID.randomUUID())
        val b = MetadataWatermarkGuard.key(key, vaultID, java.util.UUID.randomUUID())
        assertEquals(64, a.length)
        assertTrue(a != b)
        assertTrue(!a.contains(vaultID.toString().replace("-", "")))
    }
}
