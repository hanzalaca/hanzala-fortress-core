package com.hanzala.fortress.vault

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.io.path.listDirectoryEntries
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/** Reader behaviour on vaults built by [TestVaultBuilder]: chunked files, tampering, KDF limits. */
class ReaderBehaviourTest {
    private val temp: Path = Files.createTempDirectory("hanzala-reader-test")
    private val vault = temp.resolve("vault")
    private val out = temp.resolve("out").also { Files.createDirectories(it) }
    private val password = "كلمة سر"

    @AfterTest
    fun cleanUp() {
        temp.toFile().deleteRecursively()
    }

    /** Just over the single-object limit: four full chunks and one short one. */
    private val big = ByteArray(V2Format.MAX_SINGLE_CONTENT + 1) { (it * 31).toByte() }

    @Test
    fun readsChunkedAndSmallFilesWithPasswordAndRecoveryKey() {
        val builder = TestVaultBuilder(vault, password)
        val small = "hello".toByteArray()
        builder.build(listOf(TestVaultBuilder.File("small.txt", small), TestVaultBuilder.File("big.bin", big)))
        val reader = V2VaultReader(JvmSodium, vault)
        for (opened in listOf(reader.unlock(password), reader.recover(builder.recoveryKey))) {
            opened.use {
                assertEquals(listOf("small.txt", "big.bin"), it.entries.map { e -> e.originalName })
                assertEquals(5, it.entries[1].auxiliaryObjectNames.size)
                val buffer = ByteArrayOutputStream()
                it.readEntry(it.entries[0], buffer)
                assertContentEquals(small, buffer.toByteArray())
                val target = out.resolve("big.bin")
                Files.deleteIfExists(target)
                it.readEntryToFile(it.entries[1], target)
                assertContentEquals(big, Files.readAllBytes(target))
            }
        }
        assertEquals(listOf(out.resolve("big.bin")), out.listDirectoryEntries())
    }

    @Test
    fun refusesAnExistingDestination() {
        TestVaultBuilder(vault, password).build(listOf(TestVaultBuilder.File("a.txt", "new".toByteArray())))
        val target = out.resolve("a.txt")
        Files.write(target, "old".toByteArray())
        V2VaultReader(JvmSodium, vault).unlock(password).use {
            assertFailsWith<java.nio.file.FileAlreadyExistsException> { it.readEntryToFile(it.entries[0], target) }
        }
        assertContentEquals("old".toByteArray(), Files.readAllBytes(target))
        assertEquals(listOf(target), out.listDirectoryEntries())
    }

    @Test
    fun badDigestLeavesNoOutputFile() {
        TestVaultBuilder(vault, password).build(listOf(TestVaultBuilder.File("big.bin", big, digestOverride = ByteArray(32))))
        V2VaultReader(JvmSodium, vault).unlock(password).use {
            val e = assertFailsWith<VaultFormatException> { it.readEntryToFile(it.entries[0], out.resolve("big.bin")) }
            assertEquals("digest mismatch", e.message)
        }
        assertEquals(emptyList(), out.listDirectoryEntries())
    }

    @Test
    fun manifestMustBelongToItsEntry() {
        TestVaultBuilder(vault, password).build(listOf(TestVaultBuilder.File("big.bin", big, manifestFileIDOverride = UUID.randomUUID())))
        V2VaultReader(JvmSodium, vault).unlock(password).use {
            val e = assertFailsWith<VaultFormatException> { it.readEntryToFile(it.entries[0], out.resolve("big.bin")) }
            assertEquals("manifest mismatch", e.message)
        }
        assertFalse(Files.exists(out.resolve("big.bin")))
    }

    @Test
    fun outOfRangeKdfParametersNeverReachLibsodium() {
        TestVaultBuilder(vault, password).build(emptyList(), slotMemLimit = (1L shl 30) + 1)
        val counting = CountingSodium()
        assertFailsWith<VaultFormatException> { V2VaultReader(counting, vault).unlock(password) }
        assertEquals(0, counting.kdfCalls)
    }

    @Test
    fun kdfFailureIsNotReportedAsWrongPassword() {
        TestVaultBuilder(vault, password).build(emptyList())
        val failing = CountingSodium(failKdf = true)
        assertFailsWith<KeyDerivationException> { V2VaultReader(failing, vault).unlock(password) }
        assertEquals(2, failing.kdfCalls)
    }

    private class CountingSodium(private val failKdf: Boolean = false) : Sodium by JvmSodium {
        var kdfCalls = 0

        override fun argon2id13(outputLength: Int, password: ByteArray, salt: ByteArray, opsLimit: Long, memLimit: Long): ByteArray? {
            kdfCalls++
            return if (failKdf) null else JvmSodium.argon2id13(outputLength, password, salt, opsLimit, memLimit)
        }
    }
}
