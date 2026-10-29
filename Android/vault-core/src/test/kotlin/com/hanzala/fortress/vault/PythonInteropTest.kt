package com.hanzala.fortress.vault

import com.hanzala.fortress.vault.WriterTestSupport.bytes
import com.hanzala.fortress.vault.WriterTestSupport.writer
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Vaults written by the Kotlin writer open in the Python reference reader
 * (`Scripts/vault_format_reference/open_vault.py`, written from the spec only).
 * Skipped when python3 with PyNaCl is not installed.
 */
class PythonInteropTest {
    private val fixture: Path = Paths.get(System.getProperty("hanzala.vectors.dir"))
    private val repo: Path = fixture.resolve("../../../..").normalize()
    private val script = repo.resolve("Scripts/vault_format_reference/open_vault.py")
    private val temp: Path = Files.createTempDirectory("hanzala-interop-test")

    @AfterTest
    fun cleanUp() {
        temp.toFile().deleteRecursively()
    }

    private fun pythonAvailable(): Boolean = try {
        val p = ProcessBuilder("python3", "-c", "import nacl.bindings").redirectErrorStream(true).start()
        p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0
    } catch (e: Exception) {
        false
    }

    private fun openWithPython(vault: Path, vararg credential: String): String {
        val process = ProcessBuilder(listOf("python3", script.toString(), vault.toString()) + credential)
            .directory(script.parent.toFile()).redirectErrorStream(true)
            // Leave no __pycache__ in the repository.
            .apply { environment()["PYTHONDONTWRITEBYTECODE"] = "1" }
            .start()
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "python reader timed out")
        assertEquals(0, process.exitValue(), output)
        println("python open_vault.py ${credential[0]}:\n$output")
        return output
    }

    private fun sha256(data: ByteArray) = Hex.encode(DomainKeys.sha256(data))

    @Test
    fun fixtureCopyWrittenByKotlinStillOpensInPython() {
        assumeTrue(pythonAvailable(), "python3 with PyNaCl is not installed; skipping the Python reader check")
        val vectors = JsonFields(SwiftJson.parse(Files.readAllBytes(fixture.resolve("vectors.json"))), "v").obj("fixtureVault")
        val password = vectors.string("password")
        val vault = temp.resolve("vault")
        fixture.resolve(vectors.string("directory")).toFile().copyRecursively(vault.toFile())

        val added = bytes(50_000, 21)
        writer(vault).openSession(password).use { s ->
            val before = s.entries
            s.importData(added, "from android.bin")
            s.removeEntry(before.first().id)
        }
        for (credential in listOf(arrayOf("--password", password), arrayOf("--recovery-key", vectors.string("recoveryKey")))) {
            val output = openWithPython(vault, *credential)
            assertTrue(output.contains("from android.bin") && output.contains(sha256(added)), output)
            assertFalse(output.contains("hello world.txt"), output)
        }
    }

    @Test
    fun kotlinCreatedFixedCapacityVaultOpensInPython() {
        assumeTrue(pythonAvailable(), "python3 with PyNaCl is not installed; skipping the Python reader check")
        val vault = temp.resolve("fixed")
        val password = "interop password"
        val created = writer(vault).createVault(password, FixedCapacityPlan.MIN_CAPACITY)
        val small = "مرحبا من أندرويد".toByteArray()
        val big = bytes(V2Format.MAX_SINGLE_CONTENT + 333, 22)
        val bigFile = temp.resolve("big.bin").also { Files.write(it, big) }
        writer(vault).openSession(password).use { s ->
            s.importData(small, "salam.txt")
            s.importFile(bigFile)
            s.importData(byteArrayOf(9), "removed.txt").also { s.removeEntry(it.id) }
        }
        for (credential in listOf(arrayOf("--password", password), arrayOf("--recovery-key", created.recoveryKey))) {
            val output = openWithPython(vault, *credential)
            assertTrue(output.contains(sha256(small)) && output.contains(sha256(big)), output)
            assertFalse(output.contains("removed.txt"), output)
        }
    }
}
