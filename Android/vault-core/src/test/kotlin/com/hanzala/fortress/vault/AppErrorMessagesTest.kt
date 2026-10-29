package com.hanzala.fortress.vault

import com.hanzala.fortress.vault.WriterTestSupport.writer
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The Android app (`VaultViewModel`) tells "wrong password" and "invalid
 * recovery key" apart from a damaged vault by these exact messages. Changing
 * them here must change the app too.
 */
class AppErrorMessagesTest {
    private val temp: Path = Files.createTempDirectory("hanzala-messages-test")
    private val vault = temp.resolve("vault")

    @AfterTest
    fun cleanUp() {
        temp.toFile().deleteRecursively()
    }

    @Test
    fun sessionOpenFailuresKeepTheMessagesTheAppMatches() {
        val created = writer(vault).createVault("the right password")
        assertEquals("wrong password", assertFailsWith<VaultFormatException> { writer(vault).openSession("not it at all") }.message)

        val wellFormedButWrong = "HZRK-" + "0".repeat(64).chunked(4).joinToString("-")
        for (key in listOf(wellFormedButWrong, "HZRK-1234", "not a key", created.recoveryKey.dropLast(1))) {
            assertEquals(
                "invalid recovery key",
                assertFailsWith<VaultFormatException> { writer(vault).openSessionWithRecoveryKey(key) }.message,
            )
        }
    }
}
