package com.hanzala.fortress.vault

import com.hanzala.fortress.vault.WriterTestSupport.assertNoOrphans
import com.hanzala.fortress.vault.WriterTestSupport.bytes
import com.hanzala.fortress.vault.WriterTestSupport.linkCopy
import com.hanzala.fortress.vault.WriterTestSupport.masterKey
import com.hanzala.fortress.vault.WriterTestSupport.metadata
import com.hanzala.fortress.vault.WriterTestSupport.objectFiles
import com.hanzala.fortress.vault.WriterTestSupport.otherAnchors
import com.hanzala.fortress.vault.WriterTestSupport.readAll
import com.hanzala.fortress.vault.WriterTestSupport.writer
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Power loss after every durable step of import and removal (each staging
 * create/write/sync, rename and unlink), in an ordinary and a fixed-capacity
 * vault. Reopening must complete or abort exactly as Swift's recovery does,
 * leave valid metadata with no pending work, no orphan owned names and (fixed
 * capacity) the same pool shape.
 */
class CrashRecoveryTest {
    private val temp: Path = Files.createTempDirectory("hanzala-crash-test")
    private val password = "crash test password"
    private val newSmall = bytes(3000, 11)
    private val newBig = bytes(V2Format.MAX_SINGLE_CONTENT + 5, 12)
    private val bigSource = temp.resolve("new-big.bin").also { Files.write(it, newBig) }
    private val contents = mapOf(
        "keep.txt" to bytes(700, 13),
        "victim.txt" to bytes(20_000, 14),
        "victim-big.bin" to bytes(V2Format.MAX_SINGLE_CONTENT + 77, 15),
        "new.txt" to newSmall,
        "new-big.bin" to newBig,
    )

    @AfterTest
    fun cleanUp() {
        temp.toFile().deleteRecursively()
    }

    private class Injector(private val crashAt: Int) : FaultInjector {
        var count = 0
        override fun reached(point: CrashPoint, destination: Path) {
            count++
            if (count == crashAt) throw SimulatedCrash(point)
        }
    }

    private enum class Op(val target: String, val isImport: Boolean) {
        IMPORT_SMALL("new.txt", true), IMPORT_CHUNKED("new-big.bin", true),
        REMOVE_SMALL("victim.txt", false), REMOVE_CHUNKED("victim-big.bin", false),
    }

    private fun run(op: Op, session: V2VaultSession) {
        when (op) {
            Op.IMPORT_SMALL -> session.importData(newSmall, "new.txt")
            Op.IMPORT_CHUNKED -> session.importFile(bigSource)
            else -> session.removeEntry(session.entries.first { it.originalName == op.target }.id)
        }
    }

    private fun base(fixed: Boolean): Pair<Path, String> {
        val root = temp.resolve(if (fixed) "base-fixed" else "base")
        val created = writer(root).createVault(password, if (fixed) FixedCapacityPlan.MIN_CAPACITY else null)
        writer(root).openSession(password).use { s ->
            for (name in listOf("keep.txt", "victim.txt")) s.importData(contents.getValue(name), name)
            val big = temp.resolve("victim-big.bin")
            Files.write(big, contents.getValue("victim-big.bin"))
            s.importFile(big)
        }
        return root to created.recoveryKey
    }

    private fun crashEverywhere(fixed: Boolean, ops: List<Op>) {
        val (base, recoveryKey) = base(fixed)
        val key = masterKey(base, recoveryKey)
        val anchors = otherAnchors(base, key)
        val shape = objectFiles(base).values.sorted()
        for (op in ops) {
            val dry = temp.resolve("dry")
            linkCopy(base, dry)
            val counter = Injector(0)
            writer(dry, counter).openSession(password).use { run(op, it) }
            dry.toFile().deleteRecursively()
            assertTrue(counter.count > 4, "$op has crash points")

            for (k in 1..counter.count) {
                val dir = temp.resolve("crash")
                linkCopy(base, dir)
                val injector = Injector(k)
                val crash = assertFailsWith<SimulatedCrash> { writer(dir, injector).openSession(password).use { run(op, it) } }
                val label = "$op fixed=$fixed crash #$k at ${crash.point}"

                // What recovery must do, decided from the state the crash left.
                val before = metadata(dir, key)
                val expectPresent = if (op.isImport) {
                    expectImportFinalized(dir, before, op.target)
                } else {
                    before.entries.any { it.originalName == op.target }
                }

                writer(dir).openSession(password).use { s ->
                    val m = s.metadata()
                    assertFalse(m.hasPendingWork, label)
                    assertEquals(before.hasPendingWork, !s.recovery.isEmpty, label)
                    assertEquals(expectPresent, m.entries.any { it.originalName == op.target }, label)
                    val others = contents.keys.filter { it != op.target && it != "new.txt" && it != "new-big.bin" }
                    assertEquals(others.toSet(), m.entries.map { it.originalName }.filter { it != op.target }.toSet(), label)
                    m.entries.firstOrNull { it.originalName == op.target }?.let {
                        assertContentEquals(contents.getValue(op.target), readAll(dir, password, it), label)
                    }
                }
                assertNoOrphans(dir, key, anchors)
                if (fixed) assertEquals(shape, objectFiles(dir).values.sorted(), label)

                // The interrupted operation can simply be done again.
                if (!op.isImport || op == Op.IMPORT_SMALL) {
                    writer(dir).openSession(password).use { s ->
                        if (op.isImport || s.entries.any { it.originalName == op.target }) run(op, s)
                        assertFalse(s.metadata().hasPendingWork, label)
                    }
                    assertNoOrphans(dir, key, anchors)
                    if (fixed) assertEquals(shape, objectFiles(dir).values.sorted(), label)
                }
                dir.toFile().deleteRecursively()
            }
        }
    }

    /** Swift's rule: a single object present → finalize; a chunked import with a manifest or every chunk → finalize. */
    private fun expectImportFinalized(dir: Path, m: AccessMetadata, target: String): Boolean {
        if (m.entries.any { it.originalName == target }) return true
        val objects = dir.resolve("objects")
        m.pendingImports.firstOrNull { it.originalName == target }?.let { return Files.exists(objects.resolve(it.opaqueObjectName)) }
        m.pendingChunkImports.firstOrNull { it.originalName == target }?.let { p ->
            return Files.exists(objects.resolve(p.manifestObjectName)) ||
                p.chunks.all { Files.exists(objects.resolve(it.opaqueObjectName)) }
        }
        return false
    }

    @Test
    fun ordinaryVaultSurvivesACrashAfterEveryStep() = crashEverywhere(false, Op.entries)

    @Test
    fun fixedCapacityVaultSurvivesACrashAfterEveryStep() = crashEverywhere(true, Op.entries)

    @Test
    fun interruptedFixedCapacityFillResumes() {
        val root = temp.resolve("fill")
        val created = writer(root).createVault(password)
        // Crash a quarter of the way through the cover fill.
        val crashAt = (FixedCapacityPlan.slots(FixedCapacityPlan.MIN_CAPACITY).sumOf { it.slotCount } * 4 / 4).toInt()
        assertFailsWith<SimulatedCrash> {
            writer(root, Injector(crashAt)).openSession(password).use { it.prepareFixedCapacity(FixedCapacityPlan.MIN_CAPACITY) }
        }
        val key = masterKey(root, created.recoveryKey)
        assertEquals(false, metadata(root, key).fixedCapacity?.isFilled)
        writer(root).openSession(password).use { s ->
            assertFailsWith<VaultFormatException> { s.importData(byteArrayOf(1), "early.txt") }
            s.prepareFixedCapacity(FixedCapacityPlan.MIN_CAPACITY)
            assertEquals(true, s.fixedCapacityStatus()?.isFilled)
            s.importData(byteArrayOf(1), "after.txt")
        }
        val plan = FixedCapacityPlan.slots(FixedCapacityPlan.MIN_CAPACITY)
        assertEquals(plan.sumOf { it.slotCount }.toInt() + 4, objectFiles(root).size)
    }
}
