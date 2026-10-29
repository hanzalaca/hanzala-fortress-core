package com.hanzala.fortress.vault

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** §8.2 checks a reader must apply, on hand-built metadata JSON. */
class MetadataValidationTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val c = "c".repeat(64)
    private val id1 = "F05D3565-DE5A-45AA-834C-750941703E48"
    private val id2 = "D8B40F20-00D9-463C-A8E8-9E99259AC9CA"

    private fun entry(id: String, name: String, length: Long, file: String = "x.txt") =
        """{"auxiliaryObjectNames":[],"createdAt":"2026-01-01T00:01:00Z","id":"$id","logicalByteCount":$length,"opaqueObjectName":"$name","originalName":"$file"}"""

    private fun metadata(
        entries: String,
        usage: String,
        removals: String = "[]",
        imports: String = "[]",
        budget: String = """{"reserveBytes":0,"safetyMarginBytes":0,"totalBytes":1000}""",
        extra: String = "",
    ) = (
        """{"accessID":"10F8A77D-8D05-492B-9CA7-35532A39928E","budget":$budget,"entries":$entries,"formatVersion":1,""" +
            """"generation":3,"pendingChunkImports":[],"pendingImports":$imports,"pendingRemovals":$removals,""" +
            """"tombstonedObjectNames":[],"usage":$usage$extra}"""
        ).toByteArray()

    @Test
    fun acceptsConsistentMetadata() {
        val m = AccessMetadata.parse(metadata("[${entry(id1, a, 10)},${entry(id2, b, 5)}]", """{"logicalBytes":15,"objectCount":2}"""))
        assertEquals(listOf(id1, id2), m.entries.map { Uuids.upper(it.id) })
        assertEquals(3, m.generation)
    }

    @Test
    fun rejectsUsageMismatch() {
        assertFailsWith<VaultFormatException> {
            AccessMetadata.parse(metadata("[${entry(id1, a, 10)}]", """{"logicalBytes":11,"objectCount":1}"""))
        }
    }

    @Test
    fun rejectsSharedObjectName() {
        assertFailsWith<VaultFormatException> {
            AccessMetadata.parse(metadata("[${entry(id1, a, 1)},${entry(id2, a, 1)}]", """{"logicalBytes":2,"objectCount":2}"""))
        }
    }

    @Test
    fun rejectsUnsafeOriginalName() {
        for (bad in listOf("", ".", "..", "a/b", "a\\\\b", "a\\u0000b")) {
            assertFailsWith<VaultFormatException>(bad) {
                AccessMetadata.parse(metadata("[${entry(id1, a, 1, bad)}]", """{"logicalBytes":1,"objectCount":1}"""))
            }
        }
    }

    @Test
    fun rejectsBadBudgets() {
        val usage = """{"logicalBytes":0,"objectCount":0}"""
        for (budget in listOf(
            """{"reserveBytes":0,"safetyMarginBytes":0,"totalBytes":0}""",
            """{"reserveBytes":10,"safetyMarginBytes":0,"totalBytes":10}""",
            """{"reserveBytes":5,"safetyMarginBytes":6,"totalBytes":10}""",
        )) {
            assertFailsWith<VaultFormatException>(budget) { AccessMetadata.parse(metadata("[]", usage, budget = budget)) }
        }
        assertFailsWith<VaultFormatException> {
            AccessMetadata.parse(metadata("[${entry(id1, a, 901)}]", """{"logicalBytes":901,"objectCount":1}""",
                budget = """{"reserveBytes":100,"safetyMarginBytes":0,"totalBytes":1000}"""))
        }
    }

    @Test
    fun pendingRemovalMustNotNameALiveEntryOrObject() {
        val removal = { entryID: String, name: String ->
            """[{"auxiliaryObjectNames":[],"createdAt":"2026-01-01T00:01:00Z","entryID":"$entryID","logicalByteCount":4,""" +
                """"opaqueObjectName":"$name","transactionID":"014F7631-FD0C-4403-8121-0DAA6A22F218"}]"""
        }
        val live = "[${entry(id1, a, 10)}]"
        val usage = """{"logicalBytes":10,"objectCount":1}"""
        // A committed removal: its entry already left `entries`.
        AccessMetadata.parse(metadata(live, usage, removals = removal(id2, b)))
        assertFailsWith<VaultFormatException> { AccessMetadata.parse(metadata(live, usage, removals = removal(id1, b))) }
        assertFailsWith<VaultFormatException> { AccessMetadata.parse(metadata(live, usage, removals = removal(id2, a))) }
    }

    @Test
    fun coverSlotsRequireFixedCapacity() {
        val import = """[{"coverSlot":{"bucketPlaintextByteCount":4096,"index":0},"createdAt":"2026-01-01T00:01:00Z",""" +
            """"logicalByteCount":1,"opaqueObjectName":"$c","originalName":"y","transactionID":"014F7631-FD0C-4403-8121-0DAA6A22F218"}]"""
        assertFailsWith<VaultFormatException> {
            AccessMetadata.parse(metadata("[]", """{"logicalBytes":0,"objectCount":0}""", imports = import))
        }
    }

    @Test
    fun fixedCapacityLedgerMustMatchThePlan() {
        val plan = FixedCapacityPlan.slots(FixedCapacityPlan.MIN_CAPACITY)
        fun ledger(allFree: Boolean, dropLast: Boolean = false) = plan.dropLast(if (dropLast) 1 else 0).joinToString(",") {
            val bitmap = ByteArray(((it.slotCount + 7) / 8).toInt())
            if (allFree) for (i in 0 until it.slotCount) bitmap[(i / 8).toInt()] = (bitmap[(i / 8).toInt()].toInt() or (1 shl (i % 8).toInt())).toByte()
            """{"coverBitmap":"${Codings.base64(bitmap)}","plaintextByteCount":${it.plaintextByteCount},"slotCount":${it.slotCount}}"""
        }
        val budget = """{"reserveBytes":0,"safetyMarginBytes":0,"totalBytes":${FixedCapacityPlan.MIN_CAPACITY}}"""
        val fc = { l: String -> ""","fixedCapacity":{"capacityBytes":${FixedCapacityPlan.MIN_CAPACITY},"isFilled":true,"ledger":{"buckets":[$l]}}""" }
        val empty = """{"logicalBytes":0,"objectCount":0}"""

        val m = AccessMetadata.parse(metadata("[]", empty, budget = budget, extra = fc(ledger(allFree = true))))
        assertEquals(FixedCapacityPlan.MIN_CAPACITY, m.fixedCapacityBytes)
        // Free covers + owned objects must equal the slot count.
        assertFailsWith<VaultFormatException> { AccessMetadata.parse(metadata("[]", empty, budget = budget, extra = fc(ledger(allFree = false)))) }
        assertFailsWith<VaultFormatException> {
            AccessMetadata.parse(metadata("[]", empty, budget = budget, extra = fc(ledger(allFree = true, dropLast = true))))
        }
    }

    @Test
    fun swiftJsonEscapes() {
        val json = SwiftJson.parse("""{"b":"a/b\u0001\n\"","a":1,"Z":[true,false]}""".toByteArray())
        assertContentEquals(
            """{"Z":[true,false],"a":1,"b":"a\/b\u0001\n\""}""".toByteArray(),
            SwiftJson.encode(json, escapeSlashes = true),
        )
        assertContentEquals(
            """{"Z":[true,false],"a":1,"b":"a/b\u0001\n\""}""".toByteArray(),
            SwiftJson.encode(json, escapeSlashes = false),
        )
    }

    @Test
    fun poolObjectRoundTrip() {
        val codec = PoolObjectCodec(JvmSodium)
        val key = JvmSodium.randomBytes(32)
        val content = "مرحبا".toByteArray()
        val sealed = codec.seal(PoolObjectKind.DATA, content, key, a, Padding.dataTarget(content.size.toLong()).toInt())
        assertEquals(4096 + V2Format.POOL_OVERHEAD, sealed.size)
        val opened = codec.open(sealed, key, a)
        assertEquals(PoolObjectKind.DATA, opened.kind)
        assertContentEquals(content, opened.content)
        assertFailsWith<VaultFormatException> { codec.open(sealed, JvmSodium.randomBytes(32), a) }
    }
}
