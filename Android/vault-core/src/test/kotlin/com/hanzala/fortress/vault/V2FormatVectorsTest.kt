package com.hanzala.fortress.vault

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Opens the committed fixture vault and checks every known-answer vector in
 * Tests/HanzalaomatorCoreTests/Fixtures/v2-format-vectors, the same files the
 * Swift and Python implementations check.
 */
class V2FormatVectorsTest {
    private val fixture: Path = Paths.get(System.getProperty("hanzala.vectors.dir"))
    private val vectors: JsonObject = Json.parseToJsonElement(Files.readString(fixture.resolve("vectors.json"))).jsonObject
    private val fv = vectors.obj("fixtureVault")
    private val vaultRoot = fixture.resolve(fv.str("directory"))
    private val reader = V2VaultReader(JvmSodium, vaultRoot)

    @Test
    fun opensFixtureWithPasswordAndRecoveryKey() {
        val openers = listOf({ reader.unlock(fv.str("password")) }, { reader.recover(fv.str("recoveryKey")) })
        for (open in openers) {
            open().use { vault ->
                assertEquals(fv.str("vaultID"), Uuids.upper(vault.vaultID))
                assertEquals(fv["role"]!!.jsonPrimitive.int, vault.role.raw)
                assertEquals(fv.str("accessID"), Uuids.upper(vault.metadata.accessID))
                assertEquals(fv["metadataGeneration"]!!.jsonPrimitive.long, vault.metadata.generation)
                val expected = fv["files"]!!.jsonArray.map { it.jsonObject }
                assertEquals(expected.map { it.str("name") }, vault.entries.map { it.originalName })
                for ((entry, file) in vault.entries.zip(expected)) {
                    assertEquals(file.str("id"), Uuids.upper(entry.id))
                    assertEquals(file.str("objectName"), entry.opaqueObjectName)
                    assertEquals(file.str("createdAt"), Codings.formatDate(entry.createdAt))
                    val out = ByteArrayOutputStream()
                    vault.readEntry(entry, out)
                    assertEquals(file.str("contentHex"), Hex.encode(out.toByteArray()))
                    assertEquals(file.str("sha256Hex"), Hex.encode(DomainKeys.sha256(out.toByteArray())))
                }
            }
        }
    }

    @Test
    fun refusesWrongPasswordAndRecoveryKey() {
        assertFailsWith<VaultFormatException> { reader.unlock("wrong password") }
        assertFailsWith<VaultFormatException> { reader.unlock(fv.str("password") + " ") }
        val other = RecoveryKeyText.format(ByteArray(32) { 7 })
        val e = assertFailsWith<VaultFormatException> { reader.recover(other) }
        assertEquals("invalid recovery key", e.message)
        assertFailsWith<VaultFormatException> { reader.recover("HZRK-not-a-key") }
    }

    @Test
    fun detectsV2() {
        assertEquals(VaultFormatVersion.V2, reader.detectFormat())
    }

    @Test
    fun swiftJsonReencodesFixtureBytes() {
        val metadata = Hex.decode(fv.str("metadataJSONHex"))
        assertContentEquals(metadata, SwiftJson.encode(SwiftJson.parse(metadata), escapeSlashes = true))
        val envelope = Files.readAllBytes(vaultRoot.resolve(V2Format.ENVELOPE_NAME))
        assertContentEquals(envelope, SwiftJson.encode(SwiftJson.parse(envelope), escapeSlashes = false))
        val recovery = Hex.decode(fv.str("recoveryPayloadJSONHex"))
        assertContentEquals(recovery, SwiftJson.encode(SwiftJson.parse(recovery), escapeSlashes = false))
        val manifest = Hex.decode(vectors.obj("manifestObject").str("contentJSONHex"))
        assertContentEquals(manifest, SwiftJson.encode(SwiftJson.parse(manifest), escapeSlashes = false))
    }

    @Test
    fun passwordKdf() {
        val k = vectors.obj("passwordKDF")
        assertEquals(AccessEnvelope.KDF_ALGORITHM, k.str("algorithm"))
        val key = JvmSodium.argon2id13(
            32, k.str("password").toByteArray(), Hex.decode(k.str("saltHex")),
            k["operationsLimit"]!!.jsonPrimitive.long, k["memoryLimit"]!!.jsonPrimitive.long,
        )
        assertEquals(k.str("keyHex"), Hex.encode(key!!))
    }

    @Test
    fun slotUnwrap() {
        val s = vectors.obj("slotUnwrap")
        val envelope = reader.readEnvelope()
        assertEquals(s.str("wrappedPayloadHex"), Hex.encode(envelope.slots[0].wrappedPayload))
        val password = vectors.obj("passwordKDF").str("password").toByteArray()
        val vaultID = Uuids.parse(s.str("vaultID"))
        val unlocker = SlotUnlocker(JvmSodium)
        val key = unlocker.unwrap(envelope.slots[0], password, vaultID)!!
        assertEquals(s["role"]!!.jsonPrimitive.int, key.role.raw)
        assertEquals(s.str("masterKeyHex"), Hex.encode(key.masterKey))
        assertNull(unlocker.unwrap(envelope.slots[1], password, vaultID))
        // The payload binds the vault ID: the same slot under another vault does not open.
        assertNull(unlocker.unwrap(envelope.slots[0], password, java.util.UUID.randomUUID()))
    }

    @Test
    fun domainKeys() {
        val d = vectors.obj("domainKeys")
        val ikm = Hex.decode(d.str("inputKeyHex"))
        assertEquals(d.str("namespaceV2Hex"), Hex.encode(DomainKeys.derive(ikm, DomainKeys.NAMESPACE_V2)))
        assertEquals(d.str("recoveryNamespaceV2Hex"), Hex.encode(DomainKeys.derive(ikm, DomainKeys.RECOVERY_NAMESPACE_V2)))
        assertEquals(d.str("poolObjectV2Hex"), Hex.encode(DomainKeys.derive(ikm, DomainKeys.POOL_OBJECT_V2)))
        assertEquals(d.str("indexV1Hex"), Hex.encode(DomainKeys.derive(ikm, DomainKeys.INDEX_V1)))
        assertEquals(d.str("objectV1Hex"), Hex.encode(DomainKeys.derive(ikm, DomainKeys.OBJECT_V1)))
        assertFailsWith<VaultFormatException> { DomainKeys.derive(ByteArray(31), DomainKeys.NAMESPACE_V2) }
    }

    @Test
    fun recoveryKeyText() {
        val r = vectors.obj("recoveryKey")
        val secret = Hex.decode(r.str("secretHex"))
        assertEquals(r.str("displayKey"), RecoveryKeyText.format(secret))
        r["acceptedInputs"]!!.jsonArray.forEach { assertContentEquals(secret, RecoveryKeyText.parse(it.jsonPrimitive.content)) }
        r["rejectedInputs"]!!.jsonArray.forEach {
            assertFailsWith<VaultFormatException> { RecoveryKeyText.parse(it.jsonPrimitive.content) }
        }
        assertEquals(r.str("anchorName"), ObjectNames.recoveryAnchor(secret, Uuids.parse(r.str("vaultID"))))
        val name = r.str("anchorName")
        val opened = PoolObjectCodec(JvmSodium).open(Files.readAllBytes(vaultRoot.resolve("objects").resolve(name)), secret, name)
        assertEquals(PoolObjectKind.RECOVERY_ANCHOR, opened.kind)
        assertEquals(fv.str("recoveryPayloadJSONHex"), Hex.encode(opened.content))
    }

    @Test
    fun objectNames() {
        val m = vectors.obj("metadataAnchor")
        assertEquals(m.str("name"), ObjectNames.metadataAnchor(Hex.decode(m.str("masterKeyHex"))))
        for (c in vectors["coverNames"]!!.jsonArray.map { it.jsonObject }) {
            val name = ObjectNames.cover(Hex.decode(c.str("masterKeyHex")), c["bucket"]!!.jsonPrimitive.long, c["index"]!!.jsonPrimitive.long)
            assertEquals(c.str("name"), name)
        }
    }

    @Test
    fun poolObjectOpensAndIsBoundToItsName() {
        val p = vectors.obj("poolObject")
        val file = Hex.decode(p.str("envelopeHex"))
        val key = Hex.decode(p.str("keyMaterialHex"))
        assertEquals(p["paddedPlaintextByteCount"]!!.jsonPrimitive.int + V2Format.POOL_OVERHEAD, file.size)
        val codec = PoolObjectCodec(JvmSodium)
        val opened = codec.open(file, key, p.str("objectName"))
        assertEquals(p["kind"]!!.jsonPrimitive.int, opened.kind.raw)
        assertEquals(p.str("contentHex"), Hex.encode(opened.content))
        assertFailsWith<VaultFormatException> { codec.open(file, key, p.str("otherObjectName")) }
        val tampered = file.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFailsWith<VaultFormatException> { codec.open(tampered, key, p.str("objectName")) }
    }

    @Test
    fun manifestObject() {
        val mo = vectors.obj("manifestObject")
        val opened = PoolObjectCodec(JvmSodium).open(Hex.decode(mo.str("envelopeHex")), Hex.decode(mo.str("keyMaterialHex")), mo.str("objectName"))
        assertEquals(PoolObjectKind.MANIFEST, opened.kind)
        assertEquals(mo.str("contentJSONHex"), Hex.encode(opened.content))
        val manifest = ChunkManifest.parse(opened.content)
        assertEquals(mo.str("fileID"), Uuids.upper(manifest.fileID))
        assertEquals(mo["logicalByteCount"]!!.jsonPrimitive.long, manifest.logicalByteCount)
        assertEquals(mo.str("sha256DigestHex"), Hex.encode(manifest.sha256Digest))
        val expected = mo["chunks"]!!.jsonArray.map { it.jsonObject.str("opaqueObjectName") to it.jsonObject["logicalByteCount"]!!.jsonPrimitive.long }
        assertEquals(expected, manifest.chunks)
    }

    @Test
    fun paddingTargets() {
        for (t in vectors["dataPaddingTargets"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(t["plaintextByteCount"]!!.jsonPrimitive.long, Padding.dataTarget(t["contentByteCount"]!!.jsonPrimitive.long))
        }
        for (t in vectors["metadataPaddingTargets"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(t["plaintextByteCount"]!!.jsonPrimitive.long, Padding.metadataTarget(t["encodedByteCount"]!!.jsonPrimitive.long))
        }
        assertFailsWith<VaultFormatException> { Padding.dataTarget(V2Format.MAX_SINGLE_CONTENT + 1L) }
    }

    @Test
    fun fixedCapacityPlans() {
        for (plan in vectors["fixedCapacityPlans"]!!.jsonArray.map { it.jsonObject }) {
            val expected = plan["slots"]!!.jsonArray.map {
                FixedCapacityPlan.Bucket(it.jsonObject["plaintextByteCount"]!!.jsonPrimitive.long, it.jsonObject["count"]!!.jsonPrimitive.long)
            }
            assertEquals(expected, FixedCapacityPlan.slots(plan["capacityBytes"]!!.jsonPrimitive.long))
        }
    }

    private fun JsonObject.obj(key: String) = getValue(key).jsonObject

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
}
