package com.hanzala.fortress.vault

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID

/**
 * Writes a small v2 vault for reader tests, following the spec directly (a test
 * helper, not the app's writer). Argon2id runs with libsodium's minimum cost.
 */
class TestVaultBuilder(private val root: Path, private val password: String) {
    class File(
        val name: String,
        val content: ByteArray,
        /** Chunked files only: replaces the manifest's SHA-256. */
        val digestOverride: ByteArray? = null,
        /** Chunked files only: replaces the manifest's file ID. */
        val manifestFileIDOverride: UUID? = null,
    )

    val vaultID: UUID = UUID.randomUUID()
    val masterKey: ByteArray = JvmSodium.randomBytes(32)
    val recoverySecret: ByteArray = JvmSodium.randomBytes(32)
    private val codec = PoolObjectCodec(JvmSodium)
    private val created = Instant.parse("2026-01-01T00:00:00Z")

    fun build(files: List<File>, slotMemLimit: Long = 8192, slotOpsLimit: Long = 1) {
        Files.createDirectories(root.resolve(V2Format.POOL_DIRECTORY))
        val accessID = UUID.randomUUID()
        val entries = files.map { writeFile(it) }
        val total = files.sumOf { it.content.size.toLong() }
        val metadata = buildJsonObject {
            put("accessID", Uuids.upper(accessID))
            put("budget", buildJsonObject {
                put("reserveBytes", 0)
                put("safetyMarginBytes", 0)
                put("totalBytes", 1L shl 40)
            })
            put("entries", JsonArray(entries))
            put("formatVersion", 1)
            put("generation", files.size)
            put("pendingChunkImports", JsonArray(emptyList()))
            put("pendingImports", JsonArray(emptyList()))
            put("pendingRemovals", JsonArray(emptyList()))
            put("tombstonedObjectNames", JsonArray(emptyList()))
            put("usage", buildJsonObject {
                put("logicalBytes", total)
                put("objectCount", files.size)
            })
        }
        val metadataBytes = SwiftJson.encode(metadata, escapeSlashes = true)
        seal(PoolObjectKind.METADATA, metadataBytes, masterKey, ObjectNames.metadataAnchor(masterKey),
            Padding.metadataTarget(metadataBytes.size.toLong()))

        val recovery = SwiftJson.encode(buildJsonObject {
            put("accessID", Uuids.upper(accessID))
            put("formatVersion", 1)
            put("masterKey", Codings.base64(masterKey))
            put("roleRawValue", AccessRole.VISIBLE.raw)
            put("vaultID", Uuids.upper(vaultID))
        }, escapeSlashes = false)
        seal(PoolObjectKind.RECOVERY_ANCHOR, recovery, recoverySecret, ObjectNames.recoveryAnchor(recoverySecret, vaultID),
            V2Format.RECOVERY_ANCHOR_PLAINTEXT.toLong())

        val dummyPassword = Codings.base64(JvmSodium.randomBytes(32))
        val envelope = buildJsonObject {
            put("accessSlots", JsonArray(listOf(
                slot(password, AccessRole.VISIBLE, masterKey, slotOpsLimit, slotMemLimit),
                slot(dummyPassword, AccessRole.CONCEALED, JvmSodium.randomBytes(32), slotOpsLimit, slotMemLimit),
            )))
            put("createdAt", Codings.formatDate(created))
            put("formatVersion", 2)
            put("vaultID", Uuids.upper(vaultID))
        }
        Files.write(root.resolve(V2Format.ENVELOPE_NAME), SwiftJson.encode(envelope, escapeSlashes = false))
    }

    val recoveryKey get() = RecoveryKeyText.format(recoverySecret)

    private fun writeFile(file: File): JsonObject {
        val id = UUID.randomUUID()
        val name = randomName()
        val auxiliary = ArrayList<String>()
        if (file.content.size <= V2Format.MAX_SINGLE_CONTENT) {
            seal(PoolObjectKind.DATA, file.content, masterKey, name, Padding.dataTarget(file.content.size.toLong()))
        } else {
            val chunks = (0 until file.content.size step V2Format.CHUNK_CONTENT).map {
                file.content.copyOfRange(it, minOf(it + V2Format.CHUNK_CONTENT, file.content.size))
            }
            val refs = chunks.map { chunk ->
                val chunkName = randomName()
                seal(PoolObjectKind.DATA, chunk, masterKey, chunkName, V2Format.CHUNK_PLAINTEXT.toLong())
                auxiliary += chunkName
                buildJsonObject {
                    put("logicalByteCount", chunk.size)
                    put("opaqueObjectName", chunkName)
                }
            }
            val manifest = SwiftJson.encode(buildJsonObject {
                put("chunks", JsonArray(refs))
                put("fileID", Uuids.upper(file.manifestFileIDOverride ?: id))
                put("formatVersion", 1)
                put("logicalByteCount", file.content.size)
                put("sha256Digest", Codings.base64(file.digestOverride ?: DomainKeys.sha256(file.content)))
            }, escapeSlashes = false)
            seal(PoolObjectKind.MANIFEST, manifest, masterKey, name, Padding.metadataTarget(manifest.size.toLong()))
        }
        return buildJsonObject {
            put("auxiliaryObjectNames", JsonArray(auxiliary.map { JsonPrimitive(it) }))
            put("createdAt", Codings.formatDate(created))
            put("id", Uuids.upper(id))
            put("logicalByteCount", file.content.size)
            put("opaqueObjectName", name)
            put("originalName", file.name)
        }
    }

    private fun slot(password: String, role: AccessRole, key: ByteArray, ops: Long, mem: Long): JsonObject {
        val salt = JvmSodium.randomBytes(AccessEnvelope.SALT_BYTES)
        // Derive with libsodium's minimum cost; the stored parameters may differ
        // on purpose (tests of out-of-range parameters never reach the KDF).
        val slotKey = JvmSodium.argon2id13(32, password.toByteArray(), salt, minOf(ops, 4).coerceAtLeast(1), mem.coerceIn(8192, 1L shl 30))!!
        val payload = byteArrayOf(AccessEnvelope.SLOT_PAYLOAD_VERSION.toByte(), role.raw.toByte()) +
            Uuids.lower(vaultID).toByteArray() + key
        val nonce = JvmSodium.randomBytes(V2Format.NONCE_BYTES)
        return buildJsonObject {
            put("kdf", buildJsonObject {
                put("algorithm", AccessEnvelope.KDF_ALGORITHM)
                put("memoryLimit", mem)
                put("operationsLimit", ops)
                put("salt", Codings.base64(salt))
            })
            put("wrappedPayload", Codings.base64(nonce + JvmSodium.secretboxEasy(payload, nonce, slotKey)))
        }
    }

    private fun seal(kind: PoolObjectKind, content: ByteArray, key: ByteArray, name: String, padded: Long) {
        Files.write(root.resolve(V2Format.POOL_DIRECTORY).resolve(name), codec.seal(kind, content, key, name, padded.toInt()))
    }

    private fun randomName() = Hex.encode(JvmSodium.randomBytes(32))
}
