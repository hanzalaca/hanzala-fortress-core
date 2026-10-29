package com.hanzala.fortress.vault

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.UUID

/** §4.5 roles, taken from the decrypted slot payload, never from slot position. */
enum class AccessRole(val raw: Int) {
    VISIBLE(1), CONCEALED(2);

    companion object {
        fun of(raw: Int) = entries.firstOrNull { it.raw == raw }
    }
}

/** §4.1 one access slot as stored; nothing in it is trusted before a slot opens. */
class AccessSlot(
    val algorithm: String,
    val salt: ByteArray,
    val opsLimit: Long,
    val memLimit: Long,
    val wrappedPayload: ByteArray,
)

/** §4 the public `vault.hanzala` envelope. */
class AccessEnvelope(val vaultID: UUID, val createdAt: String, val slots: List<AccessSlot>) {
    /** §4.1 JSON as Swift writes it (`.sortedKeys`, `.withoutEscapingSlashes`). Also the session's envelope binding. */
    fun encode(): ByteArray = SwiftJson.encode(
        JsonObject(
            mapOf(
                "accessSlots" to JsonArray(slots.map { slot ->
                    JsonObject(
                        mapOf(
                            "kdf" to JsonObject(
                                mapOf(
                                    "algorithm" to JsonPrimitive(slot.algorithm),
                                    "memoryLimit" to JsonPrimitive(slot.memLimit),
                                    "operationsLimit" to JsonPrimitive(slot.opsLimit),
                                    "salt" to JsonPrimitive(Codings.base64(slot.salt)),
                                ),
                            ),
                            "wrappedPayload" to JsonPrimitive(Codings.base64(slot.wrappedPayload)),
                        ),
                    )
                }),
                "createdAt" to JsonPrimitive(createdAt),
                "formatVersion" to JsonPrimitive(V2Format.ENVELOPE_FORMAT_VERSION),
                "vaultID" to JsonPrimitive(Uuids.upper(vaultID)),
            ),
        ),
        escapeSlashes = false,
    )

    companion object {
        const val SLOT_COUNT = 2
        const val KDF_ALGORITHM = "argon2id13"
        const val SALT_BYTES = 16
        const val OPSLIMIT_SENSITIVE = 4L
        const val MEMLIMIT_SENSITIVE = 1_073_741_824L
        const val SLOT_PAYLOAD_VERSION = 2
        const val SLOT_PAYLOAD_SIZE = 70

        fun parse(bytes: ByteArray): AccessEnvelope {
            if (bytes.size > V2Format.MAX_ENVELOPE_FILE) throw VaultFormatException("envelope too large")
            val json = JsonFields(SwiftJson.parse(bytes), "envelope")
            if (json.unsigned("formatVersion") != V2Format.ENVELOPE_FORMAT_VERSION) throw VaultFormatException("not a v2 envelope")
            val slots = json.objects("accessSlots").map { slot ->
                val kdf = slot.obj("kdf")
                AccessSlot(
                    algorithm = kdf.string("algorithm"),
                    salt = kdf.bytes("salt"),
                    opsLimit = kdf.unsigned("operationsLimit"),
                    memLimit = kdf.unsigned("memoryLimit"),
                    wrappedPayload = slot.bytes("wrappedPayload"),
                )
            }
            if (slots.size != SLOT_COUNT) throw VaultFormatException("envelope must have exactly 2 slots")
            json.date("createdAt")
            return AccessEnvelope(json.uuid("vaultID"), json.string("createdAt"), slots)
        }
    }
}

/** The master key of one access path. Call [close] to wipe it. */
class AccessKey(val role: AccessRole, val masterKey: ByteArray) : AutoCloseable {
    override fun close() = masterKey.wipe()
}

/** §4.2–§4.4 password unlock. */
class SlotUnlocker(private val sodium: Sodium) {
    /**
     * Tries every slot (never stopping at the first match, §4.4). The password
     * is hashed as its exact UTF-8 bytes, with no Unicode normalization (§14.1).
     */
    fun unlock(envelope: AccessEnvelope, password: String): AccessKey {
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        try {
            var kdfFailed = false
            val matches = envelope.slots.mapNotNull {
                try {
                    unwrap(it, passwordBytes, envelope.vaultID)
                } catch (e: KeyDerivationException) {
                    kdfFailed = true
                    null
                }
            }
            if (matches.size != 1) {
                matches.forEach { it.close() }
                // A slot whose KDF could not run (e.g. not enough memory) was never
                // tried, so "wrong password" would be a lie.
                if (matches.isEmpty() && kdfFailed) throw KeyDerivationException()
                throw VaultFormatException(if (matches.isEmpty()) "wrong password" else "ambiguous password")
            }
            return matches[0]
        } finally {
            passwordBytes.wipe()
        }
    }

    /**
     * One slot; any failure (bad parameters, authentication, payload) means "did
     * not match", except a KDF that libsodium could not run with in-range
     * parameters, which throws [KeyDerivationException].
     */
    fun unwrap(slot: AccessSlot, password: ByteArray, vaultID: UUID): AccessKey? {
        if (slot.algorithm != AccessEnvelope.KDF_ALGORITHM) return null
        if (slot.salt.size != AccessEnvelope.SALT_BYTES) return null
        if (slot.opsLimit !in 1..AccessEnvelope.OPSLIMIT_SENSITIVE) return null
        if (slot.memLimit !in 8192..AccessEnvelope.MEMLIMIT_SENSITIVE) return null
        if (slot.wrappedPayload.size != V2Format.NONCE_BYTES + AccessEnvelope.SLOT_PAYLOAD_SIZE + V2Format.TAG_BYTES) return null

        val slotKey = sodium.argon2id13(32, password, slot.salt, slot.opsLimit, slot.memLimit)
            ?: throw KeyDerivationException()
        val payload = try {
            sodium.secretboxOpenEasy(
                slot.wrappedPayload.copyOfRange(V2Format.NONCE_BYTES, slot.wrappedPayload.size),
                slot.wrappedPayload.copyOfRange(0, V2Format.NONCE_BYTES),
                slotKey,
            )
        } finally {
            slotKey.wipe()
        } ?: return null
        try {
            if (payload.size != AccessEnvelope.SLOT_PAYLOAD_SIZE) return null
            if (payload[0].toInt() != AccessEnvelope.SLOT_PAYLOAD_VERSION) return null
            val role = AccessRole.of(payload[1].toInt()) ?: return null
            val embedded = try {
                Uuids.parse(payload.copyOfRange(2, 38).toString(Charsets.US_ASCII))
            } catch (e: VaultFormatException) {
                return null
            }
            if (embedded != vaultID) return null
            return AccessKey(role, payload.copyOfRange(38, 70))
        } finally {
            payload.wipe()
        }
    }
}

/** §7.1 recovery key display form and input normalization. */
object RecoveryKeyText {
    fun format(secret: ByteArray): String {
        if (secret.size != 32) throw VaultFormatException("recovery secret must be 32 bytes")
        val body = Hex.encode(secret).uppercase()
        return "HZRK-" + body.chunked(4).joinToString("-")
    }

    /** Uppercase, drop whitespace and `-`, then `HZRK` + exactly 64 hex digits. */
    fun parse(text: String): ByteArray {
        val compact = text.uppercase(java.util.Locale.ROOT).filter { !it.isWhitespace() && it != '-' }
        if (!compact.startsWith("HZRK")) throw VaultFormatException("invalid recovery key")
        val body = compact.substring(4)
        if (body.length != 64 || body.any { it !in '0'..'9' && it !in 'A'..'F' }) {
            throw VaultFormatException("invalid recovery key")
        }
        return Hex.decode(body)
    }
}
