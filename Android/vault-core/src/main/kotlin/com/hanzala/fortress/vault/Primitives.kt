package com.hanzala.fortress.vault

import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** §1 hashing, §3 domain keys. */
object DomainKeys {
    const val NAMESPACE_V2 = "hanzala/namespace/v2"
    const val RECOVERY_NAMESPACE_V2 = "hanzala/recovery-namespace/v2"
    const val POOL_OBJECT_V2 = "hanzala/pool-object/v2"
    const val INDEX_V1 = "hanzala/index/v1"
    const val OBJECT_V1 = "hanzala/object/v1"

    /** HKDF-SHA256 with an empty salt and a 32-byte output (one expand block). */
    fun derive(inputKey: ByteArray, info: String): ByteArray {
        if (inputKey.size != 32) throw VaultFormatException("HKDF input key must be 32 bytes")
        val prk = hmacSha256(ByteArray(32), inputKey)
        return hmacSha256(prk, info.toByteArray(Charsets.US_ASCII) + byteArrayOf(1))
    }

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}

internal object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(DIGITS[v ushr 4]).append(DIGITS[v and 0x0f])
        }
        return out.toString()
    }

    fun decode(text: String): ByteArray {
        if (text.length % 2 != 0) throw VaultFormatException("odd hex length")
        return ByteArray(text.length / 2) { i ->
            val hi = Character.digit(text[2 * i], 16)
            val lo = Character.digit(text[2 * i + 1], 16)
            if (hi < 0 || lo < 0) throw VaultFormatException("bad hex")
            ((hi shl 4) or lo).toByte()
        }
    }
}

/** §1 UUID text forms. Parsing is strict (36 characters), like Swift's `UUID(uuidString:)`. */
internal object Uuids {
    private val pattern = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    fun parse(text: String): UUID {
        if (!pattern.matches(text)) throw VaultFormatException("bad UUID")
        return UUID.fromString(text)
    }

    fun upper(uuid: UUID): String = uuid.toString().uppercase()

    fun lower(uuid: UUID): String = uuid.toString().lowercase()
}

/** §9 base64 and dates. */
internal object Codings {
    fun base64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)

    fun unbase64(text: String): ByteArray {
        // Swift's Data(base64Encoded:) requires padding; java.util.Base64 does not.
        if (text.length % 4 != 0) throw VaultFormatException("bad base64")
        return try {
            Base64.getDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            throw VaultFormatException("bad base64")
        }
    }

    private val isoPattern = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
    private val isoFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

    fun parseDate(text: String): Instant {
        if (!isoPattern.matches(text)) throw VaultFormatException("bad date")
        return try {
            Instant.parse(text)
        } catch (e: java.time.format.DateTimeParseException) {
            throw VaultFormatException("bad date")
        }
    }

    fun formatDate(instant: Instant): String = isoFormatter.format(instant)
}

/** Overwrites key material once it is no longer needed. */
fun ByteArray.wipe() = fill(0)
