package com.hanzala.fortress.vault

import java.util.UUID

/** §12 constants. */
object V2Format {
    const val ENVELOPE_NAME = "vault.hanzala"
    const val POOL_DIRECTORY = "objects"
    const val ENVELOPE_FORMAT_VERSION = 2L
    const val MAX_ENVELOPE_FILE = 1_048_576

    const val POOL_PAYLOAD_VERSION = 1
    const val POOL_HEADER = 10
    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16
    const val POOL_OVERHEAD = 8 + NONCE_BYTES + TAG_BYTES
    const val MAX_POOL_PLAINTEXT = 16_777_216
    const val MAX_SINGLE_CONTENT = MAX_POOL_PLAINTEXT - POOL_HEADER
    const val RECOVERY_ANCHOR_PLAINTEXT = 4096
    const val FIXED_METADATA_PLAINTEXT = 1_048_576
    const val CHUNK_PLAINTEXT = 4_194_304
    const val CHUNK_CONTENT = CHUNK_PLAINTEXT - POOL_HEADER
    const val MAX_CHUNKS = 16_384

    val POOL_MAGIC = "HZOBJ003".toByteArray(Charsets.US_ASCII)
    val BUCKETS = longArrayOf(4096, 16384, 65536, 262144, 1048576, 4194304, 16777216)

    const val LABEL_INDEX_ANCHOR = "hanzala/v2/index-anchor"
    const val LABEL_RECOVERY_ANCHOR = "hanzala/v2/recovery-anchor"
    const val LABEL_COVER_SLOT = "hanzala/v2/cover-slot"

    fun isObjectName(name: String) = name.length == 64 && name.all { it in '0'..'9' || it in 'a'..'f' }
}

/** §6 pool object kinds. */
enum class PoolObjectKind(val raw: Int) {
    METADATA(1), DATA(2), PADDING(3), MANIFEST(4), RECOVERY_ANCHOR(5);

    companion object {
        fun of(raw: Int) = entries.firstOrNull { it.raw == raw }
    }
}

/** §5 derived object names. */
object ObjectNames {
    fun metadataAnchor(masterKey: ByteArray): String {
        val ns = DomainKeys.derive(masterKey, DomainKeys.NAMESPACE_V2)
        return Hex.encode(DomainKeys.hmacSha256(ns, ascii(V2Format.LABEL_INDEX_ANCHOR))).also { ns.wipe() }
    }

    fun recoveryAnchor(recoverySecret: ByteArray, vaultID: UUID): String {
        val ns = DomainKeys.derive(recoverySecret, DomainKeys.RECOVERY_NAMESPACE_V2)
        val msg = ascii(V2Format.LABEL_RECOVERY_ANCHOR) + byteArrayOf(0) + ascii(Uuids.lower(vaultID))
        return Hex.encode(DomainKeys.hmacSha256(ns, msg)).also { ns.wipe() }
    }

    fun cover(masterKey: ByteArray, bucket: Long, index: Long): String {
        val ns = DomainKeys.derive(masterKey, DomainKeys.NAMESPACE_V2)
        val msg = ascii(V2Format.LABEL_COVER_SLOT) + byteArrayOf(0) + u64(bucket) + u64(index)
        return Hex.encode(DomainKeys.hmacSha256(ns, msg)).also { ns.wipe() }
    }

    private fun ascii(s: String) = s.toByteArray(Charsets.US_ASCII)

    private fun u64(v: Long) = ByteArray(8) { i -> (v ushr (56 - 8 * i)).toByte() }
}

/** §5 cover names under one namespace key, derived once for many names; [close] wipes it. */
internal class CoverNamer(masterKey: ByteArray) : AutoCloseable {
    private val ns = DomainKeys.derive(masterKey, DomainKeys.NAMESPACE_V2)

    fun name(bucket: Long, index: Long): String {
        val msg = V2Format.LABEL_COVER_SLOT.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            ByteArray(8) { i -> (bucket ushr (56 - 8 * i)).toByte() } + ByteArray(8) { i -> (index ushr (56 - 8 * i)).toByte() }
        return Hex.encode(DomainKeys.hmacSha256(ns, msg))
    }

    override fun close() = ns.wipe()
}

/** §6.1 padding targets. */
object Padding {
    fun bucketFor(minimum: Long): Long =
        V2Format.BUCKETS.firstOrNull { it >= minimum } ?: throw VaultFormatException("too large for one object")

    fun dataTarget(contentLength: Long): Long {
        if (contentLength > V2Format.MAX_SINGLE_CONTENT) throw VaultFormatException("content too large for one object")
        return bucketFor(V2Format.POOL_HEADER + contentLength)
    }

    fun metadataTarget(encodedLength: Long): Long = bucketFor(V2Format.POOL_HEADER + encodedLength)
}

/** §6 `HZOBJ003` pool object envelope. */
class PoolObjectCodec(private val sodium: Sodium) {
    class Opened(val kind: PoolObjectKind, val content: ByteArray)

    fun seal(kind: PoolObjectKind, content: ByteArray, keyMaterial: ByteArray, name: String, paddedPlaintextSize: Int): ByteArray {
        if (!V2Format.isObjectName(name)) throw VaultFormatException("invalid object name")
        val minimum = V2Format.POOL_HEADER + content.size
        if (paddedPlaintextSize < minimum || paddedPlaintextSize > V2Format.MAX_POOL_PLAINTEXT) {
            throw VaultFormatException("bad padding target")
        }
        val plaintext = ByteArray(paddedPlaintextSize)
        plaintext[0] = V2Format.POOL_PAYLOAD_VERSION.toByte()
        plaintext[1] = kind.raw.toByte()
        for (i in 0 until 8) plaintext[2 + i] = (content.size.toLong() ushr (56 - 8 * i)).toByte()
        content.copyInto(plaintext, V2Format.POOL_HEADER)
        sodium.randomBytes(paddedPlaintextSize - minimum).copyInto(plaintext, minimum)
        val nonce = sodium.randomBytes(V2Format.NONCE_BYTES)
        val key = DomainKeys.derive(keyMaterial, DomainKeys.POOL_OBJECT_V2)
        try {
            return V2Format.POOL_MAGIC + nonce + sodium.xchacha20poly1305Encrypt(plaintext, associatedData(name), nonce, key)
        } finally {
            key.wipe()
            plaintext.wipe()
        }
    }

    fun open(file: ByteArray, keyMaterial: ByteArray, name: String): Opened {
        if (!V2Format.isObjectName(name)) throw VaultFormatException("invalid object name")
        val minSize = V2Format.POOL_OVERHEAD + V2Format.POOL_HEADER
        val maxSize = V2Format.POOL_OVERHEAD + V2Format.MAX_POOL_PLAINTEXT
        if (file.size < minSize || file.size > maxSize) throw VaultFormatException("bad object size")
        if (!file.copyOfRange(0, 8).contentEquals(V2Format.POOL_MAGIC)) throw VaultFormatException("bad magic")
        val nonce = file.copyOfRange(8, 8 + V2Format.NONCE_BYTES)
        val sealed = file.copyOfRange(8 + V2Format.NONCE_BYTES, file.size)
        val key = DomainKeys.derive(keyMaterial, DomainKeys.POOL_OBJECT_V2)
        val plaintext = try {
            sodium.xchacha20poly1305Decrypt(sealed, associatedData(name), nonce, key)
        } finally {
            key.wipe()
        } ?: throw VaultFormatException("authentication failed")
        try {
            if (plaintext.size < V2Format.POOL_HEADER || plaintext[0].toInt() != V2Format.POOL_PAYLOAD_VERSION) {
                throw VaultFormatException("bad payload version")
            }
            val kind = PoolObjectKind.of(plaintext[1].toInt() and 0xff) ?: throw VaultFormatException("bad kind")
            var length = 0L
            for (i in 0 until 8) {
                if (i == 0 && plaintext[2].toInt() and 0x80 != 0) throw VaultFormatException("bad logical length")
                length = (length shl 8) or (plaintext[2 + i].toLong() and 0xff)
            }
            if (length > plaintext.size - V2Format.POOL_HEADER) throw VaultFormatException("bad logical length")
            return Opened(kind, plaintext.copyOfRange(V2Format.POOL_HEADER, V2Format.POOL_HEADER + length.toInt()))
        } finally {
            plaintext.wipe()
        }
    }

    private fun associatedData(name: String) =
        V2Format.POOL_MAGIC + byteArrayOf(0) + name.toByteArray(Charsets.US_ASCII)
}

/** §11 fixed-capacity slot profile. */
object FixedCapacityPlan {
    const val MIN_CAPACITY = 64L * 1024 * 1024
    const val MAX_CAPACITY = 256L * 1024 * 1024 * 1024

    data class Bucket(val plaintextByteCount: Long, val slotCount: Long)

    private class Share(val bucket: Long, val percent: Long, val maxCount: Long?)

    private val shares = listOf(
        Share(4096, 1, 4096), Share(16384, 1, 2048), Share(65536, 2, 1024),
        Share(262144, 4, 512), Share(1048576, 8, 512), Share(16777216, 16, null),
    )

    fun slots(capacityBytes: Long): List<Bucket> {
        if (capacityBytes < MIN_CAPACITY || capacityBytes > MAX_CAPACITY) throw VaultFormatException("capacity out of range")
        val counts = sortedMapOf<Long, Long>()
        for (share in shares) {
            val raw = capacityBytes * share.percent / 100 / share.bucket
            counts[share.bucket] = if (share.maxCount == null) raw else minOf(raw, share.maxCount)
        }
        val used = counts.entries.sumOf { it.key * it.value }
        val chunk = V2Format.CHUNK_PLAINTEXT.toLong()
        counts[chunk] = (counts[chunk] ?: 0) + (capacityBytes - used) / chunk
        return counts.filter { it.value > 0 }.map { Bucket(it.key, it.value) }
    }
}
