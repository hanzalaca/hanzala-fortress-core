package com.hanzala.fortress.vault

import java.nio.ByteBuffer
import java.util.UUID

/**
 * Where this device remembers the highest metadata generation it has seen
 * for each access path (Swift `V2MetadataWatermarkStore`). Keys are opaque
 * (an HMAC under the master key), so the store reveals nothing about the
 * vault. The app keeps it in app-private storage that is never backed up.
 */
interface MetadataWatermarkStore {
    fun generation(key: String): Long?
    fun setGeneration(key: String, generation: Long)
}

class InMemoryMetadataWatermarkStore : MetadataWatermarkStore {
    private val values = HashMap<String, Long>()

    @Synchronized
    override fun generation(key: String): Long? = values[key]

    @Synchronized
    override fun setGeneration(key: String, generation: Long) {
        values[key] = generation
    }
}

/**
 * The vault on disk is older than one this device already opened: someone
 * may have put back an old copy (for example to undo a deletion). The owner
 * can still open it on purpose with `acceptingOlderCopy = true`.
 */
class OlderCopyDetectedException : Exception("this vault is older than a copy already opened on this device")

/**
 * Swift `V2MetadataWatermarkGuard`. Fails open: if the store cannot be read
 * or written, the vault still opens, so a broken store never locks the owner
 * out.
 */
internal class MetadataWatermarkGuard(private val store: MetadataWatermarkStore) {

    fun check(generation: Long, key: String, accepting: Boolean) {
        val seen = try {
            store.generation(key)
        } catch (e: Exception) {
            return
        }
        if (seen != null && generation < seen) {
            if (!accepting) throw OlderCopyDetectedException()
            write(key, generation)
            return
        }
        if (seen == null || generation > seen) write(key, generation)
    }

    private fun write(key: String, generation: Long) {
        try {
            store.setGeneration(key, generation)
        } catch (e: Exception) {
            // Fail open.
        }
    }

    companion object {
        private const val PURPOSE = "hanzala/metadata-watermark/v2"
        private val LABEL = "HZ-METADATA-WATERMARK-1".toByteArray(Charsets.US_ASCII)

        fun key(masterKey: ByteArray, vaultID: UUID, accessID: UUID): String {
            val derived = DomainKeys.derive(masterKey, PURPOSE)
            try {
                val message = ByteBuffer.allocate(LABEL.size + 32)
                    .put(LABEL)
                    .putLong(vaultID.mostSignificantBits).putLong(vaultID.leastSignificantBits)
                    .putLong(accessID.mostSignificantBits).putLong(accessID.leastSignificantBits)
                    .array()
                return Hex.encode(DomainKeys.hmacSha256(derived, message))
            } finally {
                derived.wipe()
            }
        }
    }
}
