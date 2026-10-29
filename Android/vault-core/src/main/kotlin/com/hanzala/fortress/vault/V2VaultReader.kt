package com.hanzala.fortress.vault

import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.UUID

/** §2.1 format detection: by the envelope's `formatVersion`, never by trying a password. */
enum class VaultFormatVersion { V1, V2 }

/**
 * Opens a v2 vault folder (§2, §8.3) read-only.
 *
 * Zero Bulk Decryption: unlocking reads only the envelope, one metadata anchor
 * and (for recovery) one recovery anchor. File contents are decrypted one
 * entry at a time, only when [OpenedVault.readEntry] is called.
 */
class V2VaultReader(private val sodium: Sodium, private val root: Path) {
    private val codec = PoolObjectCodec(sodium)

    fun detectFormat(): VaultFormatVersion {
        val version = JsonFields(SwiftJson.parse(readEnvelopeBytes()), "envelope").unsigned("formatVersion")
        return when (version) {
            1L -> VaultFormatVersion.V1
            2L -> VaultFormatVersion.V2
            else -> throw VaultFormatException("unsupported vault format")
        }
    }

    fun readEnvelope(): AccessEnvelope = AccessEnvelope.parse(readEnvelopeBytes())

    fun unlock(password: String): OpenedVault {
        val envelope = readEnvelope()
        val key = SlotUnlocker(sodium).unlock(envelope, password)
        return open(envelope, key, expectedAccessID = null)
    }

    /** §7: every failure is one generic "invalid recovery key" error. */
    fun recover(recoveryKey: String): OpenedVault {
        val envelope = readEnvelope()
        val (key, accessID) = recoverAccess(envelope, recoveryKey)
        try {
            return open(envelope, key, expectedAccessID = accessID)
        } catch (e: Exception) {
            throw VaultFormatException("invalid recovery key")
        }
    }

    /**
     * §7.2: the master key and access ID held by the recovery anchor that
     * [recoveryKey] names. Every failure is "invalid recovery key".
     */
    internal fun recoverAccess(envelope: AccessEnvelope, recoveryKey: String): Pair<AccessKey, UUID> {
        val secret = try {
            RecoveryKeyText.parse(recoveryKey)
        } catch (e: VaultFormatException) {
            throw VaultFormatException("invalid recovery key")
        }
        try {
            val name = ObjectNames.recoveryAnchor(secret, envelope.vaultID)
            val opened = codec.open(readObject(name), secret, name)
            val json = try {
                if (opened.kind != PoolObjectKind.RECOVERY_ANCHOR) throw VaultFormatException("not a recovery anchor")
                JsonFields(SwiftJson.parse(opened.content), "recovery")
            } finally {
                opened.content.wipe()
            }
            // The parsed JSON still holds the master key as an immutable string;
            // the JVM gives no way to wipe it, so this is best effort.
            val masterKey = json.bytes("masterKey")
            val roleRaw = json.unsigned("roleRawValue")
            val role = if (roleRaw <= 2) AccessRole.of(roleRaw.toInt()) else null
            if (json.unsigned("formatVersion") != 1L || json.uuid("vaultID") != envelope.vaultID ||
                masterKey.size != 32 || role == null
            ) {
                masterKey.wipe()
                throw VaultFormatException("invalid recovery anchor")
            }
            return AccessKey(role, masterKey) to json.uuid("accessID")
        } catch (e: Exception) {
            throw VaultFormatException("invalid recovery key")
        } finally {
            secret.wipe()
        }
    }

    private fun open(envelope: AccessEnvelope, key: AccessKey, expectedAccessID: UUID?): OpenedVault {
        try {
            val name = ObjectNames.metadataAnchor(key.masterKey)
            val opened = codec.open(readObject(name), key.masterKey, name)
            val metadata = try {
                if (opened.kind != PoolObjectKind.METADATA) throw VaultFormatException("not a metadata anchor")
                AccessMetadata.parse(opened.content)
            } finally {
                opened.content.wipe()
            }
            if (expectedAccessID != null && metadata.accessID != expectedAccessID) {
                throw VaultFormatException("recovery anchor does not match metadata")
            }
            return OpenedVault(envelope.vaultID, key, metadata)
        } catch (e: Exception) {
            key.close()
            throw e
        }
    }

    inner class OpenedVault internal constructor(
        val vaultID: UUID,
        private val key: AccessKey,
        val metadata: AccessMetadata,
    ) : AutoCloseable {
        val role get() = key.role
        val entries get() = metadata.entries

        /**
         * Decrypts one entry into [destination], which appears only once the whole
         * file has been verified (for a chunked file: every chunk and the SHA-256
         * of the whole plaintext). The bytes are staged in a sibling temporary
         * file that is deleted on any failure. Prefer this over [readEntry].
         * If the process dies mid-read, a `.hanzala-read-*.tmp` file can remain;
         * the app deletes those at start-up and on lock. [destination] must be in
         * app-private storage (plaintext is staged next to it) and must not exist.
         */
        fun readEntryToFile(entry: VaultEntry, destination: Path) {
            val directory = destination.toAbsolutePath().parent ?: throw VaultFormatException("no destination folder")
            if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) throw java.nio.file.FileAlreadyExistsException(destination.toString())
            val staging = Files.createTempFile(directory, ".hanzala-read-", ".tmp")
            try {
                Files.newOutputStream(staging, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { readEntry(entry, it) }
                try {
                    Files.move(staging, destination, StandardCopyOption.ATOMIC_MOVE)
                } catch (e: java.nio.file.AtomicMoveNotSupportedException) {
                    Files.move(staging, destination)
                }
            } catch (e: Throwable) {
                Files.deleteIfExists(staging)
                throw e
            }
        }

        /**
         * Decrypts one entry into [out]. For a chunked file the SHA-256 of the
         * whole plaintext is checked after the last chunk: if this throws, the
         * caller MUST discard everything already written to [out]
         * ([readEntryToFile] does that for you).
         */
        internal fun readEntry(entry: VaultEntry, out: OutputStream) {
            if (!entry.isChunked) {
                val content = openKind(entry.opaqueObjectName, PoolObjectKind.DATA)
                try {
                    if (content.size.toLong() != entry.logicalByteCount) throw VaultFormatException("data object mismatch")
                    out.write(content)
                } finally {
                    content.wipe()
                }
                return
            }
            val manifestBytes = openKind(entry.opaqueObjectName, PoolObjectKind.MANIFEST)
            val manifest = try {
                ChunkManifest.parse(manifestBytes)
            } finally {
                manifestBytes.wipe()
            }
            if (manifest.fileID != entry.id || manifest.logicalByteCount != entry.logicalByteCount ||
                manifest.chunks.map { it.first } != entry.auxiliaryObjectNames
            ) {
                throw VaultFormatException("manifest mismatch")
            }
            val digest = MessageDigest.getInstance("SHA-256")
            for ((name, length) in manifest.chunks) {
                val part = openKind(name, PoolObjectKind.DATA)
                try {
                    if (part.size.toLong() != length) throw VaultFormatException("chunk mismatch")
                    digest.update(part)
                    out.write(part)
                } finally {
                    part.wipe()
                }
            }
            if (!MessageDigest.isEqual(digest.digest(), manifest.sha256Digest)) throw VaultFormatException("digest mismatch")
        }

        private fun openKind(name: String, kind: PoolObjectKind): ByteArray {
            val opened = codec.open(readObject(name), key.masterKey, name)
            if (opened.kind != kind) {
                opened.content.wipe()
                throw VaultFormatException("unexpected object kind")
            }
            return opened.content
        }

        override fun close() = key.close()
    }

    private fun readEnvelopeBytes(): ByteArray {
        requireDirectory(root)
        return readRegularFile(root.resolve(V2Format.ENVELOPE_NAME), V2Format.MAX_ENVELOPE_FILE.toLong())
    }

    /** §2: objects are opened by derived or listed names only; `objects/` is never enumerated. */
    private fun readObject(name: String): ByteArray {
        if (!V2Format.isObjectName(name)) throw VaultFormatException("invalid object name")
        val pool = root.resolve(V2Format.POOL_DIRECTORY)
        requireDirectory(pool)
        return readRegularFile(pool.resolve(name), (V2Format.POOL_OVERHEAD + V2Format.MAX_POOL_PLAINTEXT).toLong())
    }

    private fun requireDirectory(path: Path) {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw VaultFormatException("not a vault folder")
    }

    /** Reads a regular file without following symbolic links, refusing anything over [maxSize]. */
    private fun readRegularFile(path: Path, maxSize: Long): ByteArray {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw VaultFormatException("missing vault file")
        FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val size = channel.size()
            if (size > maxSize) throw VaultFormatException("vault file too large")
            val buffer = ByteBuffer.allocate(size.toInt())
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) throw VaultFormatException("vault file changed while reading")
            }
            return buffer.array()
        }
    }
}
