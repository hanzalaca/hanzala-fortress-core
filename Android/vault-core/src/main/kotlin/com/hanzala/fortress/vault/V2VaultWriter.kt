package com.hanzala.fortress.vault

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.UUID

/** §4.1 Argon2id cost of a new or rewritten slot. */
data class KdfParameters(val opsLimit: Long, val memLimit: Long) {
    init {
        // Swift `PasswordKeyEngine.makeParameters` bounds; libsodium also needs ops >= 1, mem >= 8192.
        require(opsLimit in 1..AccessEnvelope.OPSLIMIT_SENSITIVE && memLimit in 8192..AccessEnvelope.MEMLIMIT_SENSITIVE) {
            "KDF parameters out of range"
        }
    }

    companion object {
        /** `crypto_pwhash_OPSLIMIT_MODERATE` / `MEMLIMIT_MODERATE`, what Swift writes (§12). */
        val PRODUCTION = KdfParameters(3, 268_435_456)
    }
}

/** A new vault: show [recoveryKey] once, after the fill finished (iPhone flow). */
class CreatedVault(val vaultID: UUID, val recoveryKey: String)

/** Swift `V2FixedCapacityStatus`: what a fixed-capacity vault looks like to the app. */
data class FixedCapacityStatus(
    val capacityBytes: Long,
    /** False while the covers are still being written. */
    val isFilled: Boolean,
    /** Authenticated plaintext all slots hold. */
    val slotPlaintextBytes: Long,
    /** Of that, the part in free slots. */
    val freePlaintextBytes: Long,
)

/** Pending work must be completed first: reopen the session (it recovers on open). */
class RecoveryRequiredException : Exception("pending work must be recovered first")

/** The vault's public envelope or access path changed since the session opened. */
class SessionInvalidatedException(message: String) : Exception(message)

/**
 * The new password may already be on disk but could not be confirmed. Lock and
 * open again with the new password (Swift `passwordChangeOutcomeUncertain`).
 */
class PasswordChangeOutcomeUncertainException : IOException("the password change could not be confirmed")

/**
 * Writes v2 vaults (Docs/V2-VAULT-FORMAT-SPEC.md), matching the Swift core's
 * bytes and crash-safety protocol: [createVault] (§13, `V2VaultBootstrapStore`
 * and `MobileVaultModel.createVault`), and sessions ([openSession],
 * [openSessionWithRecoveryKey]) that import, remove, change the password and
 * recover interrupted work (`V2VaultSessionStore`).
 *
 * Every file is staged beside its destination and renamed atomically; links
 * are never followed; `objects/` is never listed (the only exception is
 * Swift's own: an emptiness check when a failed creation cleans up).
 * Zero Bulk Decryption: an operation decrypts only metadata, covers and the
 * objects of the one file it works on.
 */
class V2VaultWriter internal constructor(
    private val sodium: Sodium,
    private val root: Path,
    private val kdf: KdfParameters,
    availableSpace: AvailableSpaceProvider,
    faultInjector: FaultInjector?,
) {
    constructor(
        sodium: Sodium,
        root: Path,
        kdf: KdfParameters = KdfParameters.PRODUCTION,
        availableSpace: AvailableSpaceProvider = AvailableSpaceProvider.SYSTEM,
    ) : this(sodium, root, kdf, availableSpace, null)

    private val committer = DurableFileCommitter(faultInjector)
    private val store = PoolObjectStore(sodium, root, committer)
    private val guard = PhysicalCapacityGuard(availableSpace)
    private val metadataStore = MetadataStore(store, guard, committer)
    private val covers = Covers(store)
    private val transactions = Transactions(sodium, store, metadataStore, guard, covers)
    private val envelopePath = root.resolve(V2Format.ENVELOPE_NAME)

    /**
     * Creates a password-only vault (slot 1 is a dummy, §4.5) and returns its
     * recovery key. With [capacityBytes] (the iPhone offers 2, 5 and 10 GiB) the
     * vault is made fixed-capacity and its covers are written first, so the
     * recovery key is returned only once the folder has its final size;
     * [progress] gets (slots done, slots in all). If this throws part way, the
     * caller deletes the folder (the iPhone app builds the vault in a pending
     * folder and removes it on failure); [V2VaultSession.prepareFixedCapacity]
     * can also resume an interrupted fill.
     */
    fun createVault(
        password: String,
        capacityBytes: Long? = null,
        budget: StorageBudget = StorageBudget.APP_DEFAULT,
        progress: ((Long, Long) -> Unit)? = null,
    ): CreatedVault {
        budget.validate()
        capacityBytes?.let { FixedCapacityPlan.slots(it) }
        val (created, visibleKey) = bootstrap(password, budget)
        try {
            if (capacityBytes != null) {
                // Swift opens a session with the password here; the master key in
                // hand gives the same session without a second Argon2 run.
                val binding = AccessEnvelope.parse(readEnvelopeBytes()).encode()
                val accessID = metadataStore.read(visibleKey).accessID
                session(created.vaultID, accessID, AccessRole.VISIBLE, visibleKey.copyOf(), binding).use {
                    it.prepareFixedCapacity(capacityBytes, progress)
                }
            }
        } finally {
            visibleKey.wipe()
        }
        return created
    }

    /** §4.4 unlock, then crash recovery of pending work (§8.3 step 3). */
    fun openSession(password: String): V2VaultSession {
        val envelope = AccessEnvelope.parse(readEnvelopeBytes())
        val key = SlotUnlocker(sodium).unlock(envelope, password)
        return open(envelope, key, expectedAccessID = null)
    }

    /** §7 recovery-key open; every credential failure is "invalid recovery key". */
    fun openSessionWithRecoveryKey(recoveryKey: String): V2VaultSession {
        val envelope = AccessEnvelope.parse(readEnvelopeBytes())
        val (key, accessID) = V2VaultReader(sodium, root).recoverAccess(envelope, recoveryKey)
        return try {
            open(envelope, key, accessID)
        } catch (e: VaultFormatException) {
            throw VaultFormatException("invalid recovery key")
        }
    }

    private fun open(envelope: AccessEnvelope, key: AccessKey, expectedAccessID: UUID?): V2VaultSession {
        val session = try {
            val metadata = metadataStore.read(key.masterKey)
            if (expectedAccessID != null && metadata.accessID != expectedAccessID) {
                throw VaultFormatException("recovery anchor does not match metadata")
            }
            session(envelope.vaultID, metadata.accessID, key.role, key.masterKey.copyOf(), envelope.encode())
        } finally {
            key.close()
        }
        try {
            session.recover()
        } catch (e: Throwable) {
            if (e !is SimulatedCrash) session.close()
            throw e
        }
        return session
    }

    private fun session(vaultID: UUID, accessID: UUID, role: AccessRole, key: ByteArray, binding: ByteArray) =
        V2VaultSession(this, vaultID, accessID, role, key, binding)

    // MARK: creation (§13, Swift `V2VaultBootstrapStore`)

    private fun bootstrap(password: String, budget: StorageBudget): Pair<CreatedVault, ByteArray> {
        val vaultID = UUID.randomUUID()
        val createdAt = Codings.formatDate(nowWholeSeconds())
        val dummyPassword = Codings.base64(sodium.randomBytes(32))
        val visibleKey = sodium.randomBytes(32)
        val dummyKey = sodium.randomBytes(32)
        val secrets = listOf(sodium.randomBytes(32), sodium.randomBytes(32))
        try {
            val visibleSlot = makeSlot(AccessRole.VISIBLE, visibleKey, password, vaultID)
            val dummySlot = makeSlot(AccessRole.CONCEALED, dummyKey, dummyPassword, vaultID)
            val envelope = AccessEnvelope(vaultID, createdAt, listOf(visibleSlot, dummySlot))
            val keys = listOf(visibleKey, dummyKey)
            if (keys[0].contentEquals(keys[1])) throw VaultFormatException("duplicate master key")
            if (secrets[0].contentEquals(secrets[1])) throw VaultFormatException("duplicate recovery key")
            val metadataNames = keys.map { ObjectNames.metadataAnchor(it) }
            val recoveryNames = secrets.map { ObjectNames.recoveryAnchor(it, vaultID) }
            if ((metadataNames + recoveryNames).toSet().size != 4) throw VaultFormatException("duplicate anchor")
            writeFoundation(envelope, keys, secrets, metadataNames, recoveryNames, budget)
            return CreatedVault(vaultID, RecoveryKeyText.format(secrets[0])) to visibleKey.copyOf()
        } finally {
            visibleKey.wipe()
            dummyKey.wipe()
            secrets.forEach { it.wipe() }
        }
    }

    private fun writeFoundation(
        envelope: AccessEnvelope,
        keys: List<ByteArray>,
        secrets: List<ByteArray>,
        metadataNames: List<String>,
        recoveryNames: List<String>,
        budget: StorageBudget,
    ) {
        val pool = root.resolve(V2Format.POOL_DIRECTORY)
        // §2: never reinterpret or remove an existing v1/v2 layout.
        for (name in listOf(V2Format.ENVELOPE_NAME, "index.hanzala", V2Format.POOL_DIRECTORY, ".journal")) {
            if (entryExists(root.resolve(name))) throw VaultFormatException("folder already contains a vault")
        }
        val rootExisted = entryExists(root)
        var createdPool = false
        var wroteEnvelope = false
        val committed = ArrayList<String>()
        var rootIdentity: Any? = null
        try {
            Files.createDirectories(root)
            Files.createDirectory(pool)
            createdPool = true
            rootIdentity = identity(root)

            val metadata = keys.map { key -> metadataStore.createInitialEmpty(budget, key).also { committed += ObjectNames.metadataAnchor(key) } }
            for (i in keys.indices) {
                val role = if (i == 0) AccessRole.VISIBLE else AccessRole.CONCEALED
                val payload = recoveryPayload(envelope.vaultID, metadata[i].accessID, role, keys[i])
                try {
                    guard.validateWrite(PhysicalCapacityGuard.sealedSize(V2Format.RECOVERY_ANCHOR_PLAINTEXT.toLong()), budget, root)
                    store.create(recoveryNames[i], PoolObjectKind.RECOVERY_ANCHOR, payload, secrets[i], V2Format.RECOVERY_ANCHOR_PLAINTEXT.toLong())
                } catch (e: PoolObjectExistsException) {
                    throw VaultFormatException("recovery anchor already exists")
                } finally {
                    payload.wipe()
                }
                committed += recoveryNames[i]
            }

            // Authenticate all four private anchors before the public envelope exists.
            val reader = V2VaultReader(sodium, root)
            for (i in keys.indices) {
                if (metadataStore.read(keys[i]).accessID != metadata[i].accessID) throw VaultFormatException("invalid envelope")
                val (recovered, accessID) = reader.recoverAccess(envelope, RecoveryKeyText.format(secrets[i]))
                recovered.use {
                    val expectedRole = if (i == 0) AccessRole.VISIBLE else AccessRole.CONCEALED
                    if (it.role != expectedRole || !it.masterKey.contentEquals(keys[i]) || accessID != metadata[i].accessID) {
                        throw VaultFormatException("invalid envelope")
                    }
                }
            }
            if (identity(root) != rootIdentity) throw IOException("vault folder changed during creation")

            val data = envelope.encode()
            if (data.size > V2Format.MAX_ENVELOPE_FILE) throw VaultFormatException("envelope too large")
            try {
                committer.writeNew(data, envelopePath, StagingPrefix.ENVELOPE)
            } catch (e: java.nio.file.FileAlreadyExistsException) {
                throw VaultFormatException("folder already contains a vault")
            }
            wroteEnvelope = true
            AccessEnvelope.parse(readEnvelopeBytes())
        } catch (e: Exception) {
            // Never clean up a folder that is no longer the one we created in.
            if (rootIdentity != null && identity(root) != rootIdentity) throw e
            if (wroteEnvelope) Files.deleteIfExists(envelopePath)
            // Only exact objects this call created; never unknown pool contents.
            for (name in committed) Files.deleteIfExists(store.path(name))
            if (createdPool && isEmptyDirectory(pool)) Files.deleteIfExists(pool)
            if (!rootExisted && isEmptyDirectory(root)) Files.deleteIfExists(root)
            throw e
        }
    }

    private fun recoveryPayload(vaultID: UUID, accessID: UUID, role: AccessRole, masterKey: ByteArray): ByteArray =
        SwiftJson.encode(
            JsonObject(
                mapOf(
                    "accessID" to JsonPrimitive(Uuids.upper(accessID)),
                    "formatVersion" to JsonPrimitive(1),
                    "masterKey" to JsonPrimitive(Codings.base64(masterKey)),
                    "roleRawValue" to JsonPrimitive(role.raw),
                    "vaultID" to JsonPrimitive(Uuids.upper(vaultID)),
                ),
            ),
            escapeSlashes = false,
        )

    /** §4.2/§4.3: fresh salt and nonce; the payload binds the lowercase vault ID. */
    internal fun makeSlot(role: AccessRole, masterKey: ByteArray, password: String, vaultID: UUID): AccessSlot {
        if (masterKey.size != 32) throw VaultFormatException("master key must be 32 bytes")
        val salt = sodium.randomBytes(AccessEnvelope.SALT_BYTES)
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        val slotKey = try {
            sodium.argon2id13(32, passwordBytes, salt, kdf.opsLimit, kdf.memLimit) ?: throw KeyDerivationException()
        } finally {
            passwordBytes.wipe()
        }
        val payload = byteArrayOf(AccessEnvelope.SLOT_PAYLOAD_VERSION.toByte(), role.raw.toByte()) +
            Uuids.lower(vaultID).toByteArray(Charsets.US_ASCII) + masterKey
        try {
            val nonce = sodium.randomBytes(V2Format.NONCE_BYTES)
            return AccessSlot(AccessEnvelope.KDF_ALGORITHM, salt, kdf.opsLimit, kdf.memLimit, nonce + sodium.secretboxEasy(payload, nonce, slotKey))
        } finally {
            slotKey.wipe()
            payload.wipe()
        }
    }

    // MARK: helpers shared with sessions

    internal fun readEnvelopeBytes(): ByteArray {
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) throw VaultFormatException("not a vault folder")
        if (!Files.isRegularFile(envelopePath, LinkOption.NOFOLLOW_LINKS)) throw VaultFormatException("missing vault file")
        if (Files.size(envelopePath) > V2Format.MAX_ENVELOPE_FILE) throw VaultFormatException("envelope too large")
        return java.nio.channels.FileChannel.open(envelopePath, java.nio.file.StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { ch ->
            val size = ch.size()
            if (size > V2Format.MAX_ENVELOPE_FILE) throw VaultFormatException("envelope too large")
            val buffer = java.nio.ByteBuffer.allocate(size.toInt())
            while (buffer.hasRemaining()) if (ch.read(buffer) < 0) throw VaultFormatException("envelope changed while reading")
            buffer.array()
        }
    }

    internal val sodiumForSessions get() = sodium
    internal val rootForSessions get() = root
    internal val metadataForSessions get() = metadataStore
    internal val transactionsForSessions get() = transactions
    internal val coversForSessions get() = covers
    internal val guardForSessions get() = guard
    internal val storeForSessions get() = store
    internal val committerForSessions get() = committer
    internal val envelopePathForSessions get() = envelopePath

    private fun identity(path: Path): Any? = try {
        Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
    } catch (e: IOException) {
        null
    }

    private fun isEmptyDirectory(dir: Path): Boolean = try {
        Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) && Files.newDirectoryStream(dir).use { !it.iterator().hasNext() }
    } catch (e: IOException) {
        false
    }
}

/**
 * One unlocked access path (Swift `V2VaultSession` + `V2VaultSessionStore`).
 * Every operation first checks that the public envelope still equals the one
 * this session opened and that the metadata still has this access ID. [close]
 * wipes the master key.
 */
class V2VaultSession internal constructor(
    private val writer: V2VaultWriter,
    val vaultID: UUID,
    val accessID: UUID,
    val role: AccessRole,
    private val key: ByteArray,
    private var binding: ByteArray,
) : AutoCloseable {
    private var closed = false
    private val metadataStore get() = writer.metadataForSessions
    private val transactions get() = writer.transactionsForSessions

    /** What crash recovery did when this session opened. */
    var recovery: RecoveryReport = RecoveryReport()
        private set

    /** Authenticated metadata, re-read now. */
    fun metadata(): AccessMetadata = validatedMetadata()

    /** Live entries only; the pool is never scanned for more. */
    val entries: List<VaultEntry> get() = validatedMetadata().entries

    fun fixedCapacityStatus(): FixedCapacityStatus? {
        val state = validatedMetadata().fixedCapacity ?: return null
        return FixedCapacityStatus(
            state.capacityBytes, state.isFilled, state.plan().sumOf { it.plaintextByteCount * it.slotCount }, state.ledger.freePlaintextBytes,
        )
    }

    /**
     * Swift `prepareFixedCapacity`: makes this new, empty access path
     * fixed-capacity and writes its covers (the whole capacity, once). Called
     * again with the same size it resumes an interrupted fill; on a filled vault
     * it does nothing. [progress] gets (slots done, slots in all).
     */
    fun prepareFixedCapacity(capacityBytes: Long, progress: ((Long, Long) -> Unit)? = null) {
        val metadata = validatedMetadata()
        requireNoPendingRecovery(metadata)
        val plan = FixedCapacityPlan.slots(capacityBytes)
        val state = metadata.fixedCapacity
        if (state != null) {
            if (state.capacityBytes != capacityBytes) throw VaultFormatException("fixed capacity unavailable")
            if (state.isFilled) return
        } else if (metadata.entries.isNotEmpty()) {
            throw VaultFormatException("fixed capacity unavailable")
        }
        // Refuse up front rather than part way through a fill the device cannot hold.
        val covers = writer.coversForSessions
        writer.guardForSessions.validateWrite(covers.missingBytes(plan, key), metadata.budget, writer.rootForSessions)
        if (state == null) mutate { it.beginningFixedCapacity(capacityBytes) }
        covers.fill(plan, key, progress)
        mutate { it.completingFixedCapacityFill() }
    }

    /** Imports a regular file (links are refused). */
    fun importFile(path: Path, originalName: String = path.fileName.toString()): VaultEntry =
        ImportSource.of(path).use { importSource(it, originalName) }

    /**
     * Imports [source]: one padded object up to 16 777 206 bytes, otherwise
     * 4 MiB chunks streamed in two passes (§10). Never holds more than one
     * chunk of a large file in memory.
     */
    fun importSource(source: ImportSource, originalName: String): VaultEntry {
        val metadata = validatedMetadata()
        requireNoPendingRecovery(metadata)
        AccessMetadata.validateOriginalName(originalName)
        if (source.size <= V2Format.MAX_SINGLE_CONTENT) {
            val data = ByteArray(source.size.toInt())
            try {
                source.openStream().use { stream ->
                    var offset = 0
                    while (offset < data.size) {
                        val n = try {
                            stream.read(data, offset, data.size - offset)
                        } catch (e: IOException) {
                            throw ImportSourceException("source could not be read", e)
                        }
                        if (n < 0) throw ImportSourceException("source changed during import")
                        offset += n
                    }
                    if (stream.read() >= 0) throw ImportSourceException("source changed during import")
                }
                return importData(data, originalName)
            } finally {
                data.wipe()
            }
        }
        val committed = transactions.importChunked(source, originalName, key)
        return persisted(committed)
    }

    /** Imports bytes already in memory (at most 16 777 206; larger content goes through [importSource]). */
    fun importData(data: ByteArray, originalName: String): VaultEntry {
        val metadata = validatedMetadata()
        requireNoPendingRecovery(metadata)
        AccessMetadata.validateOriginalName(originalName)
        val padded = Padding.dataTarget(data.size.toLong())
        return persisted(transactions.importData(data, originalName, key, padded))
    }

    /** Removes one live entry (pending-removal protocol). Returns the transaction ID. */
    fun removeEntry(id: UUID): UUID {
        val metadata = validatedMetadata()
        requireNoPendingRecovery(metadata)
        if (metadata.entries.none { it.id == id }) throw EntryNotFoundException()
        return transactions.removeEntry(id, key)
    }

    /**
     * Decrypts one live entry into [destination] (see [V2VaultReader.OpenedVault.readEntryToFile]).
     * The entry is looked up again by ID in authenticated metadata.
     */
    fun readEntryToFile(entry: VaultEntry, destination: Path) {
        val metadata = validatedMetadata()
        val current = metadata.entries.firstOrNull { it.id == entry.id } ?: throw EntryNotFoundException()
        val reader = V2VaultReader(writer.sodiumForSessions, writer.rootForSessions)
        reader.OpenedVault(vaultID, AccessKey(role, key.copyOf()), metadata).use { it.readEntryToFile(current, destination) }
    }

    /** Completes or aborts authenticated pending work of this access path (runs on open). */
    fun recover(): RecoveryReport {
        validatedMetadata()
        var report = RecoveryReport()
        report = transactions.recoverPendingImports(key, report)
        report = transactions.recoverPendingChunkImports(key, report)
        report = transactions.recoverPendingRemovals(key, report)
        validatedMetadata()
        recovery = report
        return report
    }

    /**
     * Swift `changeVisiblePassword` / `replaceVisiblePassword`: rewrites slot 0
     * only, with a fresh salt and nonce; the master key, metadata, files and
     * the recovery key do not change. Works for a session opened with the old
     * password or with the recovery key.
     */
    fun changePassword(newPassword: String) {
        checkOpen()
        if (role != AccessRole.VISIBLE) throw VaultFormatException("password change unavailable")
        if (newPassword.isEmpty()) throw VaultFormatException("invalid new password")
        validatedMetadata()

        val current = AccessEnvelope.parse(writer.readEnvelopeBytes())
        if (!current.encode().contentEquals(binding)) throw SessionInvalidatedException("envelope changed")
        metadataStore.read(key)
        val updated = AccessEnvelope(
            current.vaultID, current.createdAt,
            listOf(writer.makeSlot(AccessRole.VISIBLE, key, newPassword, current.vaultID), current.slots[1]),
        )
        // The new password must open exactly this key on the visible role (an
        // ambiguous password that also opens slot 1 is refused).
        SlotUnlocker(writer.sodiumForSessions).unlock(updated, newPassword).use {
            if (it.role != AccessRole.VISIBLE || !it.masterKey.contentEquals(key)) throw VaultFormatException("invalid payload")
        }
        val data = updated.encode()
        if (data.size > V2Format.MAX_ENVELOPE_FILE) throw VaultFormatException("envelope too large")
        // Key derivation took a while: check nothing moved in the meantime.
        if (!AccessEnvelope.parse(writer.readEnvelopeBytes()).encode().contentEquals(binding)) {
            throw SessionInvalidatedException("envelope changed")
        }
        try {
            writer.committerForSessions.replaceExisting(data, writer.envelopePathForSessions, StagingPrefix.ENVELOPE)
        } catch (e: Exception) {
            // The swap may have happened and still reported an error.
            val stillOld = try {
                AccessEnvelope.parse(writer.readEnvelopeBytes()).encode().contentEquals(binding)
            } catch (ignored: Exception) {
                false
            }
            if (stillOld) throw IOException("envelope commit failed", e)
            throw PasswordChangeOutcomeUncertainException()
        }
        // From here the new envelope may be published: never report a plain failure.
        try {
            if (!AccessEnvelope.parse(writer.readEnvelopeBytes()).encode().contentEquals(data)) throw IOException("mismatch")
            binding = data
            validatedMetadata()
        } catch (e: Exception) {
            throw PasswordChangeOutcomeUncertainException()
        }
    }

    override fun close() {
        if (!closed) {
            closed = true
            key.wipe()
        }
    }

    private fun persisted(committed: VaultEntry): VaultEntry =
        validatedMetadata().entries.firstOrNull { it.id == committed.id } ?: throw VaultFormatException("committed entry missing")

    private fun mutate(mutation: (AccessMetadata) -> AccessMetadata) {
        repeat(MetadataStore.MAXIMUM_TRANSITION_RETRIES) {
            val current = validatedMetadata()
            val next = mutation(current)
            try {
                metadataStore.commit(current, next, key)
                return
            } catch (e: StaleMetadataException) {
                // Read the newer generation and try again.
            }
        }
        throw VaultFormatException("metadata transition retries exhausted")
    }

    private fun requireNoPendingRecovery(metadata: AccessMetadata) {
        if (metadata.hasPendingWork) throw RecoveryRequiredException()
    }

    private fun validatedMetadata(): AccessMetadata {
        checkOpen()
        val envelope = AccessEnvelope.parse(writer.readEnvelopeBytes())
        if (!envelope.encode().contentEquals(binding) || envelope.vaultID != vaultID) {
            throw SessionInvalidatedException("envelope changed")
        }
        val metadata = metadataStore.read(key)
        if (metadata.accessID != accessID) throw SessionInvalidatedException("access identity changed")
        return metadata
    }

    private fun checkOpen() = check(!closed) { "session is closed" }
}
