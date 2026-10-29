import Foundation

public enum VaultObjectStoreError: Error, Equatable {
    case missingIndex
    case missingObject
    case entryNotFound
    case invalidSourceFile
}

public final class VaultObjectStore {
    private let fileManager: FileManager
    private let streamEngine: SecretStreamEngine
    private let indexStore: EncryptedIndexStore
    private let keyDeriver: DomainKeyDeriver
    private let transactionJournal: VaultTransactionJournal

    public init(
        fileManager: FileManager = .default,
        streamEngine: SecretStreamEngine = SecretStreamEngine(),
        indexStore: EncryptedIndexStore = EncryptedIndexStore(),
        keyDeriver: DomainKeyDeriver = DomainKeyDeriver(),
        transactionJournal: VaultTransactionJournal? = nil
    ) {
        self.fileManager = fileManager
        self.streamEngine = streamEngine
        self.indexStore = indexStore
        self.keyDeriver = keyDeriver
        self.transactionJournal = transactionJournal ?? VaultTransactionJournal(fileManager: fileManager)
    }

    @discardableResult
    public func importFile(at sourceURL: URL, into vault: OpenedVault) throws -> VaultEntry {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: sourceURL.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            throw VaultObjectStoreError.invalidSourceFile
        }

        let indexURL = VaultLayout.indexURL(in: vault.root)
        guard fileManager.fileExists(atPath: indexURL.path) else {
            throw VaultObjectStoreError.missingIndex
        }

        var index = try indexStore.read(from: indexURL, masterKey: vault.masterKey)
        let objectKey = try keyDeriver.derive(masterKey: vault.masterKey, purpose: .objectV1)
        let opaqueName = UUID().uuidString + ".hzo"
        let objectURL = VaultLayout.objectURL(named: opaqueName, in: vault.root)

        let attributes = try fileManager.attributesOfItem(atPath: sourceURL.path)
        let byteCount = (attributes[.size] as? NSNumber)?.uint64Value ?? 0
        let entry = VaultEntry(
            opaqueObjectName: opaqueName,
            originalName: sourceURL.lastPathComponent,
            byteCount: byteCount
        )

        // Persist a minimal opaque journal record before creating the encrypted
        // object. The record contains no original filename or plaintext metadata.
        let journalRecord = try transactionJournal.beginImport(
            in: vault.root,
            opaqueObjectName: opaqueName
        )

        do {
            try streamEngine.encryptFile(at: sourceURL, to: objectURL, key: objectKey)
            index.entries.append(entry)
            try indexStore.write(index, to: indexURL, masterKey: vault.masterKey)
        } catch {
            var rollbackSucceeded = true
            if fileManager.fileExists(atPath: objectURL.path) {
                do {
                    try fileManager.removeItem(at: objectURL)
                } catch {
                    rollbackSucceeded = false
                }
            }
            if rollbackSucceeded {
                try? transactionJournal.finishImport(journalRecord, in: vault.root)
            }
            throw error
        }

        // The index write is the commit point. If journal cleanup itself fails,
        // recovery on the next vault open will see the indexed object and preserve it.
        try? transactionJournal.finishImport(journalRecord, in: vault.root)
        return entry
    }

    public func exportFile(entryID: UUID, from vault: OpenedVault, to destinationURL: URL) throws {
        let (entry, objectURL) = try resolveObject(entryID: entryID, in: vault)
        let objectKey = try keyDeriver.derive(masterKey: vault.masterKey, purpose: .objectV1)
        _ = entry
        try streamEngine.decryptFile(at: objectURL, to: destinationURL, key: objectKey)
    }

    /// Streams authenticated plaintext for one vault object to a caller without
    /// creating a decrypted file on disk. This is the primitive intended for
    /// virtual filesystem backends such as the Finder mount.
    public func streamFile(
        entryID: UUID,
        from vault: OpenedVault,
        consume: (Data) throws -> Void
    ) throws {
        let (_, objectURL) = try resolveObject(entryID: entryID, in: vault)
        let objectKey = try keyDeriver.derive(masterKey: vault.masterKey, purpose: .objectV1)
        try streamEngine.decryptFileChunks(at: objectURL, key: objectKey, consume: consume)
    }

    public func listEntries(in vault: OpenedVault) throws -> [VaultEntry] {
        let indexURL = VaultLayout.indexURL(in: vault.root)
        guard fileManager.fileExists(atPath: indexURL.path) else {
            throw VaultObjectStoreError.missingIndex
        }
        return try indexStore.read(from: indexURL, masterKey: vault.masterKey).entries
    }

    private func resolveObject(entryID: UUID, in vault: OpenedVault) throws -> (VaultEntry, URL) {
        let indexURL = VaultLayout.indexURL(in: vault.root)
        guard fileManager.fileExists(atPath: indexURL.path) else {
            throw VaultObjectStoreError.missingIndex
        }

        let index = try indexStore.read(from: indexURL, masterKey: vault.masterKey)
        guard let entry = index.entries.first(where: { $0.id == entryID }) else {
            throw VaultObjectStoreError.entryNotFound
        }

        let objectURL = VaultLayout.objectURL(named: entry.opaqueObjectName, in: vault.root)
        guard fileManager.fileExists(atPath: objectURL.path) else {
            throw VaultObjectStoreError.missingObject
        }
        return (entry, objectURL)
    }
}
