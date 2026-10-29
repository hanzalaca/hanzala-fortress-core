import Foundation

public enum VaultStoreError: Error, Equatable {
    case rootAlreadyContainsVault
    case missingHeader
    case invalidHeader
    case missingIndex
    case missingObjectsDirectory
}

public struct OpenedVault: Sendable {
    public let root: URL
    public let header: VaultHeader
    public let masterKey: Data

    public init(root: URL, header: VaultHeader, masterKey: Data) {
        self.root = root
        self.header = header
        self.masterKey = masterKey
    }
}

public final class VaultStore {
    private let fileManager: FileManager
    private let keyManager: VaultKeyManager
    private let indexStore: EncryptedIndexStore
    private let transactionJournal: VaultTransactionJournal
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        fileManager: FileManager = .default,
        keyManager: VaultKeyManager = VaultKeyManager(),
        indexStore: EncryptedIndexStore = EncryptedIndexStore(),
        transactionJournal: VaultTransactionJournal? = nil
    ) {
        self.fileManager = fileManager
        self.keyManager = keyManager
        self.indexStore = indexStore
        self.transactionJournal = transactionJournal ?? VaultTransactionJournal(fileManager: fileManager)
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.encoder.outputFormatting = [.sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder.dateDecodingStrategy = .iso8601
    }

    public func createVault(at root: URL, password: String) throws -> OpenedVault {
        let headerURL = VaultLayout.headerURL(in: root)
        let indexURL = VaultLayout.indexURL(in: root)
        let objectsURL = VaultLayout.objectsURL(in: root)

        // Never reuse or remove an existing Hanzalaomator layout component.
        // This prevents a failed creation attempt from deleting unrelated user data.
        guard !fileManager.fileExists(atPath: headerURL.path),
              !fileManager.fileExists(atPath: indexURL.path),
              !fileManager.fileExists(atPath: objectsURL.path) else {
            throw VaultStoreError.rootAlreadyContainsVault
        }

        let rootExistedBeforeCreation = fileManager.fileExists(atPath: root.path)
        var createdObjectsDirectory = false
        var wroteHeader = false
        var wroteIndex = false

        do {
            try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
            try fileManager.createDirectory(at: objectsURL, withIntermediateDirectories: false)
            createdObjectsDirectory = true

            let created = try keyManager.createHeader(password: password)
            let headerData = try encoder.encode(created.header)
            try SecureFileWriter.atomicallyWrite(headerData, to: headerURL)
            wroteHeader = true

            try indexStore.write(VaultIndex(), to: indexURL, masterKey: created.masterKey)
            wroteIndex = true

            return OpenedVault(root: root, header: created.header, masterKey: created.masterKey)
        } catch {
            if wroteIndex {
                try? fileManager.removeItem(at: indexURL)
            }
            if wroteHeader {
                try? fileManager.removeItem(at: headerURL)
            }
            if createdObjectsDirectory {
                try? fileManager.removeItem(at: objectsURL)
            }
            if !rootExistedBeforeCreation {
                try? fileManager.removeItem(at: root)
            }
            throw error
        }
    }

    public func createVaultWithRecovery(at root: URL, password: String) throws -> (vault: OpenedVault, recoveryKey: String) {
        let headerURL = VaultLayout.headerURL(in: root)
        let indexURL = VaultLayout.indexURL(in: root)
        let objectsURL = VaultLayout.objectsURL(in: root)

        guard !fileManager.fileExists(atPath: headerURL.path),
              !fileManager.fileExists(atPath: indexURL.path),
              !fileManager.fileExists(atPath: objectsURL.path) else {
            throw VaultStoreError.rootAlreadyContainsVault
        }

        let rootExistedBeforeCreation = fileManager.fileExists(atPath: root.path)
        var createdObjectsDirectory = false
        var wroteHeader = false
        var wroteIndex = false

        do {
            try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
            try fileManager.createDirectory(at: objectsURL, withIntermediateDirectories: false)
            createdObjectsDirectory = true

            let created = try keyManager.createHeaderWithRecovery(password: password)
            let headerData = try encoder.encode(created.header)
            try SecureFileWriter.atomicallyWrite(headerData, to: headerURL)
            wroteHeader = true

            try indexStore.write(VaultIndex(), to: indexURL, masterKey: created.masterKey)
            wroteIndex = true

            let vault = OpenedVault(root: root, header: created.header, masterKey: created.masterKey)
            return (vault, created.recoveryKey)
        } catch {
            if wroteIndex {
                try? fileManager.removeItem(at: indexURL)
            }
            if wroteHeader {
                try? fileManager.removeItem(at: headerURL)
            }
            if createdObjectsDirectory {
                try? fileManager.removeItem(at: objectsURL)
            }
            if !rootExistedBeforeCreation {
                try? fileManager.removeItem(at: root)
            }
            throw error
        }
    }

    public func openVault(at root: URL, password: String) throws -> OpenedVault {
        let header = try readHeader(at: root)
        let masterKey = try keyManager.unlock(header: header, password: password)
        try validateVaultLayout(at: root, masterKey: masterKey)
        return OpenedVault(root: root, header: header, masterKey: masterKey)
    }

    public func openVault(at root: URL, recoveryKey: String) throws -> OpenedVault {
        let header = try readHeader(at: root)
        let masterKey = try keyManager.unlockWithRecovery(header: header, recoveryKey: recoveryKey)
        try validateVaultLayout(at: root, masterKey: masterKey)
        return OpenedVault(root: root, header: header, masterKey: masterKey)
    }

    public func changePassword(for vault: OpenedVault, to newPassword: String) throws -> OpenedVault {
        let updatedHeader = try keyManager.rewrapPassword(
            header: vault.header,
            masterKey: vault.masterKey,
            newPassword: newPassword
        )
        let headerData = try encoder.encode(updatedHeader)
        try SecureFileWriter.atomicallyWrite(headerData, to: VaultLayout.headerURL(in: vault.root))
        return OpenedVault(root: vault.root, header: updatedHeader, masterKey: vault.masterKey)
    }

    public func recoverVault(
        at root: URL,
        recoveryKey: String,
        newPassword: String
    ) throws -> OpenedVault {
        let recovered = try openVault(at: root, recoveryKey: recoveryKey)
        return try changePassword(for: recovered, to: newPassword)
    }

    public func rotateRecoveryKey(for vault: OpenedVault) throws -> (vault: OpenedVault, recoveryKey: String) {
        let rotated = try keyManager.rotateRecoveryKey(
            header: vault.header,
            masterKey: vault.masterKey
        )
        let headerData = try encoder.encode(rotated.header)
        try SecureFileWriter.atomicallyWrite(headerData, to: VaultLayout.headerURL(in: vault.root))
        let updatedVault = OpenedVault(root: vault.root, header: rotated.header, masterKey: vault.masterKey)
        return (updatedVault, rotated.recoveryKey)
    }

    private func readHeader(at root: URL) throws -> VaultHeader {
        let headerURL = VaultLayout.headerURL(in: root)
        guard fileManager.fileExists(atPath: headerURL.path) else {
            throw VaultStoreError.missingHeader
        }

        let data = try Data(contentsOf: headerURL)
        do {
            return try decoder.decode(VaultHeader.self, from: data)
        } catch {
            throw VaultStoreError.invalidHeader
        }
    }

    private func validateVaultLayout(at root: URL, masterKey: Data) throws {
        let indexURL = VaultLayout.indexURL(in: root)
        guard fileManager.fileExists(atPath: indexURL.path) else {
            throw VaultStoreError.missingIndex
        }

        var isDirectory: ObjCBool = false
        let objectsURL = VaultLayout.objectsURL(in: root)
        guard fileManager.fileExists(atPath: objectsURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw VaultStoreError.missingObjectsDirectory
        }

        // The encrypted index is authenticated before it is trusted as the source
        // of truth for transaction recovery.
        let index = try indexStore.read(from: indexURL, masterKey: masterKey)
        let referencedOpaqueNames = Set(index.entries.map(\.opaqueObjectName))
        try transactionJournal.recoverImports(
            in: root,
            referencedOpaqueNames: referencedOpaqueNames
        )
    }
}
