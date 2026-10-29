import Foundation

public enum VaultTransactionJournalError: Error, Equatable {
    case invalidOpaqueObjectName
    case malformedRecord
    case unsupportedVersion
}

public struct VaultImportJournalRecord: Codable, Equatable, Sendable {
    public let formatVersion: UInt32
    public let transactionID: UUID
    public let opaqueObjectName: String
    public let createdAt: Date

    public init(
        formatVersion: UInt32 = 1,
        transactionID: UUID = UUID(),
        opaqueObjectName: String,
        createdAt: Date = Date()
    ) {
        self.formatVersion = formatVersion
        self.transactionID = transactionID
        self.opaqueObjectName = opaqueObjectName
        self.createdAt = createdAt
    }
}

/// Minimal crash-recovery journal for object imports.
///
/// Journal records intentionally contain only opaque encrypted-object identifiers,
/// never original filenames or plaintext metadata. On vault reopen, a pending
/// import is considered committed when the encrypted index references its object;
/// otherwise any leftover encrypted object is rolled back as an orphan.
public final class VaultTransactionJournal {
    private let fileManager: FileManager
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.encoder.outputFormatting = [.sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder.dateDecodingStrategy = .iso8601
    }

    @discardableResult
    public func beginImport(in root: URL, opaqueObjectName: String) throws -> VaultImportJournalRecord {
        guard isSafeOpaqueObjectName(opaqueObjectName) else {
            throw VaultTransactionJournalError.invalidOpaqueObjectName
        }

        let record = VaultImportJournalRecord(opaqueObjectName: opaqueObjectName)
        let directory = VaultLayout.journalURL(in: root)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )

        let data = try encoder.encode(record)
        try SecureFileWriter.atomicallyWrite(
            data,
            to: VaultLayout.journalRecordURL(transactionID: record.transactionID, in: root)
        )
        return record
    }

    public func finishImport(_ record: VaultImportJournalRecord, in root: URL) throws {
        let url = VaultLayout.journalRecordURL(transactionID: record.transactionID, in: root)
        if fileManager.fileExists(atPath: url.path) {
            try fileManager.removeItem(at: url)
        }
        try removeJournalDirectoryIfEmpty(in: root)
    }

    /// Reconciles pending import records against the authenticated encrypted index.
    ///
    /// A referenced object is treated as committed and preserved. An unreferenced
    /// object from a valid journal record is an interrupted-import orphan and is
    /// removed. Malformed or suspicious journal records are left untouched and
    /// never cause object deletion.
    public func recoverImports(in root: URL, referencedOpaqueNames: Set<String>) throws {
        let directory = VaultLayout.journalURL(in: root)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return
        }

        let urls = try fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: []
        )

        for url in urls where isJournalRecordURL(url) {
            let record: VaultImportJournalRecord
            do {
                let data = try Data(contentsOf: url)
                record = try decoder.decode(VaultImportJournalRecord.self, from: data)
                guard record.formatVersion == 1 else {
                    throw VaultTransactionJournalError.unsupportedVersion
                }
                guard isSafeOpaqueObjectName(record.opaqueObjectName) else {
                    throw VaultTransactionJournalError.invalidOpaqueObjectName
                }
            } catch {
                // Fail conservatively: a record we cannot authenticate structurally
                // is never allowed to trigger deletion of an encrypted object.
                continue
            }

            if !referencedOpaqueNames.contains(record.opaqueObjectName) {
                let objectURL = VaultLayout.objectURL(named: record.opaqueObjectName, in: root)
                if fileManager.fileExists(atPath: objectURL.path) {
                    try fileManager.removeItem(at: objectURL)
                }
            }

            try fileManager.removeItem(at: url)
        }

        try removeJournalDirectoryIfEmpty(in: root)
    }

    public func pendingImports(in root: URL) throws -> [VaultImportJournalRecord] {
        let directory = VaultLayout.journalURL(in: root)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return []
        }

        return try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter(isJournalRecordURL)
            .compactMap { url in
                guard let data = try? Data(contentsOf: url),
                      let record = try? decoder.decode(VaultImportJournalRecord.self, from: data),
                      record.formatVersion == 1,
                      isSafeOpaqueObjectName(record.opaqueObjectName) else {
                    return nil
                }
                return record
            }
            .sorted { $0.createdAt < $1.createdAt }
    }

    private func isJournalRecordURL(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return name.hasPrefix("import-") && name.hasSuffix(".json")
    }

    private func isSafeOpaqueObjectName(_ name: String) -> Bool {
        guard !name.isEmpty,
              name.hasSuffix(".hzo"),
              !name.contains("/"),
              !name.contains("\\"),
              name != ".",
              name != ".." else {
            return false
        }
        return URL(fileURLWithPath: name).lastPathComponent == name
    }

    private func removeJournalDirectoryIfEmpty(in root: URL) throws {
        let directory = VaultLayout.journalURL(in: root)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return
        }
        let contents = try fileManager.contentsOfDirectory(atPath: directory.path)
        if contents.isEmpty {
            try fileManager.removeItem(at: directory)
        }
    }
}
