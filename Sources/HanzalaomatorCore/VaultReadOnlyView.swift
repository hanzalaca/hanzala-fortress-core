import Foundation

public enum VaultReadOnlyViewError: Error, Equatable {
    case invalidRange
    case entryNotFound
    case missingObject
}

/// Read-only presentation adapter intended for Finder/FSKit integration.
///
/// It exposes decrypted names/metadata from the encrypted index and serves
/// authenticated plaintext ranges directly from encrypted objects without
/// creating a persistent plaintext mirror of the vault.
public final class VaultReadOnlyView {
    private let fileManager: FileManager
    private let objectStore: VaultObjectStore
    private let indexStore: EncryptedIndexStore
    private let keyDeriver: DomainKeyDeriver
    private let streamEngine: SecretStreamEngine

    public init(
        fileManager: FileManager = .default,
        objectStore: VaultObjectStore = VaultObjectStore(),
        indexStore: EncryptedIndexStore = EncryptedIndexStore(),
        keyDeriver: DomainKeyDeriver = DomainKeyDeriver(),
        streamEngine: SecretStreamEngine = SecretStreamEngine()
    ) {
        self.fileManager = fileManager
        self.objectStore = objectStore
        self.indexStore = indexStore
        self.keyDeriver = keyDeriver
        self.streamEngine = streamEngine
    }

    public func entries(in vault: OpenedVault) throws -> [VaultEntry] {
        try objectStore.listEntries(in: vault)
    }

    /// Returns at most `length` plaintext bytes beginning at `offset`.
    ///
    /// Secretstream is sequential, so this first implementation authenticates
    /// frames from the beginning of the encrypted object and discards plaintext
    /// before the requested range. This is intentionally correctness-first for
    /// the read-only Finder milestone. A later seekable object format can make
    /// large random reads efficient without changing the presentation API.
    public func read(
        entryID: UUID,
        from vault: OpenedVault,
        offset: UInt64,
        length: Int
    ) throws -> Data {
        guard length >= 0 else { throw VaultReadOnlyViewError.invalidRange }
        if length == 0 { return Data() }

        let indexURL = VaultLayout.indexURL(in: vault.root)
        let index = try indexStore.read(from: indexURL, masterKey: vault.masterKey)
        guard let entry = index.entries.first(where: { $0.id == entryID }) else {
            throw VaultReadOnlyViewError.entryNotFound
        }

        guard offset < entry.byteCount else { return Data() }

        let objectURL = VaultLayout.objectURL(named: entry.opaqueObjectName, in: vault.root)
        guard fileManager.fileExists(atPath: objectURL.path) else {
            throw VaultReadOnlyViewError.missingObject
        }

        let objectKey = try keyDeriver.derive(masterKey: vault.masterKey, purpose: .objectV1)
        let (candidateEnd, overflow) = offset.addingReportingOverflow(UInt64(length))
        let requestedEnd = overflow ? entry.byteCount : min(entry.byteCount, candidateEnd)
        var plaintextPosition: UInt64 = 0
        var result = Data()
        result.reserveCapacity(Int(requestedEnd - offset))

        try streamEngine.decryptFileChunks(at: objectURL, key: objectKey) { chunk in
            let chunkStart = plaintextPosition
            let (chunkEnd, chunkOverflow) = chunkStart.addingReportingOverflow(UInt64(chunk.count))
            guard !chunkOverflow else { throw VaultReadOnlyViewError.invalidRange }
            defer { plaintextPosition = chunkEnd }

            guard chunkEnd > offset, chunkStart < requestedEnd else { return }

            let lower = Int(max(offset, chunkStart) - chunkStart)
            let upper = Int(min(requestedEnd, chunkEnd) - chunkStart)
            if lower < upper {
                result.append(chunk.subdata(in: lower..<upper))
            }
        }

        return result
    }
}
