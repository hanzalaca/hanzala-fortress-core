import Foundation

public enum OnDemandPlaintextLeaseError: Error, Equatable {
    case entryNotFound
}

/// Manages short-lived plaintext materializations for files that are actively
/// opened through the future Finder/FSKit view.
///
/// The vault itself remains encrypted. A plaintext file is created only when a
/// specific entry is leased, uses a randomized cache filename, and is removed
/// when the final lease token is released or when all leases are invalidated
/// (for example on Vault Lock, unmount, or backing-drive loss).
///
/// This is damage-reduction, not secure erasure. APFS, swap, snapshots, backup
/// software, Quick Look, or an external viewer may retain copies outside this
/// store's control.
public final class OnDemandPlaintextLeaseStore {
    public struct Lease: Sendable, Equatable {
        public let id: UUID
        public let entryID: UUID
        public let plaintextURL: URL

        public init(id: UUID, entryID: UUID, plaintextURL: URL) {
            self.id = id
            self.entryID = entryID
            self.plaintextURL = plaintextURL
        }
    }

    private struct ActiveMaterialization {
        let plaintextURL: URL
        var leaseIDs: Set<UUID>
    }

    private let fileManager: FileManager
    private let objectStore: VaultObjectStore
    private let rootDirectory: URL
    private let lock = NSLock()
    private var materializationsByEntry: [UUID: ActiveMaterialization] = [:]
    private var entryByLeaseID: [UUID: UUID] = [:]

    public init(
        fileManager: FileManager = .default,
        objectStore: VaultObjectStore = VaultObjectStore(),
        rootDirectory: URL? = nil
    ) {
        self.fileManager = fileManager
        self.objectStore = objectStore
        self.rootDirectory = rootDirectory ?? fileManager.temporaryDirectory
            .appendingPathComponent("Hanzalaomator-OnDemandPlaintext", isDirectory: true)
    }

    deinit {
        invalidateAll()
    }

    /// Materializes exactly one requested entry. Repeated opens of the same entry
    /// share one randomized plaintext backing file, but each open receives a
    /// unique lease token so closes can be paired exactly once.
    ///
    /// The lock intentionally covers materialization. This serializes acquire,
    /// release, and invalidateAll so a concurrent Vault Lock/unmount cannot finish
    /// and then have an in-flight acquire publish new plaintext afterward.
    public func acquire(entryID: UUID, from vault: OpenedVault) throws -> Lease {
        lock.lock()
        defer { lock.unlock() }

        if var existing = materializationsByEntry[entryID],
           fileManager.fileExists(atPath: existing.plaintextURL.path) {
            let leaseID = UUID()
            existing.leaseIDs.insert(leaseID)
            materializationsByEntry[entryID] = existing
            entryByLeaseID[leaseID] = entryID
            return Lease(id: leaseID, entryID: entryID, plaintextURL: existing.plaintextURL)
        }

        if let stale = materializationsByEntry.removeValue(forKey: entryID) {
            for leaseID in stale.leaseIDs {
                entryByLeaseID.removeValue(forKey: leaseID)
            }
            try? fileManager.removeItem(at: stale.plaintextURL.deletingLastPathComponent())
        }

        let entries = try objectStore.listEntries(in: vault)
        guard entries.contains(where: { $0.id == entryID }) else {
            throw OnDemandPlaintextLeaseError.entryNotFound
        }

        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        let sessionDirectory = rootDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fileManager.createDirectory(at: sessionDirectory, withIntermediateDirectories: false)
        let destinationURL = sessionDirectory.appendingPathComponent(UUID().uuidString, isDirectory: false)

        do {
            try objectStore.exportFile(entryID: entryID, from: vault, to: destinationURL)
        } catch {
            try? fileManager.removeItem(at: sessionDirectory)
            throw error
        }

        let leaseID = UUID()
        materializationsByEntry[entryID] = ActiveMaterialization(
            plaintextURL: destinationURL,
            leaseIDs: [leaseID]
        )
        entryByLeaseID[leaseID] = entryID
        return Lease(id: leaseID, entryID: entryID, plaintextURL: destinationURL)
    }

    /// Releases one open reference. Releasing the same token twice is a no-op.
    /// The plaintext backing file disappears after the final unique lease token
    /// for that entry is released.
    public func release(_ lease: Lease) {
        lock.lock()
        defer { lock.unlock() }

        guard let entryID = entryByLeaseID.removeValue(forKey: lease.id),
              var active = materializationsByEntry[entryID],
              active.leaseIDs.remove(lease.id) != nil else {
            return
        }

        if !active.leaseIDs.isEmpty {
            materializationsByEntry[entryID] = active
            return
        }

        materializationsByEntry.removeValue(forKey: entryID)
        try? fileManager.removeItem(at: active.plaintextURL.deletingLastPathComponent())
    }

    /// Removes every active plaintext materialization. Call before dropping the
    /// unlocked vault session and during unmount/eject/backing-drive-loss handling.
    public func invalidateAll() {
        lock.lock()
        defer { lock.unlock() }

        let directories = materializationsByEntry.values.map {
            $0.plaintextURL.deletingLastPathComponent()
        }
        materializationsByEntry.removeAll()
        entryByLeaseID.removeAll()

        for directory in directories {
            try? fileManager.removeItem(at: directory)
        }
        try? fileManager.removeItem(at: rootDirectory)
    }

    public func activeEntryIDs() -> Set<UUID> {
        lock.lock()
        defer { lock.unlock() }
        return Set(materializationsByEntry.keys)
    }

    public func activeLeaseCount(for entryID: UUID) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return materializationsByEntry[entryID]?.leaseIDs.count ?? 0
    }
}
