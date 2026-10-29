import Foundation

public enum FinderReadOnlySessionError: Error, Equatable {
    case sessionInvalidated
    case entryNotFound
    case invalidReadRange
    case leaseNotFound
}

/// Core-side bridge for a future FSKit read-only volume.
///
/// This type intentionally has no dependency on FSKit so the encrypted-vault
/// semantics remain unit-testable on the existing SwiftPM CI. The FSKit app
/// extension will translate Finder filesystem callbacks into these methods.
///
/// Security model:
/// - Enumerating the mounted root reveals decrypted names/metadata only.
/// - File content is not materialized by enumeration.
/// - `open` materializes only the requested entry through the on-demand lease store.
/// - `close` releases that one open handle.
/// - `invalidate` blocks new I/O and removes all Hanzalaomator-owned plaintext.
public final class FinderReadOnlySession {
    public struct FileInfo: Sendable, Equatable, Identifiable {
        public let id: UUID
        public let name: String
        public let byteCount: UInt64
        public let createdAt: Date

        public init(id: UUID, name: String, byteCount: UInt64, createdAt: Date) {
            self.id = id
            self.name = name
            self.byteCount = byteCount
            self.createdAt = createdAt
        }
    }

    public struct OpenHandle: Sendable, Equatable, Identifiable {
        public let id: UUID
        public let entryID: UUID

        public init(id: UUID, entryID: UUID) {
            self.id = id
            self.entryID = entryID
        }
    }

    private let vault: OpenedVault
    private let objectStore: VaultObjectStore
    private let leaseStore: OnDemandPlaintextLeaseStore
    private let lock = NSLock()

    private var invalidated = false
    private var leasesByHandle: [UUID: OnDemandPlaintextLeaseStore.Lease] = [:]

    public init(
        vault: OpenedVault,
        objectStore: VaultObjectStore = VaultObjectStore(),
        leaseStore: OnDemandPlaintextLeaseStore = OnDemandPlaintextLeaseStore()
    ) {
        self.vault = vault
        self.objectStore = objectStore
        self.leaseStore = leaseStore
    }

    deinit {
        invalidate()
    }

    public func listRoot() throws -> [FileInfo] {
        try ensureActive()
        return try objectStore.listEntries(in: vault).map {
            FileInfo(id: $0.id, name: $0.originalName, byteCount: $0.byteCount, createdAt: $0.createdAt)
        }
    }

    /// Opens exactly one vault entry for Finder-style access.
    /// No other entry is decrypted as a side effect.
    public func open(entryID: UUID) throws -> OpenHandle {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else { throw FinderReadOnlySessionError.sessionInvalidated }

        let entries = try objectStore.listEntries(in: vault)
        guard entries.contains(where: { $0.id == entryID }) else {
            throw FinderReadOnlySessionError.entryNotFound
        }

        let lease = try leaseStore.acquire(entryID: entryID, from: vault)
        let handle = OpenHandle(id: UUID(), entryID: entryID)
        leasesByHandle[handle.id] = lease
        return handle
    }

    /// Reads plaintext bytes from the one file represented by `handle`.
    /// The caller receives only the requested range from the active lease.
    public func read(handle: OpenHandle, offset: UInt64, length: Int) throws -> Data {
        guard length >= 0 else { throw FinderReadOnlySessionError.invalidReadRange }

        lock.lock()
        guard !invalidated else {
            lock.unlock()
            throw FinderReadOnlySessionError.sessionInvalidated
        }
        guard let lease = leasesByHandle[handle.id], lease.entryID == handle.entryID else {
            lock.unlock()
            throw FinderReadOnlySessionError.leaseNotFound
        }
        let url = lease.plaintextURL
        lock.unlock()

        if length == 0 { return Data() }
        let handleFile = try FileHandle(forReadingFrom: url)
        defer { try? handleFile.close() }
        try handleFile.seek(toOffset: offset)
        return try handleFile.read(upToCount: length) ?? Data()
    }

    public func close(_ handle: OpenHandle) {
        lock.lock()
        guard let lease = leasesByHandle.removeValue(forKey: handle.id) else {
            lock.unlock()
            return
        }
        lock.unlock()
        leaseStore.release(lease)
    }

    /// Fail-closed transition used by Lock, unmount, app termination, or backing
    /// drive loss. New I/O is rejected before plaintext leases are invalidated.
    public func invalidate() {
        lock.lock()
        if invalidated {
            lock.unlock()
            return
        }
        invalidated = true
        leasesByHandle.removeAll()
        lock.unlock()

        leaseStore.invalidateAll()
    }

    public func activeEntryIDs() -> Set<UUID> {
        leaseStore.activeEntryIDs()
    }

    private func ensureActive() throws {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else { throw FinderReadOnlySessionError.sessionInvalidated }
    }
}
