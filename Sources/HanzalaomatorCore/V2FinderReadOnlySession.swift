import Foundation

public enum V2FinderReadOnlySessionError: Error, Equatable, Sendable {
    case sessionInvalidated
    case entryNotFound
    case invalidReadRange
    case readTooLarge
    case handleNotFound
}

/// Read-only Finder-facing semantic session for an already-open v2 access path.
///
/// Unlike the legacy v1 Finder bridge, this type never creates a plaintext lease
/// file. `open` establishes only a logical handle after the entry is found in
/// authenticated per-access metadata. `read` delegates bounded logical ranges to
/// `V2VaultSessionStore`, which authenticates the session/entry and decrypts only
/// the requested single object or intersecting chunks in memory.
///
/// This type deliberately has no FSKit dependency. A later keyless RPC/FSKit
/// integration can translate Finder callbacks into this surface without moving a
/// password, master key, manifest name, or chunk name across the extension boundary.
public final class V2FinderReadOnlySession {
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

    public struct OpenHandle: Sendable, Equatable, Hashable, Identifiable {
        public let id: UUID
        public let entryID: UUID

        public init(id: UUID, entryID: UUID) {
            self.id = id
            self.entryID = entryID
        }
    }

    public static let defaultMaximumReadLength = V2VaultSessionStore.defaultMaximumReadLength

    private let session: V2VaultSession
    private let sessionStore: V2VaultSessionStore
    private let maximumReadLength: Int
    private let lock = NSLock()

    private var invalidated = false
    private var handles: [UUID: OpenHandle] = [:]

    public init(
        session: V2VaultSession,
        sessionStore: V2VaultSessionStore = V2VaultSessionStore(),
        maximumReadLength: Int = V2FinderReadOnlySession.defaultMaximumReadLength
    ) {
        precondition(maximumReadLength > 0)
        self.session = session
        self.sessionStore = sessionStore
        self.maximumReadLength = maximumReadLength
    }

    deinit {
        invalidate()
    }

    /// Lists names/metadata from this access path's authenticated private index.
    /// No file content is decrypted as a side effect.
    public func listRoot() throws -> [FileInfo] {
        try ensureActive()
        let entries = try sessionStore.listEntries(in: session)
        try ensureActive()
        return entries.map {
            FileInfo(
                id: $0.id,
                name: $0.originalName,
                byteCount: $0.logicalByteCount,
                createdAt: $0.createdAt
            )
        }
    }

    /// Opens one authenticated logical entry without creating a plaintext file.
    public func open(entryID: UUID) throws -> OpenHandle {
        try ensureActive()
        let entries = try sessionStore.listEntries(in: session)
        guard entries.contains(where: { $0.id == entryID }) else {
            throw V2FinderReadOnlySessionError.entryNotFound
        }

        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else {
            throw V2FinderReadOnlySessionError.sessionInvalidated
        }
        let handle = OpenHandle(id: UUID(), entryID: entryID)
        handles[handle.id] = handle
        return handle
    }

    /// Returns only the requested authenticated logical range.
    ///
    /// A forged/stale handle never becomes a raw object-name capability. The
    /// underlying session store reloads authenticated metadata again for every
    /// range read. If invalidation races a read, plaintext produced by the store
    /// is discarded and not returned after the invalidated state is observed.
    public func read(
        handle: OpenHandle,
        offset: UInt64,
        length: Int
    ) throws -> Data {
        guard length >= 0 else {
            throw V2FinderReadOnlySessionError.invalidReadRange
        }
        guard length <= maximumReadLength else {
            throw V2FinderReadOnlySessionError.readTooLarge
        }

        lock.lock()
        guard !invalidated else {
            lock.unlock()
            throw V2FinderReadOnlySessionError.sessionInvalidated
        }
        guard let stored = handles[handle.id], stored == handle else {
            lock.unlock()
            throw V2FinderReadOnlySessionError.handleNotFound
        }
        lock.unlock()

        let data = try sessionStore.readEntryRange(
            id: handle.entryID,
            offset: offset,
            length: length,
            in: session
        )

        // Do not return freshly decrypted bytes after a concurrent Lock/unmount.
        try ensureActive()
        return data
    }

    public func close(_ handle: OpenHandle) {
        lock.lock()
        handles.removeValue(forKey: handle.id)
        lock.unlock()
    }

    /// Fail-closed transition used by Lock, unmount, app termination, or backing
    /// drive loss. There are no plaintext leases to clean up in this v2 bridge;
    /// invalidation atomically prevents new logical I/O and forgets every handle.
    public func invalidate() {
        lock.lock()
        if invalidated {
            lock.unlock()
            return
        }
        invalidated = true
        handles.removeAll()
        lock.unlock()
    }

    public func activeEntryIDs() -> Set<UUID> {
        lock.lock()
        defer { lock.unlock() }
        return Set(handles.values.map(\.entryID))
    }

    private func ensureActive() throws {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else {
            throw V2FinderReadOnlySessionError.sessionInvalidated
        }
    }
}
