import Foundation

public enum FinderSessionRPCError: Error, Equatable {
    case invalidated
    case invalidReadLength
    case readTooLarge
    case unknownHandle
}

/// Keyless semantic RPC facade for the FSKit mount.
///
/// The RPC surface is intentionally storage-format neutral. The unlocked main app
/// may back it with the existing v1 plaintext-lease session or the v2 logical
/// bounded-read session. FSKit callers receive only logical file metadata, opaque
/// handles, and bounded plaintext responses; passwords, master keys, v2 manifest
/// names, chunk names, and plaintext backing paths never cross this boundary.
public final class FinderSessionRPC {
    public struct RemoteFile: Sendable, Equatable, Identifiable {
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

    public struct RemoteHandle: Sendable, Equatable, Hashable, Identifiable {
        public let id: UUID
        public let entryID: UUID

        public init(id: UUID, entryID: UUID) {
            self.id = id
            self.entryID = entryID
        }
    }

    public static let defaultMaximumReadLength = 4 * 1024 * 1024

    private enum LocalHandle {
        case v1(FinderReadOnlySession.OpenHandle)
        case v2(V2FinderReadOnlySession.OpenHandle)

        var entryID: UUID {
            switch self {
            case .v1(let handle):
                return handle.entryID
            case .v2(let handle):
                return handle.entryID
            }
        }
    }

    private enum Backend {
        case v1(FinderReadOnlySession)
        case v2(V2FinderReadOnlySession)

        func listRoot() throws -> [RemoteFile] {
            switch self {
            case .v1(let session):
                return try session.listRoot().map {
                    RemoteFile(
                        id: $0.id,
                        name: $0.name,
                        byteCount: $0.byteCount,
                        createdAt: $0.createdAt
                    )
                }
            case .v2(let session):
                return try session.listRoot().map {
                    RemoteFile(
                        id: $0.id,
                        name: $0.name,
                        byteCount: $0.byteCount,
                        createdAt: $0.createdAt
                    )
                }
            }
        }

        func open(entryID: UUID) throws -> LocalHandle {
            switch self {
            case .v1(let session):
                return .v1(try session.open(entryID: entryID))
            case .v2(let session):
                return .v2(try session.open(entryID: entryID))
            }
        }

        func read(
            handle: LocalHandle,
            offset: UInt64,
            length: Int
        ) throws -> Data {
            switch (self, handle) {
            case (.v1(let session), .v1(let local)):
                return try session.read(handle: local, offset: offset, length: length)
            case (.v2(let session), .v2(let local)):
                return try session.read(handle: local, offset: offset, length: length)
            default:
                throw FinderSessionRPCError.unknownHandle
            }
        }

        func close(_ handle: LocalHandle) {
            switch (self, handle) {
            case (.v1(let session), .v1(let local)):
                session.close(local)
            case (.v2(let session), .v2(let local)):
                session.close(local)
            default:
                return
            }
        }

        func invalidate() {
            switch self {
            case .v1(let session):
                session.invalidate()
            case .v2(let session):
                session.invalidate()
            }
        }
    }

    private let backend: Backend
    private let maximumReadLength: Int
    private let lock = NSLock()
    private var invalidated = false
    private var localHandles: [UUID: LocalHandle] = [:]

    /// Existing v1 initializer retained without source changes for current
    /// production callers.
    public init(
        session: FinderReadOnlySession,
        maximumReadLength: Int = FinderSessionRPC.defaultMaximumReadLength
    ) {
        precondition(maximumReadLength > 0)
        self.backend = .v1(session)
        self.maximumReadLength = maximumReadLength
    }

    /// v2 initializer for the logical bounded-read Finder session. This does not
    /// itself enable v2 mounting; the app-side mount coordinator must deliberately
    /// choose this backend in a later integration stage.
    public init(
        session: V2FinderReadOnlySession,
        maximumReadLength: Int = FinderSessionRPC.defaultMaximumReadLength
    ) {
        precondition(maximumReadLength > 0)
        self.backend = .v2(session)
        self.maximumReadLength = maximumReadLength
    }

    deinit {
        invalidate()
    }

    public func listRoot() throws -> [RemoteFile] {
        try ensureActive()
        let files = try backend.listRoot()
        try ensureActive()
        return files
    }

    public func open(entryID: UUID) throws -> RemoteHandle {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else { throw FinderSessionRPCError.invalidated }

        let local = try backend.open(entryID: entryID)
        let remote = RemoteHandle(id: UUID(), entryID: entryID)
        localHandles[remote.id] = local
        return remote
    }

    public func read(handle: RemoteHandle, offset: UInt64, length: Int) throws -> Data {
        guard length >= 0 else { throw FinderSessionRPCError.invalidReadLength }
        guard length <= maximumReadLength else { throw FinderSessionRPCError.readTooLarge }

        lock.lock()
        guard !invalidated else {
            lock.unlock()
            throw FinderSessionRPCError.invalidated
        }
        guard let local = localHandles[handle.id], local.entryID == handle.entryID else {
            lock.unlock()
            throw FinderSessionRPCError.unknownHandle
        }
        lock.unlock()

        let data = try backend.read(handle: local, offset: offset, length: length)
        try ensureActive()
        return data
    }

    public func close(_ handle: RemoteHandle) {
        lock.lock()
        guard let local = localHandles.removeValue(forKey: handle.id),
              local.entryID == handle.entryID else {
            lock.unlock()
            return
        }
        lock.unlock()
        backend.close(local)
    }

    /// Fail-closed. New calls are rejected before the selected backend is
    /// invalidated. v1 removes its plaintext leases; v2 clears logical handles
    /// and has no whole-file plaintext leases to remove.
    public func invalidate() {
        lock.lock()
        if invalidated {
            lock.unlock()
            return
        }
        invalidated = true
        localHandles.removeAll()
        lock.unlock()
        backend.invalidate()
    }

    private func ensureActive() throws {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else { throw FinderSessionRPCError.invalidated }
    }
}
