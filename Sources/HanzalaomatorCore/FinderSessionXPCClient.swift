import Foundation

// NSXPCConnection/NSXPCListener exist only on macOS; the Finder bridge is macOS-only.
#if os(macOS)

public enum FinderSessionXPCClientError: Error, Equatable {
    case connectionUnavailable
    case invalidRemoteFile
    case invalidRemoteHandle
    case remoteError(String)
}

/// Keyless client used by the FSKit side to call the already-unlocked main app.
///
/// The client receives an in-memory `NSXPCListenerEndpoint` and never a password,
/// master key, derived key, plaintext path, or encrypted-object path.
///
/// Important: `NSXPCListenerEndpoint` is an XPC object and must be transferred by
/// XPC itself. It cannot be persisted with `NSKeyedArchiver` or written into an
/// app-group file. The eventual handoff layer must therefore pass the endpoint
/// across an actual XPC/App Extension boundary, not serialize it to disk.
///
/// Production callers must provide a code-signing requirement that identifies
/// the containing Hanzalaomator app before the connection is activated.
public final class FinderSessionXPCClient {
    public struct FileInfo: Sendable, Equatable, Identifiable {
        public let id: UUID
        public let name: String
        public let byteCount: UInt64
        public let createdAt: Date
    }

    public struct Handle: Sendable, Equatable, Hashable, Identifiable {
        public let id: UUID
        public let entryID: UUID

        public init(id: UUID, entryID: UUID) {
            self.id = id
            self.entryID = entryID
        }
    }

    private let connection: NSXPCConnection
    private let lock = NSLock()
    private var invalidated = false

    public init(endpoint: NSXPCListenerEndpoint, serverCodeSigningRequirement: String) {
        precondition(!serverCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

        let connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: FinderSessionXPCProtocol.self)
        connection.setCodeSigningRequirement(serverCodeSigningRequirement)
        self.connection = connection

        connection.invalidationHandler = { [weak self] in
            self?.markInvalidated()
        }
        connection.interruptionHandler = { [weak self] in
            self?.markInvalidated()
        }
        connection.activate()
    }

    deinit {
        connection.invalidate()
    }

    public func listRoot() async throws -> [FileInfo] {
        let proxy = try remoteProxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.listRoot { files, error in
                if let error {
                    continuation.resume(throwing: FinderSessionXPCClientError.remoteError(error.localizedDescription))
                    return
                }
                guard let files else {
                    continuation.resume(throwing: FinderSessionXPCClientError.connectionUnavailable)
                    return
                }
                do {
                    let converted = try files.map { file -> FileInfo in
                        guard let id = UUID(uuidString: file.id) else {
                            throw FinderSessionXPCClientError.invalidRemoteFile
                        }
                        return FileInfo(id: id, name: file.name, byteCount: file.byteCount, createdAt: file.createdAt)
                    }
                    continuation.resume(returning: converted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func open(entryID: UUID) async throws -> Handle {
        let proxy = try remoteProxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.open(entryID: entryID.uuidString) { handle, error in
                if let error {
                    continuation.resume(throwing: FinderSessionXPCClientError.remoteError(error.localizedDescription))
                    return
                }
                guard let handle,
                      let id = UUID(uuidString: handle.id),
                      let remoteEntryID = UUID(uuidString: handle.entryID),
                      remoteEntryID == entryID else {
                    continuation.resume(throwing: FinderSessionXPCClientError.invalidRemoteHandle)
                    return
                }
                continuation.resume(returning: Handle(id: id, entryID: remoteEntryID))
            }
        }
    }

    public func read(handle: Handle, offset: UInt64, length: Int) async throws -> Data {
        let proxy = try remoteProxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.read(
                handleID: handle.id.uuidString,
                entryID: handle.entryID.uuidString,
                offset: offset,
                length: length
            ) { data, error in
                if let error {
                    continuation.resume(throwing: FinderSessionXPCClientError.remoteError(error.localizedDescription))
                    return
                }
                guard let data else {
                    continuation.resume(throwing: FinderSessionXPCClientError.connectionUnavailable)
                    return
                }
                continuation.resume(returning: data)
            }
        }
    }

    public func close(_ handle: Handle) async {
        guard let proxy = try? remoteProxy() else { return }
        await withCheckedContinuation { continuation in
            proxy.close(handleID: handle.id.uuidString, entryID: handle.entryID.uuidString) {
                continuation.resume()
            }
        }
    }

    public func invalidate() async {
        if isInvalidatedSnapshot() {
            connection.invalidate()
            return
        }

        if let proxy = try? remoteProxy() {
            await withCheckedContinuation { continuation in
                proxy.invalidate {
                    continuation.resume()
                }
            }
        }
        markInvalidated()
        connection.invalidate()
    }

    private func remoteProxy() throws -> FinderSessionXPCProtocol {
        guard !isInvalidatedSnapshot() else {
            throw FinderSessionXPCClientError.connectionUnavailable
        }

        var proxyError: Error?
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            proxyError = error
        }) as? FinderSessionXPCProtocol else {
            if let proxyError {
                throw FinderSessionXPCClientError.remoteError(proxyError.localizedDescription)
            }
            throw FinderSessionXPCClientError.connectionUnavailable
        }
        return proxy
    }

    /// Synchronous helper keeps `NSLock` calls out of async function bodies so
    /// this remains valid when the package moves fully to Swift 6 language mode.
    private func isInvalidatedSnapshot() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return invalidated
    }

    private func markInvalidated() {
        lock.lock()
        invalidated = true
        lock.unlock()
    }
}

#endif
