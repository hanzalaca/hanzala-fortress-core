import Foundation

/// Keyless request dispatcher used behind the App Group UNIX socket server.
///
/// The socket layer is responsible for peer authentication and framing. This
/// dispatcher accepts only the narrow Finder operations and forwards them to the
/// already-unlocked FinderSessionRPC owned by the main app.
public final class FinderSessionSocketServerCore {
    private let sessionID: UUID
    private let rpc: FinderSessionRPC
    private let lock = NSLock()
    private var invalidated = false

    public init(sessionID: UUID = UUID(), rpc: FinderSessionRPC) {
        self.sessionID = sessionID
        self.rpc = rpc
    }

    public var id: UUID { sessionID }

    /// The underlying RPC surface is synchronous and internally synchronized,
    /// so keep dispatch synchronous too. This avoids blocking a socket thread
    /// on a Task/semaphore bridge and removes a mutable cross-task capture.
    public func handle(_ request: FinderSessionSocketWire.Request) -> FinderSessionSocketWire.Response {
        do {
            try FinderSessionSocketWire.validateVersion(request)
            guard request.sessionID == sessionID else {
                return errorResponse(request, code: "wrong_session")
            }
            guard isActive else {
                return errorResponse(request, code: "invalidated")
            }

            switch request.operation {
            case .listRoot:
                let files = try rpc.listRoot().map {
                    FinderSessionSocketWire.RemoteFile(
                        id: $0.id,
                        name: $0.name,
                        byteCount: $0.byteCount,
                        createdAt: $0.createdAt
                    )
                }
                return .init(requestID: request.requestID, files: files)

            case .open:
                guard let entryID = request.entryID else {
                    return errorResponse(request, code: "missing_entry")
                }
                let handle = try rpc.open(entryID: entryID)
                return .init(
                    requestID: request.requestID,
                    handle: .init(id: handle.id, entryID: handle.entryID)
                )

            case .read:
                guard let entryID = request.entryID,
                      let handleID = request.handleID,
                      let offset = request.offset,
                      let length = request.length else {
                    return errorResponse(request, code: "missing_read_fields")
                }
                guard length >= 0, length <= FinderSessionRPC.defaultMaximumReadLength else {
                    return errorResponse(request, code: "invalid_read_length")
                }
                let handle = FinderSessionRPC.RemoteHandle(id: handleID, entryID: entryID)
                let data = try rpc.read(handle: handle, offset: offset, length: length)
                return .init(requestID: request.requestID, data: data)

            case .close:
                guard let entryID = request.entryID, let handleID = request.handleID else {
                    return errorResponse(request, code: "missing_handle")
                }
                rpc.close(.init(id: handleID, entryID: entryID))
                return .init(requestID: request.requestID)

            case .invalidate:
                invalidate()
                return .init(requestID: request.requestID)
            }
        } catch {
            return errorResponse(request, code: "request_failed")
        }
    }

    public func invalidate() {
        lock.lock()
        guard !invalidated else {
            lock.unlock()
            return
        }
        invalidated = true
        lock.unlock()
        rpc.invalidate()
    }

    private var isActive: Bool {
        lock.lock()
        let active = !invalidated
        lock.unlock()
        return active
    }

    private func errorResponse(
        _ request: FinderSessionSocketWire.Request,
        code: String
    ) -> FinderSessionSocketWire.Response {
        .init(requestID: request.requestID, errorCode: code)
    }

    deinit {
        invalidate()
    }
}
