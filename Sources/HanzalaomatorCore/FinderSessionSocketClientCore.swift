import Foundation

/// Transport-independent client core for the FSKit side of the App Group socket.
/// The concrete UNIX-socket connector supplies one framed request/response
/// exchange. This type owns no vault key and validates every response.
public final class FinderSessionSocketClientCore {
    public typealias Exchange = @Sendable (Data) async throws -> Data

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

    private let sessionID: UUID
    private let exchange: Exchange
    private let lock = NSLock()
    private var invalidated = false

    public init(sessionID: UUID, exchange: @escaping Exchange) {
        self.sessionID = sessionID
        self.exchange = exchange
    }

    public func listRoot() async throws -> [FileInfo] {
        let response = try await send(.init(sessionID: sessionID, operation: .listRoot))
        return (response.files ?? []).map {
            FileInfo(id: $0.id, name: $0.name, byteCount: $0.byteCount, createdAt: $0.createdAt)
        }
    }

    public func open(entryID: UUID) async throws -> Handle {
        let response = try await send(.init(sessionID: sessionID, operation: .open, entryID: entryID))
        guard let handle = response.handle, handle.entryID == entryID else {
            throw ClientError.malformedResponse
        }
        return Handle(id: handle.id, entryID: handle.entryID)
    }

    public func read(handle: Handle, offset: UInt64, length: Int) async throws -> Data {
        guard length >= 0, length <= FinderSessionRPC.defaultMaximumReadLength else {
            throw ClientError.invalidReadLength
        }
        let response = try await send(.init(
            sessionID: sessionID,
            operation: .read,
            entryID: handle.entryID,
            handleID: handle.id,
            offset: offset,
            length: length
        ))
        guard let data = response.data else { throw ClientError.malformedResponse }
        return data
    }

    public func close(_ handle: Handle) async throws {
        _ = try await send(.init(
            sessionID: sessionID,
            operation: .close,
            entryID: handle.entryID,
            handleID: handle.id
        ))
    }

    public func invalidate() async {
        guard markInvalidatedIfNeeded() else { return }
        let request = FinderSessionSocketWire.Request(sessionID: sessionID, operation: .invalidate)
        guard let frame = try? FinderSessionSocketWire.encodeFrame(request) else { return }
        _ = try? await exchange(frame)
    }

    private func send(_ request: FinderSessionSocketWire.Request) async throws -> FinderSessionSocketWire.Response {
        guard isActive else { throw ClientError.invalidated }
        let frame = try FinderSessionSocketWire.encodeFrame(request)
        let replyFrame = try await exchange(frame)
        let response = try FinderSessionSocketWire.decodeFrame(
            FinderSessionSocketWire.Response.self,
            from: replyFrame
        )
        try FinderSessionSocketWire.validateVersion(response)
        guard response.requestID == request.requestID else { throw ClientError.requestMismatch }
        if let errorCode = response.errorCode { throw ClientError.remote(errorCode) }
        return response
    }

    private var isActive: Bool {
        lock.lock()
        let active = !invalidated
        lock.unlock()
        return active
    }

    private func markInvalidatedIfNeeded() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else { return false }
        invalidated = true
        return true
    }

    public enum ClientError: Error, Equatable {
        case invalidated
        case invalidReadLength
        case malformedResponse
        case requestMismatch
        case remote(String)
    }
}
