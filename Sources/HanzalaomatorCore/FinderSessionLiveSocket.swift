import Foundation

/// End-to-end live AF_UNIX bridge for one already-unlocked Finder session.
///
/// The main app owns this server and therefore retains all vault keys. The
/// socket transports only the bounded FinderSessionSocketWire protocol.
public final class FinderSessionLiveSocketServer: @unchecked Sendable {
    public let sessionID: UUID
    public let socketURL: URL

    private let core: FinderSessionSocketServerCore
    private let listener: FinderSessionUnixSocket.Listener

    public init(
        containerURL: URL,
        rpc: FinderSessionRPC,
        sessionID: UUID = UUID(),
        authorizePeer: @escaping @Sendable (Int32) -> Bool = { _ in true }
    ) throws {
        self.sessionID = sessionID
        self.core = FinderSessionSocketServerCore(sessionID: sessionID, rpc: rpc)
        self.socketURL = try FinderSessionUnixSocket.makeSessionSocketURL(
            containerURL: containerURL,
            sessionID: sessionID
        )

        let core = self.core
        self.listener = try FinderSessionUnixSocket.Listener(
            socketURL: socketURL,
            authorizePeer: authorizePeer
        ) { frame in
            do {
                let request = try FinderSessionSocketWire.decodeFrame(
                    FinderSessionSocketWire.Request.self,
                    from: frame
                )
                let response = core.handle(request)
                return (try? FinderSessionSocketWire.encodeFrame(response)) ?? Data()
            } catch {
                return Data()
            }
        }
    }

    public func stop() {
        core.invalidate()
        listener.stop()
    }

    deinit {
        stop()
    }
}

/// Keyless client used by the Finder/FSKit side. It owns only a session id and
/// a socket URL; passwords, master keys, object keys and vault paths never cross
/// this boundary.
public final class FinderSessionLiveSocketClient: @unchecked Sendable {
    private let core: FinderSessionSocketClientCore

    public init(sessionID: UUID, socketURL: URL) {
        core = FinderSessionSocketClientCore(sessionID: sessionID) { frame in
            try FinderSessionUnixSocket.roundTrip(socketURL: socketURL, requestFrame: frame)
        }
    }

    public func listRoot() async throws -> [FinderSessionSocketClientCore.FileInfo] {
        try await core.listRoot()
    }

    public func open(entryID: UUID) async throws -> FinderSessionSocketClientCore.Handle {
        try await core.open(entryID: entryID)
    }

    public func read(
        handle: FinderSessionSocketClientCore.Handle,
        offset: UInt64,
        length: Int
    ) async throws -> Data {
        try await core.read(handle: handle, offset: offset, length: length)
    }

    public func close(_ handle: FinderSessionSocketClientCore.Handle) async throws {
        try await core.close(handle)
    }

    public func invalidate() async {
        await core.invalidate()
    }
}
