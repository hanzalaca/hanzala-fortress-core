import Foundation

/// Keyless rendezvous metadata shared between the unlocked main app and FSKit.
/// The descriptor contains no password, vault key, object key, encrypted-object
/// path, or plaintext path.
public struct FinderSessionDescriptor: Codable, Sendable, Equatable {
    public static let currentVersion = 1

    public let version: Int
    public let sessionID: UUID
    public let socketPath: String
    public let createdAt: Date

    public init(
        version: Int = FinderSessionDescriptor.currentVersion,
        sessionID: UUID,
        socketPath: String,
        createdAt: Date = Date()
    ) {
        self.version = version
        self.sessionID = sessionID
        self.socketPath = socketPath
        self.createdAt = createdAt
    }
}

public enum FinderSessionDiscoveryError: Error, Equatable {
    case invalidContainer
    case invalidVersion
    case invalidSocketPath
    case descriptorMissing
}

/// Persists only keyless Finder-session rendezvous metadata in the App Group
/// container. The absolute socket path is accepted only when it resolves inside
/// that same container, preventing a forged descriptor from redirecting FSKit
/// to an arbitrary local socket.
public enum FinderSessionDiscovery {
    public static let directoryName = "FinderDiscovery"
    public static let descriptorFileName = "session.json"

    public static func descriptorURL(containerURL: URL) throws -> URL {
        guard containerURL.isFileURL else { throw FinderSessionDiscoveryError.invalidContainer }
        return containerURL
            .appendingPathComponent(directoryName, isDirectory: true)
            .appendingPathComponent(descriptorFileName, isDirectory: false)
    }

    @discardableResult
    public static func publish(
        containerURL: URL,
        sessionID: UUID,
        socketURL: URL,
        createdAt: Date = Date()
    ) throws -> FinderSessionDescriptor {
        guard containerURL.isFileURL else { throw FinderSessionDiscoveryError.invalidContainer }
        let container = containerURL.standardizedFileURL
        let socket = socketURL.standardizedFileURL
        guard socket.isFileURL, isDescendant(socket, of: container) else {
            throw FinderSessionDiscoveryError.invalidSocketPath
        }

        let descriptor = FinderSessionDescriptor(
            sessionID: sessionID,
            socketPath: socket.path,
            createdAt: createdAt
        )
        let url = try descriptorURL(containerURL: container)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )

        let data = try JSONEncoder().encode(descriptor)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o600)],
            ofItemAtPath: url.path
        )
        return descriptor
    }

    public static func load(containerURL: URL) throws -> FinderSessionDescriptor {
        let container = containerURL.standardizedFileURL
        let url = try descriptorURL(containerURL: container)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw FinderSessionDiscoveryError.descriptorMissing
        }

        let descriptor = try JSONDecoder().decode(
            FinderSessionDescriptor.self,
            from: Data(contentsOf: url)
        )
        guard descriptor.version == FinderSessionDescriptor.currentVersion else {
            throw FinderSessionDiscoveryError.invalidVersion
        }

        let socketURL = URL(fileURLWithPath: descriptor.socketPath).standardizedFileURL
        guard isDescendant(socketURL, of: container) else {
            throw FinderSessionDiscoveryError.invalidSocketPath
        }
        return descriptor
    }

    public static func clear(containerURL: URL) {
        guard let url = try? descriptorURL(containerURL: containerURL) else { return }
        try? FileManager.default.removeItem(at: url)
        let directory = url.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: directory)
    }

    private static func isDescendant(_ child: URL, of parent: URL) -> Bool {
        let parentPath = parent.path.hasSuffix("/") ? parent.path : parent.path + "/"
        return child.path.hasPrefix(parentPath)
    }
}

/// Main-app owner for one published, already-unlocked Finder session. Starting
/// publishes only rendezvous metadata; stopping invalidates the RPC, closes the
/// socket, releases leases through the session, and removes discovery metadata.
public final class FinderSessionPublishedServer: @unchecked Sendable {
    public let sessionID: UUID
    public let socketURL: URL

    private let containerURL: URL
    private let server: FinderSessionLiveSocketServer
    private let lock = NSLock()
    private var stopped = false

    public init(
        containerURL: URL,
        rpc: FinderSessionRPC,
        authorizePeer: @escaping @Sendable (Int32) -> Bool = { _ in true }
    ) throws {
        self.containerURL = containerURL.standardizedFileURL
        let liveServer = try FinderSessionLiveSocketServer(
            containerURL: containerURL,
            rpc: rpc,
            authorizePeer: authorizePeer
        )
        self.server = liveServer
        self.sessionID = liveServer.sessionID
        self.socketURL = liveServer.socketURL

        do {
            try FinderSessionDiscovery.publish(
                containerURL: containerURL,
                sessionID: liveServer.sessionID,
                socketURL: liveServer.socketURL
            )
        } catch {
            liveServer.stop()
            throw error
        }
    }

    public func stop() {
        lock.lock()
        guard !stopped else {
            lock.unlock()
            return
        }
        stopped = true
        lock.unlock()

        FinderSessionDiscovery.clear(containerURL: containerURL)
        server.stop()
    }

    deinit {
        stop()
    }
}
