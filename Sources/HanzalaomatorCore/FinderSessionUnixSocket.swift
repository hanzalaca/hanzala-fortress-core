import Foundation
import Darwin

public enum FinderSessionUnixSocketError: Error, Equatable, LocalizedError {
    case invalidPath
    case pathTooLong
    case createFailed(Int32)
    case bindFailed(Int32)
    case listenFailed(Int32)
    case connectFailed(Int32)
    case acceptFailed(Int32)
    case readFailed(Int32)
    case writeFailed(Int32)
    case peerClosed
    case invalidFrame

    public var errorDescription: String? {
        switch self {
        case .invalidPath:
            return "Finder session socket path is invalid."
        case .pathTooLong:
            return "Finder session socket path is too long for macOS AF_UNIX."
        case .createFailed(let code):
            return "Could not create Finder session socket (errno \(code): \(Self.errnoText(code)))."
        case .bindFailed(let code):
            return "Could not bind Finder session socket (errno \(code): \(Self.errnoText(code)))."
        case .listenFailed(let code):
            return "Could not listen on Finder session socket (errno \(code): \(Self.errnoText(code)))."
        case .connectFailed(let code):
            return "Could not connect to Finder session socket (errno \(code): \(Self.errnoText(code)))."
        case .acceptFailed(let code):
            return "Could not accept Finder session socket connection (errno \(code): \(Self.errnoText(code)))."
        case .readFailed(let code):
            return "Could not read from Finder session socket (errno \(code): \(Self.errnoText(code)))."
        case .writeFailed(let code):
            return "Could not write to Finder session socket (errno \(code): \(Self.errnoText(code)))."
        case .peerClosed:
            return "Finder session socket closed before the response completed."
        case .invalidFrame:
            return "Finder session socket received an invalid frame."
        }
    }

    private static func errnoText(_ code: Int32) -> String {
        String(cString: strerror(code))
    }
}

/// Concrete, local-only AF_UNIX transport used by the Finder/FSKit bridge.
///
/// The socket path is expected to live inside the shared App Group container.
/// This type intentionally does not know passwords, vault keys, `.hzo` paths,
/// or plaintext export paths. It transports only the bounded wire protocol.
public enum FinderSessionUnixSocket {
    public static let socketFileName = "x"

    /// macOS AF_UNIX paths are short (sockaddr_un.sun_path). App Group container
    /// paths are already fairly long, so keep our suffix intentionally compact.
    /// Each session still gets its own directory so Listener.stop() can remove
    /// only that session and never the shared App Group root.
    public static func makeSessionSocketURL(containerURL: URL, sessionID: UUID) throws -> URL {
        guard containerURL.isFileURL else { throw FinderSessionUnixSocketError.invalidPath }
        let token = sessionID.uuidString.replacingOccurrences(of: "-", with: "").prefix(16)
        let directory = containerURL
            .appendingPathComponent("s", isDirectory: true)
            .appendingPathComponent(String(token), isDirectory: true)
        let socketURL = directory.appendingPathComponent(socketFileName, isDirectory: false)
        try validateSocketPath(socketURL.path)
        return socketURL
    }

    public final class Listener: @unchecked Sendable {
        public let socketURL: URL
        private let fileDescriptor: Int32
        private let queue: DispatchQueue
        private let authorizePeer: @Sendable (Int32) -> Bool
        private let handler: @Sendable (Data) -> Data
        private let stateLock = NSLock()
        private var stopped = false

        public init(
            socketURL: URL,
            queue: DispatchQueue = DispatchQueue(label: "ca.hanzala.hanzalaomator.finder-socket"),
            authorizePeer: @escaping @Sendable (Int32) -> Bool = { _ in true },
            handler: @escaping @Sendable (Data) -> Data
        ) throws {
            self.socketURL = socketURL
            self.queue = queue
            self.authorizePeer = authorizePeer
            self.handler = handler

            try Self.validateURL(socketURL)
            try FileManager.default.createDirectory(
                at: socketURL.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
            try? FileManager.default.removeItem(at: socketURL)

            let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { throw FinderSessionUnixSocketError.createFailed(errno) }

            do {
                try Self.bind(fd: fd, to: socketURL.path)
                guard Darwin.listen(fd, 8) == 0 else {
                    throw FinderSessionUnixSocketError.listenFailed(errno)
                }
                try? FileManager.default.setAttributes(
                    [.posixPermissions: NSNumber(value: 0o600)],
                    ofItemAtPath: socketURL.path
                )
            } catch {
                Darwin.close(fd)
                throw error
            }

            fileDescriptor = fd
            queue.async { [weak self] in self?.acceptLoop() }
        }

        deinit {
            stop()
        }

        public func stop() {
            stateLock.lock()
            if stopped {
                stateLock.unlock()
                return
            }
            stopped = true
            stateLock.unlock()

            Darwin.shutdown(fileDescriptor, SHUT_RDWR)
            Darwin.close(fileDescriptor)
            try? FileManager.default.removeItem(at: socketURL)
            try? FileManager.default.removeItem(at: socketURL.deletingLastPathComponent())
        }

        private func acceptLoop() {
            while true {
                stateLock.lock()
                let shouldStop = stopped
                stateLock.unlock()
                if shouldStop { return }

                let client = Darwin.accept(fileDescriptor, nil, nil)
                if client < 0 {
                    if errno == EINTR { continue }
                    stateLock.lock()
                    let nowStopped = stopped
                    stateLock.unlock()
                    if nowStopped { return }
                    continue
                }

                autoreleasepool {
                    defer { Darwin.close(client) }

                    // The App Group path is only rendezvous. It is not identity.
                    // Authenticate the connected process before reading even one
                    // protocol byte so an unrelated local process cannot request
                    // decrypted data merely by learning the socket path.
                    guard authorizePeer(client) else {
                        Darwin.shutdown(client, SHUT_RDWR)
                        return
                    }

                    guard let requestFrame = try? FinderSessionUnixSocket.readSingleFrame(fd: client) else { return }
                    let responseFrame = handler(requestFrame)
                    try? FinderSessionUnixSocket.writeAll(fd: client, data: responseFrame)
                }
            }
        }

        private static func validateURL(_ socketURL: URL) throws {
            guard socketURL.isFileURL else { throw FinderSessionUnixSocketError.invalidPath }
            try FinderSessionUnixSocket.validateSocketPath(socketURL.path)
        }

        private static func bind(fd: Int32, to path: String) throws {
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)

            let utf8 = Array(path.utf8) + [0]
            let capacity = MemoryLayout.size(ofValue: address.sun_path)
            guard utf8.count <= capacity else { throw FinderSessionUnixSocketError.pathTooLong }

            withUnsafeMutableBytes(of: &address.sun_path) { raw in
                raw.initializeMemory(as: UInt8.self, repeating: 0)
                raw.copyBytes(from: utf8)
            }

            let length = socklen_t(MemoryLayout<sa_family_t>.size + utf8.count)
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, length)
                }
            }
            guard result == 0 else { throw FinderSessionUnixSocketError.bindFailed(errno) }
        }
    }

    public static func roundTrip(socketURL: URL, requestFrame: Data) throws -> Data {
        guard socketURL.isFileURL else { throw FinderSessionUnixSocketError.invalidPath }
        try validateSocketPath(socketURL.path)

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw FinderSessionUnixSocketError.createFailed(errno) }
        defer { Darwin.close(fd) }

        try connect(fd: fd, to: socketURL.path)
        try writeAll(fd: fd, data: requestFrame)
        Darwin.shutdown(fd, SHUT_WR)
        return try readSingleFrame(fd: fd)
    }

    private static func validateSocketPath(_ path: String) throws {
        let capacity = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        guard !path.isEmpty else { throw FinderSessionUnixSocketError.invalidPath }
        guard path.utf8.count + 1 <= capacity else { throw FinderSessionUnixSocketError.pathTooLong }
    }

    private static func connect(fd: Int32, to path: String) throws {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)

        let utf8 = Array(path.utf8) + [0]
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard utf8.count <= capacity else { throw FinderSessionUnixSocketError.pathTooLong }

        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
            raw.copyBytes(from: utf8)
        }

        let length = socklen_t(MemoryLayout<sa_family_t>.size + utf8.count)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, length)
            }
        }
        guard result == 0 else { throw FinderSessionUnixSocketError.connectFailed(errno) }
    }

    fileprivate static func readSingleFrame(fd: Int32) throws -> Data {
        let headerSize = MemoryLayout<UInt32>.size
        let header = try readExactly(fd: fd, count: headerSize)
        let payloadLength: UInt32 = header.withUnsafeBytes { raw in
            raw.loadUnaligned(as: UInt32.self).bigEndian
        }
        guard payloadLength <= UInt32(FinderSessionSocketWire.maximumPayloadLength) else {
            throw FinderSessionUnixSocketError.invalidFrame
        }
        let payload = try readExactly(fd: fd, count: Int(payloadLength))
        var frame = header
        frame.append(payload)
        return frame
    }

    private static func readExactly(fd: Int32, count: Int) throws -> Data {
        if count == 0 { return Data() }
        var result = Data(count: count)
        var offset = 0
        try result.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { throw FinderSessionUnixSocketError.readFailed(EFAULT) }
            while offset < count {
                let amount = Darwin.read(fd, base.advanced(by: offset), count - offset)
                if amount == 0 { throw FinderSessionUnixSocketError.peerClosed }
                if amount < 0 {
                    if errno == EINTR { continue }
                    throw FinderSessionUnixSocketError.readFailed(errno)
                }
                offset += amount
            }
        }
        return result
    }

    fileprivate static func writeAll(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let amount = Darwin.send(fd, base.advanced(by: offset), raw.count - offset, MSG_NOSIGNAL)
                if amount < 0 {
                    if errno == EINTR { continue }
                    throw FinderSessionUnixSocketError.writeFailed(errno)
                }
                offset += amount
            }
        }
    }
}
