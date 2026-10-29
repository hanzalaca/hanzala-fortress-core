import Foundation

/// Versioned, bounded wire messages for the portable App Group UNIX-socket bridge.
///
/// This is transport framing only. It never carries passwords, encryption keys,
/// plaintext filesystem paths, or encrypted object paths.
public enum FinderSessionSocketWire {
    public static let version: UInt16 = 1
    public static let maximumPayloadLength = 5 * 1024 * 1024

    public enum Operation: String, Codable, Sendable {
        case listRoot
        case open
        case read
        case close
        case invalidate
    }

    public struct Request: Codable, Sendable, Equatable {
        public let version: UInt16
        public let requestID: UUID
        public let sessionID: UUID
        public let operation: Operation
        public let entryID: UUID?
        public let handleID: UUID?
        public let offset: UInt64?
        public let length: Int?

        public init(
            requestID: UUID = UUID(),
            sessionID: UUID,
            operation: Operation,
            entryID: UUID? = nil,
            handleID: UUID? = nil,
            offset: UInt64? = nil,
            length: Int? = nil
        ) {
            self.version = FinderSessionSocketWire.version
            self.requestID = requestID
            self.sessionID = sessionID
            self.operation = operation
            self.entryID = entryID
            self.handleID = handleID
            self.offset = offset
            self.length = length
        }
    }

    public struct RemoteFile: Codable, Sendable, Equatable, Identifiable {
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

    public struct RemoteHandle: Codable, Sendable, Equatable, Hashable, Identifiable {
        public let id: UUID
        public let entryID: UUID

        public init(id: UUID, entryID: UUID) {
            self.id = id
            self.entryID = entryID
        }
    }

    public struct Response: Codable, Sendable, Equatable {
        public let version: UInt16
        public let requestID: UUID
        public let files: [RemoteFile]?
        public let handle: RemoteHandle?
        public let data: Data?
        public let errorCode: String?

        public init(
            requestID: UUID,
            files: [RemoteFile]? = nil,
            handle: RemoteHandle? = nil,
            data: Data? = nil,
            errorCode: String? = nil
        ) {
            self.version = FinderSessionSocketWire.version
            self.requestID = requestID
            self.files = files
            self.handle = handle
            self.data = data
            self.errorCode = errorCode
        }
    }

    public enum WireError: Error, Equatable {
        case payloadTooLarge
        case truncatedFrame
        case unsupportedVersion
        case trailingBytes
        case malformedPayload
    }

    public static func encodeFrame<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        let payload = try encoder.encode(value)
        guard payload.count <= maximumPayloadLength else {
            throw WireError.payloadTooLarge
        }

        var length = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        frame.append(payload)
        return frame
    }

    public static func decodeFrame<T: Decodable>(
        _ type: T.Type,
        from frame: Data
    ) throws -> T {
        let headerSize = MemoryLayout<UInt32>.size
        guard frame.count >= headerSize else {
            throw WireError.truncatedFrame
        }

        let payloadLength: UInt32 = frame.prefix(headerSize).withUnsafeBytes { rawBuffer in
            rawBuffer.loadUnaligned(as: UInt32.self).bigEndian
        }
        guard payloadLength <= UInt32(maximumPayloadLength) else {
            throw WireError.payloadTooLarge
        }

        let expectedCount = headerSize + Int(payloadLength)
        guard frame.count >= expectedCount else {
            throw WireError.truncatedFrame
        }
        guard frame.count == expectedCount else {
            throw WireError.trailingBytes
        }

        let payload = frame.dropFirst(headerSize)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        do {
            return try decoder.decode(type, from: payload)
        } catch {
            throw WireError.malformedPayload
        }
    }

    public static func validateVersion(_ request: Request) throws {
        guard request.version == version else {
            throw WireError.unsupportedVersion
        }
    }

    public static func validateVersion(_ response: Response) throws {
        guard response.version == version else {
            throw WireError.unsupportedVersion
        }
    }
}
