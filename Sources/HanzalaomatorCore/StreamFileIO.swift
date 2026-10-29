import Foundation

public enum StreamFileIOError: Error {
    case cannotOpenInput
    case cannotCreateOutput
    case unexpectedEOF
    case frameTooLarge
}

/// Bounded-memory framing I/O for encrypted objects.
/// Crypto is deliberately kept separate so malformed lengths are rejected
/// before buffers are allocated or passed to libsodium.
public enum StreamFileIO {
    public static let maximumCiphertextFrameSize = StreamFormat.defaultPlaintextChunkSize + 4096

    public static func readExactly(_ count: Int, from handle: FileHandle) throws -> Data {
        guard count >= 0 else { throw StreamFileIOError.unexpectedEOF }
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            let remaining = count - result.count
            guard let part = try handle.read(upToCount: remaining), !part.isEmpty else {
                throw StreamFileIOError.unexpectedEOF
            }
            result.append(part)
        }
        return result
    }

    public static func writeFrame(_ ciphertext: Data, to handle: FileHandle) throws {
        guard ciphertext.count <= maximumCiphertextFrameSize else {
            throw StreamFileIOError.frameTooLarge
        }
        try handle.write(contentsOf: StreamFormat.encodeUInt32(UInt32(ciphertext.count)))
        try handle.write(contentsOf: ciphertext)
    }

    public static func readFrame(from handle: FileHandle) throws -> Data {
        let lengthData = try readExactly(4, from: handle)
        guard let length = StreamFormat.decodeUInt32(lengthData) else {
            throw StreamCryptoError.malformedFrame
        }
        guard length > 0, length <= UInt32(maximumCiphertextFrameSize) else {
            throw StreamFileIOError.frameTooLarge
        }
        return try readExactly(Int(length), from: handle)
    }
}
