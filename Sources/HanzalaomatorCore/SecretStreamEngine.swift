import Foundation
import Sodium

public final class SecretStreamEngine {
    private let sodium = Sodium()

    public init() {}

    public func generateKey() throws -> Data {
        let key = sodium.secretStream.xchacha20poly1305.key()
        return Data(key)
    }

    public func encryptFile(at inputURL: URL, to outputURL: URL, key: Data, chunkSize: Int = StreamFormat.defaultPlaintextChunkSize) throws {
        guard chunkSize > 0 else { throw StreamCryptoError.malformedFrame }
        let secretKey = [UInt8](key)
        guard let stream = sodium.secretStream.xchacha20poly1305.initPush(secretKey: secretKey) else {
            throw StreamCryptoError.invalidKeyLength
        }

        let fm = FileManager.default
        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }

        let directory = outputURL.deletingLastPathComponent()
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        let temporary = directory.appendingPathComponent(".hanzala-stream-\(UUID().uuidString).tmp")
        fm.createFile(atPath: temporary.path, contents: nil)
        defer { try? fm.removeItem(at: temporary) }

        let output = try FileHandle(forWritingTo: temporary)
        defer { try? output.close() }

        try output.write(contentsOf: StreamFormat.magic)
        try output.write(contentsOf: StreamFormat.encodeUInt32(StreamFormat.version))

        let header = Data(stream.header())
        try output.write(contentsOf: StreamFormat.encodeUInt32(UInt32(header.count)))
        try output.write(contentsOf: header)

        var current = try input.read(upToCount: chunkSize) ?? Data()
        if current.isEmpty {
            guard let encrypted = stream.push(message: [], tag: .FINAL) else {
                throw StreamCryptoError.authenticationFailed
            }
            try StreamFileIO.writeFrame(Data(encrypted), to: output)
        } else {
            while true {
                let next = try input.read(upToCount: chunkSize) ?? Data()
                let isFinal = next.isEmpty
                let encrypted: [UInt8]?
                if isFinal {
                    encrypted = stream.push(message: [UInt8](current), tag: .FINAL)
                } else {
                    encrypted = stream.push(message: [UInt8](current))
                }
                guard let encrypted else {
                    throw StreamCryptoError.authenticationFailed
                }
                try StreamFileIO.writeFrame(Data(encrypted), to: output)
                if isFinal { break }
                current = next
            }
        }

        try output.synchronize()
        try output.close()

        if fm.fileExists(atPath: outputURL.path) {
            _ = try fm.replaceItemAt(outputURL, withItemAt: temporary)
        } else {
            try fm.moveItem(at: temporary, to: outputURL)
        }
    }

    /// Authenticates and emits plaintext one secretstream frame at a time without
    /// first materializing the whole plaintext file on disk. Callers must treat
    /// emitted chunks as sensitive plaintext and must not persist them unless that
    /// is explicitly part of the requested operation.
    public func decryptFileChunks(
        at inputURL: URL,
        key: Data,
        consume: (Data) throws -> Void
    ) throws {
        let secretKey = [UInt8](key)
        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }

        let magic = try StreamFileIO.readExactly(StreamFormat.magic.count, from: input)
        guard magic == StreamFormat.magic else { throw StreamCryptoError.malformedHeader }

        let versionData = try StreamFileIO.readExactly(4, from: input)
        guard let version = StreamFormat.decodeUInt32(versionData) else { throw StreamCryptoError.malformedHeader }
        guard version == StreamFormat.version else { throw StreamCryptoError.unsupportedVersion }

        let headerLengthData = try StreamFileIO.readExactly(4, from: input)
        guard let headerLength = StreamFormat.decodeUInt32(headerLengthData), headerLength > 0, headerLength <= 4096 else {
            throw StreamCryptoError.malformedHeader
        }
        let header = try StreamFileIO.readExactly(Int(headerLength), from: input)

        guard let stream = sodium.secretStream.xchacha20poly1305.initPull(secretKey: secretKey, header: [UInt8](header)) else {
            throw StreamCryptoError.invalidKeyLength
        }

        var sawFinal = false
        while true {
            let lengthPrefix = try input.read(upToCount: 4)
            if lengthPrefix == nil || lengthPrefix!.isEmpty { break }
            guard lengthPrefix!.count == 4, let frameLength = StreamFormat.decodeUInt32(lengthPrefix!) else {
                throw StreamCryptoError.malformedFrame
            }
            guard frameLength > 0, frameLength <= UInt32(StreamFileIO.maximumCiphertextFrameSize) else {
                throw StreamFileIOError.frameTooLarge
            }

            let ciphertext = try StreamFileIO.readExactly(Int(frameLength), from: input)
            guard let result = stream.pull(cipherText: [UInt8](ciphertext)) else {
                throw StreamCryptoError.authenticationFailed
            }
            let (message, tag) = result

            if sawFinal { throw StreamCryptoError.trailingDataAfterFinalFrame }

            // Authentication for this frame has succeeded before any plaintext is
            // handed to the caller.
            try consume(Data(message))

            if tag == .FINAL {
                sawFinal = true
                let trailing = try input.read(upToCount: 1)
                if let trailing, !trailing.isEmpty {
                    throw StreamCryptoError.trailingDataAfterFinalFrame
                }
                break
            }
        }

        guard sawFinal else { throw StreamCryptoError.missingFinalFrame }
    }

    public func decryptFile(at inputURL: URL, to outputURL: URL, key: Data) throws {
        let fm = FileManager.default
        let directory = outputURL.deletingLastPathComponent()
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        let temporary = directory.appendingPathComponent(".hanzala-decrypt-\(UUID().uuidString).tmp")
        fm.createFile(atPath: temporary.path, contents: nil)
        defer { try? fm.removeItem(at: temporary) }

        let output = try FileHandle(forWritingTo: temporary)
        defer { try? output.close() }

        try decryptFileChunks(at: inputURL, key: key) { chunk in
            try output.write(contentsOf: chunk)
        }

        try output.synchronize()
        try output.close()
        if fm.fileExists(atPath: outputURL.path) {
            _ = try fm.replaceItemAt(outputURL, withItemAt: temporary)
        } else {
            try fm.moveItem(at: temporary, to: outputURL)
        }
    }
}
