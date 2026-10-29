import Foundation
import CryptoKit

public enum V2ChunkManifestValidationError: Error, Equatable, Sendable {
    case unsupportedVersion
    case insufficientChunkCount
    case tooManyChunks
    case invalidChunkObjectName
    case duplicateChunkObjectName
    case invalidChunkLength
    case nonCanonicalChunkLength
    case arithmeticOverflow
    case logicalLengthMismatch
    case chunkingNotRequired
    case invalidContentDigest
}

public struct V2ChunkReference: Codable, Equatable, Sendable {
    public let opaqueObjectName: String
    public let logicalByteCount: UInt64

    public init(opaqueObjectName: String, logicalByteCount: UInt64) {
        self.opaqueObjectName = opaqueObjectName
        self.logicalByteCount = logicalByteCount
    }
}

/// Private authenticated manifest for one multi-object v2 file.
///
/// This value is never written in plaintext. It is encoded and sealed inside a
/// generic name-bound `V2PoolObjectKind.manifest` object. Chunk names, ordering,
/// per-chunk lengths, total file length, file identity, and the whole-file digest
/// are therefore authenticated and hidden from the public pool namespace.
public struct V2ChunkManifest: Codable, Equatable, Sendable {
    public static let formatVersion: UInt32 = 1
    public static let maximumChunkCount = 16_384

    /// Every full chunk uses a 4 MiB authenticated plaintext target. The private
    /// v2 object header occupies ten bytes inside that target, leaving this many
    /// bytes for logical file content. The final chunk may be shorter but is
    /// padded to the same target by the object codec.
    public static let chunkPaddedPlaintextByteCount = 4 * 1024 * 1024
    public static let maximumLogicalChunkByteCount =
        chunkPaddedPlaintextByteCount - V2PoolObjectCodec.encryptedPayloadHeaderByteCount

    public let formatVersion: UInt32
    public let fileID: UUID
    public let logicalByteCount: UInt64
    public let chunks: [V2ChunkReference]
    public let sha256Digest: Data

    public init(
        formatVersion: UInt32 = Self.formatVersion,
        fileID: UUID = UUID(),
        logicalByteCount: UInt64,
        chunks: [V2ChunkReference],
        sha256Digest: Data
    ) {
        self.formatVersion = formatVersion
        self.fileID = fileID
        self.logicalByteCount = logicalByteCount
        self.chunks = chunks
        self.sha256Digest = sha256Digest
    }

    public func validate() throws {
        guard formatVersion == Self.formatVersion else {
            throw V2ChunkManifestValidationError.unsupportedVersion
        }
        guard chunks.count >= 2 else {
            throw V2ChunkManifestValidationError.insufficientChunkCount
        }
        guard chunks.count <= Self.maximumChunkCount else {
            throw V2ChunkManifestValidationError.tooManyChunks
        }
        guard sha256Digest.count == SHA256.Digest.byteCount else {
            throw V2ChunkManifestValidationError.invalidContentDigest
        }
        guard logicalByteCount > UInt64(V2DataObjectPaddingPolicy.maximumLogicalContentByteCount) else {
            throw V2ChunkManifestValidationError.chunkingNotRequired
        }

        var names = Set<String>()
        var total: UInt64 = 0

        for (index, chunk) in chunks.enumerated() {
            guard V2OpaqueObjectName.isValid(chunk.opaqueObjectName) else {
                throw V2ChunkManifestValidationError.invalidChunkObjectName
            }
            guard names.insert(chunk.opaqueObjectName).inserted else {
                throw V2ChunkManifestValidationError.duplicateChunkObjectName
            }
            guard chunk.logicalByteCount > 0,
                  chunk.logicalByteCount <= UInt64(Self.maximumLogicalChunkByteCount) else {
                throw V2ChunkManifestValidationError.invalidChunkLength
            }

            if index < chunks.count - 1,
               chunk.logicalByteCount != UInt64(Self.maximumLogicalChunkByteCount) {
                throw V2ChunkManifestValidationError.nonCanonicalChunkLength
            }

            let (next, overflow) = total.addingReportingOverflow(chunk.logicalByteCount)
            guard !overflow else {
                throw V2ChunkManifestValidationError.arithmeticOverflow
            }
            total = next
        }

        guard total == logicalByteCount else {
            throw V2ChunkManifestValidationError.logicalLengthMismatch
        }
    }
}

public enum V2ChunkManifestCodecError: Error, Equatable, Sendable {
    case unexpectedObjectKind
    case malformedManifest
}

/// Encodes/decodes the private chunk map inside the same generic authenticated
/// v2 pool envelope used by other roles. The manifest receives coarse encrypted
/// size padding so its public length does not directly expose the exact number of
/// chunks.
public final class V2ChunkManifestCodec {
    private let poolCodec: V2PoolObjectCodec
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(poolCodec: V2PoolObjectCodec = V2PoolObjectCodec()) {
        self.poolCodec = poolCodec
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    public func seal(
        _ manifest: V2ChunkManifest,
        masterKey: Data,
        objectName: String
    ) throws -> Data {
        let encoded = try encodeContent(manifest)
        let paddingTarget = try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
            forEncodedMetadataByteCount: encoded.count
        )
        return try poolCodec.seal(
            kind: .manifest,
            content: encoded,
            masterKey: masterKey,
            objectName: objectName,
            paddedPlaintextByteCount: paddingTarget
        )
    }

    public func open(
        _ envelope: Data,
        masterKey: Data,
        objectName: String
    ) throws -> V2ChunkManifest {
        let object = try poolCodec.open(
            envelope,
            masterKey: masterKey,
            objectName: objectName
        )
        guard object.kind == .manifest else {
            throw V2ChunkManifestCodecError.unexpectedObjectKind
        }
        return try decodeContent(object.content)
    }

    /// Internal representation used by the chunk ownership transaction after the
    /// manifest filename has already been authenticated as pending metadata. The
    /// returned bytes must still be stored as a generic `.manifest` pool object.
    func encodeContent(_ manifest: V2ChunkManifest) throws -> Data {
        try manifest.validate()
        do {
            return try encoder.encode(manifest)
        } catch {
            throw V2ChunkManifestCodecError.malformedManifest
        }
    }

    /// Decodes only already-authenticated `.manifest` object content.
    func decodeContent(_ content: Data) throws -> V2ChunkManifest {
        let manifest: V2ChunkManifest
        do {
            manifest = try decoder.decode(V2ChunkManifest.self, from: content)
        } catch {
            throw V2ChunkManifestCodecError.malformedManifest
        }
        try manifest.validate()
        return manifest
    }
}

public enum V2ChunkedFileIntegrity {
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
