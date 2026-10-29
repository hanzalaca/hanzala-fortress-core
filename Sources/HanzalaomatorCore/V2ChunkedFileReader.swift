import Foundation
import CryptoKit

public enum V2ChunkedFileReaderError: Error, Equatable, Sendable {
    case entryIsNotChunked
    case invalidReadLength
    case readTooLarge
    case manifestKindMismatch
    case manifestEntryIdentityMismatch
    case manifestLengthMismatch
    case manifestOwnershipMismatch
    case chunkKindMismatch
    case chunkLengthMismatch
    case assembledReadLengthMismatch
    case wholeFileDigestMismatch
    case arithmeticOverflow
}

/// Authenticated bounded-range reader for a v2 chunked logical file.
///
/// Security boundary:
/// - `entry` must come from already-authenticated per-access metadata;
/// - callers never supply a manifest or chunk pool name separately;
/// - the manifest is opened only through `entry.opaqueObjectName` and is then
///   bound back to the entry ID, logical length, and authenticated auxiliary names;
/// - only chunks whose authenticated private ranges intersect the request are read;
/// - each touched chunk must authenticate under the current master key, exact
///   opaque filename, `.data` role, and manifest-declared logical length;
/// - the shared pool is never scanned.
///
/// Arbitrary range reads do not recompute the whole-file digest because doing so
/// would require reading every chunk for every small read. Per-chunk XChaCha20-
/// Poly1305 authentication and the authenticated manifest protect the requested
/// range. `verifyWholeFile` is provided for explicit end-to-end digest checking.
public final class V2ChunkedFileReader {
    /// Intentionally matches the existing Finder RPC bound while remaining a
    /// storage-layer constant rather than depending on the Finder subsystem.
    public static let defaultMaximumReadLength = 4 * 1024 * 1024

    private let objectStore: V2PoolObjectStore
    private let manifestCodec: V2ChunkManifestCodec
    private let maximumReadLength: Int

    public init(
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        manifestCodec: V2ChunkManifestCodec = V2ChunkManifestCodec(),
        maximumReadLength: Int = V2ChunkedFileReader.defaultMaximumReadLength
    ) {
        precondition(maximumReadLength > 0)
        self.objectStore = objectStore
        self.manifestCodec = manifestCodec
        self.maximumReadLength = maximumReadLength
    }

    /// Returns at most `maximumReadLength` authenticated logical bytes without
    /// materializing the complete large file. At most one bounded chunk object is
    /// held as plaintext at a time in addition to the returned range buffer.
    public func read(
        entry: V2AccessEntry,
        offset: UInt64,
        length: Int,
        masterKey: Data,
        in root: URL
    ) throws -> Data {
        guard length >= 0 else {
            throw V2ChunkedFileReaderError.invalidReadLength
        }
        guard length <= maximumReadLength else {
            throw V2ChunkedFileReaderError.readTooLarge
        }
        if length == 0 || offset >= entry.logicalByteCount {
            return Data()
        }

        let manifest = try validatedManifest(
            for: entry,
            masterKey: masterKey,
            in: root
        )

        let available = manifest.logicalByteCount - offset
        let requested = min(UInt64(length), available)
        guard requested <= UInt64(Int.max) else {
            throw V2ChunkedFileReaderError.arithmeticOverflow
        }
        let (requestedEnd, endOverflow) = offset.addingReportingOverflow(requested)
        guard !endOverflow else {
            throw V2ChunkedFileReaderError.arithmeticOverflow
        }

        var result = Data()
        result.reserveCapacity(Int(requested))
        var chunkStart: UInt64 = 0

        for reference in manifest.chunks {
            let (chunkEnd, chunkOverflow) = chunkStart.addingReportingOverflow(
                reference.logicalByteCount
            )
            guard !chunkOverflow else {
                throw V2ChunkedFileReaderError.arithmeticOverflow
            }

            if requestedEnd <= chunkStart {
                break
            }
            if offset < chunkEnd, requestedEnd > chunkStart {
                let object = try objectStore.readObject(
                    named: reference.opaqueObjectName,
                    masterKey: masterKey,
                    in: root
                )
                guard object.kind == .data else {
                    throw V2ChunkedFileReaderError.chunkKindMismatch
                }
                guard UInt64(object.content.count) == reference.logicalByteCount else {
                    throw V2ChunkedFileReaderError.chunkLengthMismatch
                }

                let overlapStart = max(offset, chunkStart)
                let overlapEnd = min(requestedEnd, chunkEnd)
                let localStart = overlapStart - chunkStart
                let localEnd = overlapEnd - chunkStart
                guard localEnd <= UInt64(Int.max), localStart <= localEnd else {
                    throw V2ChunkedFileReaderError.arithmeticOverflow
                }

                let startIndex = object.content.index(
                    object.content.startIndex,
                    offsetBy: Int(localStart)
                )
                let endIndex = object.content.index(
                    object.content.startIndex,
                    offsetBy: Int(localEnd)
                )
                result.append(contentsOf: object.content[startIndex..<endIndex])
            }

            chunkStart = chunkEnd
        }

        guard result.count == Int(requested) else {
            throw V2ChunkedFileReaderError.assembledReadLengthMismatch
        }
        return result
    }

    /// Authenticates every manifest-declared chunk in order and recomputes the
    /// encrypted whole-file SHA-256 digest without assembling the file in memory.
    public func verifyWholeFile(
        entry: V2AccessEntry,
        masterKey: Data,
        in root: URL
    ) throws {
        let manifest = try validatedManifest(
            for: entry,
            masterKey: masterKey,
            in: root
        )

        var hasher = SHA256()
        for reference in manifest.chunks {
            let object = try objectStore.readObject(
                named: reference.opaqueObjectName,
                masterKey: masterKey,
                in: root
            )
            guard object.kind == .data else {
                throw V2ChunkedFileReaderError.chunkKindMismatch
            }
            guard UInt64(object.content.count) == reference.logicalByteCount else {
                throw V2ChunkedFileReaderError.chunkLengthMismatch
            }
            hasher.update(data: object.content)
        }

        guard Data(hasher.finalize()) == manifest.sha256Digest else {
            throw V2ChunkedFileReaderError.wholeFileDigestMismatch
        }
    }

    private func validatedManifest(
        for entry: V2AccessEntry,
        masterKey: Data,
        in root: URL
    ) throws -> V2ChunkManifest {
        guard !entry.auxiliaryObjectNames.isEmpty else {
            throw V2ChunkedFileReaderError.entryIsNotChunked
        }

        let object = try objectStore.readObject(
            named: entry.opaqueObjectName,
            masterKey: masterKey,
            in: root
        )
        guard object.kind == .manifest else {
            throw V2ChunkedFileReaderError.manifestKindMismatch
        }

        let manifest = try manifestCodec.decodeContent(object.content)
        guard manifest.fileID == entry.id else {
            throw V2ChunkedFileReaderError.manifestEntryIdentityMismatch
        }
        guard manifest.logicalByteCount == entry.logicalByteCount else {
            throw V2ChunkedFileReaderError.manifestLengthMismatch
        }
        guard manifest.chunks.map(\.opaqueObjectName) == entry.auxiliaryObjectNames else {
            throw V2ChunkedFileReaderError.manifestOwnershipMismatch
        }
        return manifest
    }
}
