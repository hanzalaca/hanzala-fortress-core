import XCTest
import CryptoKit
@testable import HanzalaomatorCore

final class V2ChunkedFileReaderTests: XCTestCase {
    private let fileManager = FileManager.default

    func testReadWithinOneChunkReturnsOnlyRequestedAuthenticatedBytes() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        let reader = V2ChunkedFileReader()
        let result = try reader.read(
            entry: fixture.entry,
            offset: 10,
            length: 32,
            masterKey: fixture.key,
            in: fixture.root
        )

        XCTAssertEqual(result, Data(repeating: 0x11, count: 32))
    }

    func testReadAcrossChunkBoundaryAssemblesExactLogicalRange() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        let start = UInt64(V2ChunkManifest.maximumLogicalChunkByteCount - 3)
        let result = try V2ChunkedFileReader().read(
            entry: fixture.entry,
            offset: start,
            length: 8,
            masterKey: fixture.key,
            in: fixture.root
        )

        var expected = Data(repeating: 0x11, count: 3)
        expected.append(Data(repeating: 0x22, count: 5))
        XCTAssertEqual(result, expected)
    }

    func testReadClampsAtLogicalEOFAndPastEOFFailsOpenAsEmptyRead() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        let reader = V2ChunkedFileReader()
        let nearEnd = try reader.read(
            entry: fixture.entry,
            offset: fixture.entry.logicalByteCount - 4,
            length: 100,
            masterKey: fixture.key,
            in: fixture.root
        )
        XCTAssertEqual(nearEnd, Data(repeating: 0x55, count: 4))

        let pastEnd = try reader.read(
            entry: fixture.entry,
            offset: fixture.entry.logicalByteCount,
            length: 100,
            masterKey: fixture.key,
            in: fixture.root
        )
        XCTAssertTrue(pastEnd.isEmpty)
    }

    func testReadRejectsOversizedRequestBeforeChunkMaterialization() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        XCTAssertThrowsError(
            try V2ChunkedFileReader(maximumReadLength: 64).read(
                entry: fixture.entry,
                offset: 0,
                length: 65,
                masterKey: fixture.key,
                in: fixture.root
            )
        ) { error in
            XCTAssertEqual(error as? V2ChunkedFileReaderError, .readTooLarge)
        }
    }

    func testManifestMustBindBackToAuthenticatedEntryOwnership() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        var swapped = fixture.entry.auxiliaryObjectNames
        swapped.swapAt(0, 1)
        let forgedEntry = V2AccessEntry(
            id: fixture.entry.id,
            opaqueObjectName: fixture.entry.opaqueObjectName,
            auxiliaryObjectNames: swapped,
            originalName: fixture.entry.originalName,
            logicalByteCount: fixture.entry.logicalByteCount,
            createdAt: fixture.entry.createdAt
        )

        XCTAssertThrowsError(
            try V2ChunkedFileReader().read(
                entry: forgedEntry,
                offset: 0,
                length: 1,
                masterKey: fixture.key,
                in: fixture.root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2ChunkedFileReaderError,
                .manifestOwnershipMismatch
            )
        }
    }

    func testReaderTouchesOnlyChunksIntersectingRequestedRange() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        let untouchedName = fixture.entry.auxiliaryObjectNames.last!
        let untouchedURL = V2StorageLayout.objectURL(named: untouchedName, in: fixture.root)
        var sealed = try Data(contentsOf: untouchedURL)
        sealed[sealed.index(before: sealed.endIndex)] ^= 0x01
        try sealed.write(to: untouchedURL, options: [.atomic])

        // A range entirely inside the first chunk must not touch the damaged last
        // chunk, so it remains independently readable and bounded.
        XCTAssertEqual(
            try V2ChunkedFileReader().read(
                entry: fixture.entry,
                offset: 0,
                length: 16,
                masterKey: fixture.key,
                in: fixture.root
            ),
            Data(repeating: 0x11, count: 16)
        )

        XCTAssertThrowsError(
            try V2ChunkedFileReader().verifyWholeFile(
                entry: fixture.entry,
                masterKey: fixture.key,
                in: fixture.root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testVerifyWholeFileChecksEncryptedDigestWithoutAssemblingFile() throws {
        let fixture = try makeFixture()
        defer { try? fileManager.removeItem(at: fixture.root) }

        XCTAssertNoThrow(
            try V2ChunkedFileReader().verifyWholeFile(
                entry: fixture.entry,
                masterKey: fixture.key,
                in: fixture.root
            )
        )
    }

    func testWrongEncryptedWholeFileDigestDoesNotBreakAuthenticatedRangeButFailsVerification() throws {
        let fixture = try makeFixture(useWrongDigest: true)
        defer { try? fileManager.removeItem(at: fixture.root) }

        // The touched chunk is independently authenticated and the manifest is
        // authenticated, so a bounded range remains safe even though the private
        // end-to-end digest is intentionally inconsistent.
        XCTAssertEqual(
            try V2ChunkedFileReader().read(
                entry: fixture.entry,
                offset: 0,
                length: 8,
                masterKey: fixture.key,
                in: fixture.root
            ),
            Data(repeating: 0x11, count: 8)
        )

        XCTAssertThrowsError(
            try V2ChunkedFileReader().verifyWholeFile(
                entry: fixture.entry,
                masterKey: fixture.key,
                in: fixture.root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2ChunkedFileReaderError,
                .wholeFileDigestMismatch
            )
        }
    }

    func testSingleObjectEntryIsRejectedForChunkedReader() throws {
        let entry = V2AccessEntry(
            opaqueObjectName: opaque("a"),
            originalName: "small.txt",
            logicalByteCount: 10
        )
        XCTAssertThrowsError(
            try V2ChunkedFileReader().read(
                entry: entry,
                offset: 0,
                length: 1,
                masterKey: Data(repeating: 0x01, count: 32),
                in: fileManager.temporaryDirectory
            )
        ) { error in
            XCTAssertEqual(error as? V2ChunkedFileReaderError, .entryIsNotChunked)
        }
    }

    private struct Fixture {
        let root: URL
        let key: Data
        let entry: V2AccessEntry
    }

    private func makeFixture(useWrongDigest: Bool = false) throws -> Fixture {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-chunk-reader-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)

        let key = Data(repeating: 0x91, count: 32)
        let manifestName = opaque("a")
        let chunkNames = ["b", "c", "d", "e", "f"].map { opaque(Character($0)) }
        let full = V2ChunkManifest.maximumLogicalChunkByteCount
        let lengths = [full, full, full, full, 64]
        let byteValues: [UInt8] = [0x11, 0x22, 0x33, 0x44, 0x55]
        let objectStore = V2PoolObjectStore()

        var hasher = SHA256()
        var references: [V2ChunkReference] = []
        var total: UInt64 = 0

        for index in lengths.indices {
            let content = Data(repeating: byteValues[index], count: lengths[index])
            hasher.update(data: content)
            _ = try objectStore.createObject(
                named: chunkNames[index],
                kind: .data,
                content: content,
                masterKey: key,
                in: root,
                paddedPlaintextByteCount: V2ChunkManifest.chunkPaddedPlaintextByteCount
            )
            references.append(V2ChunkReference(
                opaqueObjectName: chunkNames[index],
                logicalByteCount: UInt64(lengths[index])
            ))
            total += UInt64(lengths[index])
        }

        let fileID = UUID()
        let actualDigest = Data(hasher.finalize())
        let manifest = V2ChunkManifest(
            fileID: fileID,
            logicalByteCount: total,
            chunks: references,
            sha256Digest: useWrongDigest
                ? Data(repeating: 0xAA, count: SHA256.Digest.byteCount)
                : actualDigest
        )
        try manifest.validate()

        let manifestCodec = V2ChunkManifestCodec()
        let encoded = try manifestCodec.encodeContent(manifest)
        let paddingTarget = try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
            forEncodedMetadataByteCount: encoded.count
        )
        _ = try objectStore.createObject(
            named: manifestName,
            kind: .manifest,
            content: encoded,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: paddingTarget
        )

        let entry = V2AccessEntry(
            id: fileID,
            opaqueObjectName: manifestName,
            auxiliaryObjectNames: chunkNames,
            originalName: "large-evidence.bin",
            logicalByteCount: total,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        return Fixture(root: root, key: key, entry: entry)
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }
}
