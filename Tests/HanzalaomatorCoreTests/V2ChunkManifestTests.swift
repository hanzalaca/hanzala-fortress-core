import XCTest
@testable import HanzalaomatorCore

final class V2ChunkManifestTests: XCTestCase {
    func testValidManifestRoundTripsInsideEncryptedNameBoundObject() throws {
        let manifest = try makeManifest(chunkCount: 5)
        let codec = V2ChunkManifestCodec()
        let key = Data(repeating: 0x81, count: 32)
        let manifestName = opaque("a")

        let sealed = try codec.seal(
            manifest,
            masterKey: key,
            objectName: manifestName
        )
        let opened = try codec.open(
            sealed,
            masterKey: key,
            objectName: manifestName
        )

        XCTAssertEqual(opened, manifest)
        let publicText = String(decoding: sealed, as: UTF8.self)
        XCTAssertFalse(publicText.contains(manifest.fileID.uuidString))
        for chunk in manifest.chunks {
            XCTAssertFalse(publicText.contains(chunk.opaqueObjectName))
        }
    }

    func testManifestCiphertextCannotBeReboundToAnotherOpaqueName() throws {
        let manifest = try makeManifest(chunkCount: 5)
        let codec = V2ChunkManifestCodec()
        let key = Data(repeating: 0x82, count: 32)
        let nameA = opaque("b")
        let nameB = opaque("c")
        let sealed = try codec.seal(manifest, masterKey: key, objectName: nameA)

        XCTAssertThrowsError(
            try codec.open(sealed, masterKey: key, objectName: nameB)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testWrongMasterKeyRejectsManifest() throws {
        let manifest = try makeManifest(chunkCount: 5)
        let codec = V2ChunkManifestCodec()
        let name = opaque("d")
        let sealed = try codec.seal(
            manifest,
            masterKey: Data(repeating: 0x83, count: 32),
            objectName: name
        )

        XCTAssertThrowsError(
            try codec.open(
                sealed,
                masterKey: Data(repeating: 0x84, count: 32),
                objectName: name
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testGenericDataObjectCannotBeInterpretedAsManifest() throws {
        let poolCodec = V2PoolObjectCodec()
        let codec = V2ChunkManifestCodec(poolCodec: poolCodec)
        let key = Data(repeating: 0x85, count: 32)
        let name = opaque("e")
        let dataObject = try poolCodec.seal(
            kind: .data,
            content: Data("not-a-manifest".utf8),
            masterKey: key,
            objectName: name,
            paddedPlaintextByteCount: 4 * 1024
        )

        XCTAssertThrowsError(
            try codec.open(dataObject, masterKey: key, objectName: name)
        ) { error in
            XCTAssertEqual(error as? V2ChunkManifestCodecError, .unexpectedObjectKind)
        }
    }

    func testDuplicateChunkNameIsRejected() throws {
        let valid = try makeManifest(chunkCount: 5)
        var chunks = valid.chunks
        chunks[4] = V2ChunkReference(
            opaqueObjectName: chunks[0].opaqueObjectName,
            logicalByteCount: chunks[4].logicalByteCount
        )
        let invalid = V2ChunkManifest(
            fileID: valid.fileID,
            logicalByteCount: valid.logicalByteCount,
            chunks: chunks,
            sha256Digest: valid.sha256Digest
        )

        XCTAssertThrowsError(try invalid.validate()) { error in
            XCTAssertEqual(
                error as? V2ChunkManifestValidationError,
                .duplicateChunkObjectName
            )
        }
    }

    func testNonCanonicalIntermediateChunkLengthIsRejected() throws {
        let valid = try makeManifest(chunkCount: 5)
        var chunks = valid.chunks
        chunks[1] = V2ChunkReference(
            opaqueObjectName: chunks[1].opaqueObjectName,
            logicalByteCount: UInt64(V2ChunkManifest.maximumLogicalChunkByteCount - 1)
        )
        let invalid = V2ChunkManifest(
            fileID: valid.fileID,
            logicalByteCount: valid.logicalByteCount - 1,
            chunks: chunks,
            sha256Digest: valid.sha256Digest
        )

        XCTAssertThrowsError(try invalid.validate()) { error in
            XCTAssertEqual(
                error as? V2ChunkManifestValidationError,
                .nonCanonicalChunkLength
            )
        }
    }

    func testLogicalLengthMismatchIsRejected() throws {
        let valid = try makeManifest(chunkCount: 5)
        let invalid = V2ChunkManifest(
            fileID: valid.fileID,
            logicalByteCount: valid.logicalByteCount + 1,
            chunks: valid.chunks,
            sha256Digest: valid.sha256Digest
        )

        XCTAssertThrowsError(try invalid.validate()) { error in
            XCTAssertEqual(error as? V2ChunkManifestValidationError, .logicalLengthMismatch)
        }
    }

    func testChunkingIsRejectedWhenSingleObjectStillFits() {
        let maxChunk = UInt64(V2ChunkManifest.maximumLogicalChunkByteCount)
        let chunks = [
            V2ChunkReference(opaqueObjectName: opaque("1"), logicalByteCount: maxChunk),
            V2ChunkReference(opaqueObjectName: opaque("2"), logicalByteCount: 1)
        ]
        let manifest = V2ChunkManifest(
            logicalByteCount: maxChunk + 1,
            chunks: chunks,
            sha256Digest: Data(repeating: 0, count: 32)
        )

        XCTAssertThrowsError(try manifest.validate()) { error in
            XCTAssertEqual(error as? V2ChunkManifestValidationError, .chunkingNotRequired)
        }
    }

    func testInvalidDigestLengthIsRejected() throws {
        let valid = try makeManifest(chunkCount: 5)
        let invalid = V2ChunkManifest(
            fileID: valid.fileID,
            logicalByteCount: valid.logicalByteCount,
            chunks: valid.chunks,
            sha256Digest: Data(repeating: 0, count: 31)
        )

        XCTAssertThrowsError(try invalid.validate()) { error in
            XCTAssertEqual(error as? V2ChunkManifestValidationError, .invalidContentDigest)
        }
    }

    func testCoarseManifestPaddingHidesSmallChunkCountDifference() throws {
        let codec = V2ChunkManifestCodec()
        let key = Data(repeating: 0x86, count: 32)
        let five = try codec.seal(
            makeManifest(chunkCount: 5),
            masterKey: key,
            objectName: opaque("3")
        )
        let six = try codec.seal(
            makeManifest(chunkCount: 6),
            masterKey: key,
            objectName: opaque("4")
        )

        XCTAssertEqual(five.count, six.count)
        XCTAssertEqual(five.count, 4 * 1024 + 8 + 24 + 16)
    }

    func testWholeFileDigestHelperIsDeterministicAndSensitiveToContent() {
        let first = V2ChunkedFileIntegrity.sha256(Data("source-a".utf8))
        let same = V2ChunkedFileIntegrity.sha256(Data("source-a".utf8))
        let different = V2ChunkedFileIntegrity.sha256(Data("source-b".utf8))

        XCTAssertEqual(first.count, 32)
        XCTAssertEqual(first, same)
        XCTAssertNotEqual(first, different)
    }

    private func makeManifest(chunkCount: Int) throws -> V2ChunkManifest {
        precondition(chunkCount >= 5)
        let full = UInt64(V2ChunkManifest.maximumLogicalChunkByteCount)
        var chunks: [V2ChunkReference] = []
        for index in 0..<chunkCount {
            let scalar = Character(String(index % 10))
            let logical = index == chunkCount - 1 ? UInt64(1_234) : full
            chunks.append(
                V2ChunkReference(
                    opaqueObjectName: opaque(scalar),
                    logicalByteCount: logical
                )
            )
        }
        let total = chunks.reduce(UInt64(0)) { $0 + $1.logicalByteCount }
        let digest = V2ChunkedFileIntegrity.sha256(Data("logical-file".utf8))
        let manifest = V2ChunkManifest(
            fileID: UUID(uuidString: "81000000-0000-0000-0000-000000000001")!,
            logicalByteCount: total,
            chunks: chunks,
            sha256Digest: digest
        )
        try manifest.validate()
        return manifest
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }
}
