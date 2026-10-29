import XCTest
@testable import HanzalaomatorCore

final class V2PoolObjectCodecTests: XCTestCase {
    func testRoundTripForEveryEncryptedRole() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x11, count: 32)

        for (index, kind) in [V2PoolObjectKind.metadata, .data, .padding].enumerated() {
            let content = Data("role-private-payload".utf8)
            let name = opaque(String(index + 1).first!)
            let sealed = try codec.seal(
                kind: kind,
                content: content,
                masterKey: key,
                objectName: name
            )
            let opened = try codec.open(
                sealed,
                masterKey: key,
                objectName: name
            )

            XCTAssertEqual(opened.kind, kind)
            XCTAssertEqual(opened.content, content)
        }
    }

    func testEqualPaddingTargetProducesEqualEnvelopeLengthsAndRoundTrips() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x22, count: 32)
        let metadataName = opaque("a")
        let dataName = opaque("b")
        let paddingName = opaque("c")

        let metadataContent = Data(repeating: 0x01, count: 20)
        let dataContent = Data(repeating: 0x02, count: 2_000)
        let metadata = try codec.seal(
            kind: .metadata,
            content: metadataContent,
            masterKey: key,
            objectName: metadataName,
            paddedPlaintextByteCount: 4_096
        )
        let data = try codec.seal(
            kind: .data,
            content: dataContent,
            masterKey: key,
            objectName: dataName,
            paddedPlaintextByteCount: 4_096
        )
        let padding = try codec.seal(
            kind: .padding,
            content: Data(),
            masterKey: key,
            objectName: paddingName,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertEqual(metadata.count, data.count)
        XCTAssertEqual(data.count, padding.count)
        XCTAssertEqual(
            try codec.open(metadata, masterKey: key, objectName: metadataName).content,
            metadataContent
        )
        XCTAssertEqual(
            try codec.open(data, masterKey: key, objectName: dataName).content,
            dataContent
        )
        XCTAssertEqual(
            try codec.open(padding, masterKey: key, objectName: paddingName).kind,
            .padding
        )
    }

    func testPublicPrefixIsGenericForEveryEncryptedRole() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x33, count: 32)
        let expectedMagic = Data("HZOBJ003".utf8)

        for (index, kind) in [V2PoolObjectKind.metadata, .data, .padding].enumerated() {
            let sealed = try codec.seal(
                kind: kind,
                content: Data("private-content".utf8),
                masterKey: key,
                objectName: opaque(String(index + 4).first!),
                paddedPlaintextByteCount: 512
            )
            XCTAssertEqual(Data(sealed.prefix(expectedMagic.count)), expectedMagic)
        }
    }

    func testCiphertextCannotBeOpenedUnderDifferentOpaqueName() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x3A, count: 32)
        let nameA = opaque("d")
        let nameB = opaque("e")
        let sealed = try codec.seal(
            kind: .data,
            content: Data("same-key-name-bound".utf8),
            masterKey: key,
            objectName: nameA,
            paddedPlaintextByteCount: 512
        )

        XCTAssertThrowsError(
            try codec.open(sealed, masterKey: key, objectName: nameB)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
        XCTAssertEqual(
            try codec.open(sealed, masterKey: key, objectName: nameA).content,
            Data("same-key-name-bound".utf8)
        )
    }

    func testInvalidObjectNameBindingIsRejected() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x3B, count: 32)

        XCTAssertThrowsError(
            try codec.seal(
                kind: .data,
                content: Data(),
                masterKey: key,
                objectName: "../not-an-opaque-name"
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .invalidObjectNameBinding)
        }

        let validName = opaque("f")
        let sealed = try codec.seal(
            kind: .data,
            content: Data(),
            masterKey: key,
            objectName: validName
        )
        XCTAssertThrowsError(
            try codec.open(sealed, masterKey: key, objectName: "short")
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .invalidObjectNameBinding)
        }
    }

    func testTamperIsRejected() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x44, count: 32)
        let name = opaque("1")
        var sealed = try codec.seal(
            kind: .data,
            content: Data("evidence".utf8),
            masterKey: key,
            objectName: name
        )
        sealed[sealed.index(before: sealed.endIndex)] ^= 0x01

        XCTAssertThrowsError(
            try codec.open(sealed, masterKey: key, objectName: name)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testWrongMasterKeyIsRejected() throws {
        let codec = V2PoolObjectCodec()
        let keyA = Data(repeating: 0x55, count: 32)
        let keyB = Data(repeating: 0x56, count: 32)
        let name = opaque("2")
        let sealed = try codec.seal(
            kind: .data,
            content: Data("source-file".utf8),
            masterKey: keyA,
            objectName: name
        )

        XCTAssertThrowsError(
            try codec.open(sealed, masterKey: keyB, objectName: name)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testInvalidMasterKeyLengthIsRejected() {
        let codec = V2PoolObjectCodec()
        XCTAssertThrowsError(
            try codec.seal(
                kind: .data,
                content: Data(),
                masterKey: Data(repeating: 0, count: 31),
                objectName: opaque("3")
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .invalidMasterKeyLength)
        }
    }

    func testPaddingTargetCannotTruncateLogicalContent() {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x66, count: 32)
        XCTAssertThrowsError(
            try codec.seal(
                kind: .data,
                content: Data(repeating: 0xAB, count: 100),
                masterKey: key,
                objectName: opaque("4"),
                paddedPlaintextByteCount: 50
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .invalidPaddingTarget)
        }
    }

    func testOversizedPaddingTargetIsRejectedBeforeAllocation() {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0x67, count: 32)
        XCTAssertThrowsError(
            try codec.seal(
                kind: .data,
                content: Data(),
                masterKey: key,
                objectName: opaque("5"),
                paddedPlaintextByteCount: V2PoolObjectCodec.maximumPlaintextByteCount + 1
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .payloadTooLarge)
        }
    }

    func testPoolObjectKeyIsSeparatedFromNamespaceKey() throws {
        let deriver = DomainKeyDeriver()
        let masterKey = Data(repeating: 0x77, count: 32)
        let namespace = try deriver.derive(masterKey: masterKey, purpose: .namespaceV2)
        let poolObject = try deriver.derive(masterKey: masterKey, purpose: .poolObjectV2)

        XCTAssertNotEqual(namespace, poolObject)
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }
}
