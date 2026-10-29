import Foundation
import XCTest
@testable import HanzalaomatorCore

final class V2AdversarialFuzzTests: XCTestCase {
    private let fileManager = FileManager.default

    func testDeterministicGarbageWithValidMagicNeverAuthenticates() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0xA1, count: 32)
        let name = opaque("a")
        let magic = Data("HZOBJ003".utf8)
        var rng = DeterministicRNG(seed: 0x48414E5A414C4132)

        for caseIndex in 0..<512 {
            let protectedLength = 50 + Int(rng.next() % 4_047)
            var candidate = magic
            candidate.append(rng.bytes(count: protectedLength))

            XCTAssertThrowsError(
                try codec.open(candidate, masterKey: key, objectName: name),
                "Unauthenticated deterministic corpus case \(caseIndex) unexpectedly opened"
            )
        }
    }

    func testSampledCiphertextBitFlipsAlwaysFailClosed() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0xA2, count: 32)
        let name = opaque("b")
        let sealed = try codec.seal(
            kind: .data,
            content: Data("journalist-source-evidence".utf8),
            masterKey: key,
            objectName: name,
            paddedPlaintextByteCount: 4_096
        )

        let sampleCount = min(256, sealed.count)
        for sample in 0..<sampleCount {
            let position = (sample * 104_729) % sealed.count
            var mutated = sealed
            let index = mutated.index(mutated.startIndex, offsetBy: position)
            mutated[index] ^= UInt8((sample % 7) + 1)

            XCTAssertThrowsError(
                try codec.open(mutated, masterKey: key, objectName: name),
                "Bit flip at public envelope byte \(position) unexpectedly authenticated"
            )
        }
    }

    func testTruncationAndExtensionOfValidEnvelopeFailClosed() throws {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0xA3, count: 32)
        let name = opaque("c")
        let sealed = try codec.seal(
            kind: .metadata,
            content: Data("authenticated-metadata".utf8),
            masterKey: key,
            objectName: name,
            paddedPlaintextByteCount: 4_096
        )

        var truncationLengths = Set<Int>([0, 1, 7, 8, 16, 31, 57, sealed.count - 1])
        for length in stride(from: 0, to: sealed.count, by: 97) {
            truncationLengths.insert(length)
        }

        for length in truncationLengths.sorted() where length < sealed.count {
            let truncated = Data(sealed.prefix(length))
            XCTAssertThrowsError(
                try codec.open(truncated, masterKey: key, objectName: name),
                "Truncated envelope length \(length) unexpectedly opened"
            )
        }

        var rng = DeterministicRNG(seed: 0x455854454E53494F)
        for extraByteCount in 1...64 {
            var extended = sealed
            extended.append(rng.bytes(count: extraByteCount))
            XCTAssertThrowsError(
                try codec.open(extended, masterKey: key, objectName: name),
                "Envelope with \(extraByteCount) unauthenticated trailing bytes unexpectedly opened"
            )
        }
    }

    func testOversizedPublicEnvelopeIsRejectedBeforeAuthentication() {
        let codec = V2PoolObjectCodec()
        let key = Data(repeating: 0xA4, count: 32)
        let name = opaque("d")
        let oversized = Data(
            repeating: 0,
            count: V2PoolObjectCodec.maximumEnvelopeByteCount + 1
        )

        XCTAssertThrowsError(
            try codec.open(oversized, masterKey: key, objectName: name)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .payloadTooLarge)
        }
    }

    func testAuthenticatedMetadataAnchorMutationsNeverDecodeAsAnotherGeneration() throws {
        let root = temporaryRoot()
        defer { try? fileManager.removeItem(at: root) }
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false)

        let key = Data(repeating: 0xA5, count: 32)
        let store = V2AccessMetadataStore(fileManager: fileManager)
        let budget = try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        let original = try store.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )
        XCTAssertEqual(try store.read(masterKey: key, in: root), original)

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        let sealed = try Data(contentsOf: anchorURL)
        let sampleCount = min(96, sealed.count)

        for sample in 0..<sampleCount {
            let position = (sample * 65_537) % sealed.count
            var mutated = sealed
            let index = mutated.index(mutated.startIndex, offsetBy: position)
            mutated[index] ^= UInt8((sample % 13) + 1)
            try mutated.write(to: anchorURL, options: [.atomic])

            XCTAssertThrowsError(
                try store.read(masterKey: key, in: root),
                "Mutated metadata anchor byte \(position) unexpectedly decoded"
            )

            try sealed.write(to: anchorURL, options: [.atomic])
            XCTAssertEqual(try store.read(masterKey: key, in: root), original)
        }
    }

    func testRandomManifestContentNeverBypassesDecodeAndValidation() {
        let codec = V2ChunkManifestCodec()
        var rng = DeterministicRNG(seed: 0x4D414E4946455354)

        for caseIndex in 0..<256 {
            let byteCount = Int(rng.next() % 2_048)
            let candidate = rng.bytes(count: byteCount)
            XCTAssertThrowsError(
                try codec.decodeContent(candidate),
                "Random manifest corpus case \(caseIndex) unexpectedly validated"
            )
        }
    }

    private func temporaryRoot() -> URL {
        fileManager.temporaryDirectory
            .appendingPathComponent("hz-adversarial-\(UUID().uuidString)", isDirectory: true)
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }
}

private struct DeterministicRNG {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return state
    }

    mutating func bytes(count: Int) -> Data {
        var output = Data()
        output.reserveCapacity(count)
        for _ in 0..<count {
            output.append(UInt8(truncatingIfNeeded: next() >> 24))
        }
        return output
    }
}
