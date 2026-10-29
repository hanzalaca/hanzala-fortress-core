import XCTest
@testable import HanzalaomatorCore

final class V2PoolObjectStoreTests: XCTestCase {
    private let fileManager = FileManager.default

    func testCreateReadRoundTripUsesOpaqueImmutableObjectAndLeavesNoStageFile() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let name = String(repeating: "a", count: V2OpaqueObjectName.encodedLength)
        let store = V2PoolObjectStore(nameGenerator: { name })
        let key = Data(repeating: 0x31, count: 32)
        let content = Data("confidential-source-material".utf8)

        let reference = try store.createObject(
            kind: .data,
            content: content,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        XCTAssertEqual(reference.opaqueName, name)
        XCTAssertEqual(reference.logicalByteCount, UInt64(content.count))
        XCTAssertTrue(store.containsObject(named: name, in: root))

        let opened = try store.readObject(named: name, masterKey: key, in: root)
        XCTAssertEqual(opened.kind, .data)
        XCTAssertEqual(opened.content, content)

        let objectURL = V2StorageLayout.objectURL(named: name, in: root)
        let publicBytes = try Data(contentsOf: objectURL)
        XCTAssertNil(publicBytes.range(of: content))
        XCTAssertEqual(UInt64(publicBytes.count), reference.sealedByteCount)

        let poolContents = try fileManager.contentsOfDirectory(
            at: V2StorageLayout.poolURL(in: root),
            includingPropertiesForKeys: nil
        )
        XCTAssertEqual(poolContents.map(\.lastPathComponent), [name])
        XCTAssertFalse(poolContents.contains { $0.lastPathComponent.contains("stage") })
    }

    func testNameCollisionNeverOverwritesExistingObjectAndUsesFreshName() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)

        let first = String(repeating: "b", count: V2OpaqueObjectName.encodedLength)
        let second = String(repeating: "c", count: V2OpaqueObjectName.encodedLength)
        let existingURL = V2StorageLayout.objectURL(named: first, in: root)
        let sentinel = Data("must-not-be-replaced".utf8)
        try sentinel.write(to: existingURL)

        var generated = [first, second]
        let store = V2PoolObjectStore(nameGenerator: { generated.removeFirst() })
        let reference = try store.createObject(
            kind: .metadata,
            content: Data("new-object".utf8),
            masterKey: Data(repeating: 0x32, count: 32),
            in: root
        )

        XCTAssertEqual(reference.opaqueName, second)
        XCTAssertEqual(try Data(contentsOf: existingURL), sentinel)
        XCTAssertTrue(fileManager.fileExists(
            atPath: V2StorageLayout.objectURL(named: second, in: root).path
        ))
        XCTAssertEqual(
            try store.readObject(
                named: second,
                masterKey: Data(repeating: 0x32, count: 32),
                in: root
            ).content,
            Data("new-object".utf8)
        )
    }

    func testRepeatedCollisionFailsClosedWithoutReplacingExistingObject() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)
        let name = String(repeating: "d", count: V2OpaqueObjectName.encodedLength)
        let existingURL = V2StorageLayout.objectURL(named: name, in: root)
        let sentinel = Data("existing".utf8)
        try sentinel.write(to: existingURL)

        let store = V2PoolObjectStore(nameGenerator: { name })
        XCTAssertThrowsError(
            try store.createObject(
                kind: .data,
                content: Data("new".utf8),
                masterKey: Data(repeating: 0x33, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .nameGenerationExhausted)
        }
        XCTAssertEqual(try Data(contentsOf: existingURL), sentinel)
    }

    func testInvalidGeneratedNameIsRejectedBeforeFilesystemWrite() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let store = V2PoolObjectStore(nameGenerator: { "../escape" })
        XCTAssertThrowsError(
            try store.createObject(
                kind: .data,
                content: Data(),
                masterKey: Data(repeating: 0x34, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .invalidOpaqueName)
        }
    }

    func testPoolPathThatIsRegularFileIsRejected() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let pool = V2StorageLayout.poolURL(in: root)
        try Data("not-a-directory".utf8).write(to: pool)

        let name = String(repeating: "e", count: V2OpaqueObjectName.encodedLength)
        let store = V2PoolObjectStore(nameGenerator: { name })
        XCTAssertThrowsError(
            try store.createObject(
                kind: .data,
                content: Data(),
                masterKey: Data(repeating: 0x35, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .poolPathIsNotDirectory)
        }
    }

    func testPoolDirectorySymlinkIsRejected() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let outside = try makeRoot()
        defer { try? fileManager.removeItem(at: outside) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createSymbolicLink(at: pool, withDestinationURL: outside)

        let name = String(repeating: "f", count: V2OpaqueObjectName.encodedLength)
        let store = V2PoolObjectStore(nameGenerator: { name })
        XCTAssertThrowsError(
            try store.createObject(
                kind: .data,
                content: Data("no-escape".utf8),
                masterKey: Data(repeating: 0x36, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .poolPathIsSymbolicLink)
        }
        XCTAssertTrue(try fileManager.contentsOfDirectory(atPath: outside.path).isEmpty)
    }

    func testObjectSymlinkIsRejectedAndNotReportedAsContained() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let outside = try makeRoot()
        defer { try? fileManager.removeItem(at: outside) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)
        let target = outside.appendingPathComponent("target")
        try Data("outside".utf8).write(to: target)

        let name = String(repeating: "1", count: V2OpaqueObjectName.encodedLength)
        let link = V2StorageLayout.objectURL(named: name, in: root)
        try fileManager.createSymbolicLink(at: link, withDestinationURL: target)

        let store = V2PoolObjectStore()
        XCTAssertFalse(store.containsObject(named: name, in: root))
        XCTAssertThrowsError(
            try store.readObject(
                named: name,
                masterKey: Data(repeating: 0x37, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectIsNotRegularFile)
        }
    }

    func testOversizedFilesystemObjectIsRejectedBeforeCodecOpen() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)
        let name = String(repeating: "2", count: V2OpaqueObjectName.encodedLength)
        let url = V2StorageLayout.objectURL(named: name, in: root)
        try Data(count: V2PoolObjectCodec.maximumEnvelopeByteCount + 1).write(to: url)

        let store = V2PoolObjectStore()
        XCTAssertFalse(store.containsObject(named: name, in: root))
        XCTAssertThrowsError(
            try store.readObject(
                named: name,
                masterKey: Data(repeating: 0x38, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectTooLarge)
        }
    }

    func testObjectPathReplacementAfterDescriptorOpenCannotRetargetRead() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-relative pool reads are Darwin-specific.")
        #else
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let name = String(repeating: "6", count: V2OpaqueObjectName.encodedLength)
        let key = Data(repeating: 0x3C, count: 32)
        let original = Data("authenticated-original-object".utf8)
        let attackerReplacement = Data("attacker-path-replacement".utf8)
        let store = V2PoolObjectStore()

        _ = try store.createObject(
            named: name,
            kind: .data,
            content: original,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        let objectURL = V2StorageLayout.objectURL(named: name, in: root)
        let retiredURL = V2StorageLayout.poolURL(in: root)
            .appendingPathComponent("retired-object")
        var replaced = false
        store.objectOpenedHook = { openedName in
            guard openedName == name, !replaced else { return }
            replaced = true
            do {
                try self.fileManager.moveItem(at: objectURL, to: retiredURL)
                try attackerReplacement.write(to: objectURL)
            } catch {
                XCTFail("Failed to replace object pathname after descriptor open: \(error)")
            }
        }

        let opened = try store.readObject(named: name, masterKey: key, in: root)
        XCTAssertTrue(replaced)
        XCTAssertEqual(opened.kind, .data)
        XCTAssertEqual(opened.content, original)
        XCTAssertEqual(try Data(contentsOf: objectURL), attackerReplacement)
        #endif
    }

    func testWrongKeyStillFailsAuthenticatedCodecOpen() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let name = String(repeating: "3", count: V2OpaqueObjectName.encodedLength)
        let store = V2PoolObjectStore(nameGenerator: { name })
        let keyA = Data(repeating: 0x39, count: 32)
        let keyB = Data(repeating: 0x3A, count: 32)
        _ = try store.createObject(
            kind: .data,
            content: Data("authenticated".utf8),
            masterKey: keyA,
            in: root
        )

        XCTAssertThrowsError(try store.readObject(named: name, masterKey: keyB, in: root)) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testSameKeySameLengthCiphertextSwapBetweenOpaqueNamesFailsAuthentication() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x3B, count: 32)
        let nameA = String(repeating: "4", count: V2OpaqueObjectName.encodedLength)
        let nameB = String(repeating: "5", count: V2OpaqueObjectName.encodedLength)
        let store = V2PoolObjectStore()
        let contentA = Data([1, 2, 3, 4])
        let contentB = Data([9, 8, 7, 6])

        _ = try store.createObject(
            named: nameA,
            kind: .data,
            content: contentA,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )
        _ = try store.createObject(
            named: nameB,
            kind: .data,
            content: contentB,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4_096
        )

        let urlA = V2StorageLayout.objectURL(named: nameA, in: root)
        let urlB = V2StorageLayout.objectURL(named: nameB, in: root)
        let ciphertextA = try Data(contentsOf: urlA)
        let ciphertextB = try Data(contentsOf: urlB)
        XCTAssertEqual(ciphertextA.count, ciphertextB.count)

        try ciphertextB.write(to: urlA, options: [.atomic])
        try ciphertextA.write(to: urlB, options: [.atomic])

        XCTAssertThrowsError(
            try store.readObject(named: nameA, masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try store.readObject(named: nameB, masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-pool-store-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
