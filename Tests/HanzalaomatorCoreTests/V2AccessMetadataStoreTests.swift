import XCTest
@testable import HanzalaomatorCore

final class V2AccessMetadataStoreTests: XCTestCase {
    private let fileManager = FileManager.default

    func testCreateAndReadEmptyMetadataAnchorWithoutPublicMetadataLeakage() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 10_000, reserveBytes: 2_000)
        let key = Data(repeating: 0x41, count: 32)
        let accessID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let store = V2AccessMetadataStore()

        let created = try store.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root,
            accessID: accessID
        )
        let opened = try store.read(masterKey: key, in: root)

        XCTAssertEqual(opened, created)
        XCTAssertEqual(opened.generation, 0)
        XCTAssertTrue(opened.entries.isEmpty)
        XCTAssertTrue(opened.tombstonedObjectNames.isEmpty)

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        XCTAssertTrue(V2OpaqueObjectName.isValid(anchorName))
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        let publicBytes = try Data(contentsOf: anchorURL)

        XCTAssertEqual(publicBytes.count, 4_096 + 8 + 24 + 16)
        XCTAssertNil(publicBytes.range(of: Data(accessID.uuidString.utf8)))
        let publicText = String(decoding: publicBytes, as: UTF8.self).lowercased()
        XCTAssertFalse(publicText.contains("reservebytes"))
        XCTAssertFalse(publicText.contains("accessid"))
    }

    func testDifferentMasterKeysCreateDifferentOpaqueMetadataAnchors() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 20_000, reserveBytes: 5_000)
        let keyA = Data(repeating: 0x42, count: 32)
        let keyB = Data(repeating: 0x43, count: 32)
        let store = V2AccessMetadataStore()

        _ = try store.createInitialEmpty(budget: budget, masterKey: keyA, in: root)
        _ = try store.createInitialEmpty(budget: budget, masterKey: keyB, in: root)

        let locator = V2StorageNamespaceLocator()
        let anchorA = try locator.indexObjectName(masterKey: keyA)
        let anchorB = try locator.indexObjectName(masterKey: keyB)
        XCTAssertNotEqual(anchorA, anchorB)
        XCTAssertTrue(fileManager.fileExists(
            atPath: V2StorageLayout.objectURL(named: anchorA, in: root).path
        ))
        XCTAssertTrue(fileManager.fileExists(
            atPath: V2StorageLayout.objectURL(named: anchorB, in: root).path
        ))
    }

    func testCreateNeverOverwritesExistingMetadataAnchor() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 5_000, reserveBytes: 1_000)
        let key = Data(repeating: 0x44, count: 32)
        let store = V2AccessMetadataStore()
        _ = try store.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        let before = try Data(contentsOf: anchorURL)

        XCTAssertThrowsError(
            try store.createInitialEmpty(budget: budget, masterKey: key, in: root)
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .anchorAlreadyExists)
        }
        XCTAssertEqual(try Data(contentsOf: anchorURL), before)
    }

    func testMissingAnchorIsReportedWithoutScanningOtherPoolObjects() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let store = V2AccessMetadataStore()
        XCTAssertThrowsError(
            try store.read(masterKey: Data(repeating: 0x45, count: 32), in: root)
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .metadataNotFound)
        }
    }

    func testPoolDirectorySymlinkIsRejectedDuringCreation() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let outside = try makeRoot()
        defer { try? fileManager.removeItem(at: outside) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createSymbolicLink(at: pool, withDestinationURL: outside)

        let store = V2AccessMetadataStore()
        let budget = try V2StorageBudget(totalBytes: 5_000, reserveBytes: 500)
        XCTAssertThrowsError(
            try store.createInitialEmpty(
                budget: budget,
                masterKey: Data(repeating: 0x46, count: 32),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .poolPathIsSymbolicLink)
        }
        XCTAssertTrue(try fileManager.contentsOfDirectory(atPath: outside.path).isEmpty)
    }

    func testMetadataAnchorSymlinkIsRejectedOnRead() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let outside = try makeRoot()
        defer { try? fileManager.removeItem(at: outside) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)
        let target = outside.appendingPathComponent("target")
        try Data("outside".utf8).write(to: target)

        let key = Data(repeating: 0x47, count: 32)
        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        try fileManager.createSymbolicLink(at: anchorURL, withDestinationURL: target)

        let store = V2AccessMetadataStore()
        XCTAssertThrowsError(try store.read(masterKey: key, in: root)) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectIsNotRegularFile)
        }
    }

    func testTamperedMetadataAnchorFailsAuthentication() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x48, count: 32)
        let budget = try V2StorageBudget(totalBytes: 5_000, reserveBytes: 500)
        let store = V2AccessMetadataStore()
        _ = try store.createInitialEmpty(budget: budget, masterKey: key, in: root)

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        var bytes = try Data(contentsOf: anchorURL)
        bytes[bytes.index(before: bytes.endIndex)] ^= 0x01
        try bytes.write(to: anchorURL, options: [.atomic])

        XCTAssertThrowsError(try store.read(masterKey: key, in: root)) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testObjectEncryptedForDifferentKeyAtExpectedAnchorFailsAuthentication() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let keyA = Data(repeating: 0x49, count: 32)
        let keyB = Data(repeating: 0x4A, count: 32)
        let budget = try V2StorageBudget(totalBytes: 5_000, reserveBytes: 500)
        let store = V2AccessMetadataStore()
        _ = try store.createInitialEmpty(budget: budget, masterKey: keyA, in: root)

        let locator = V2StorageNamespaceLocator()
        let source = V2StorageLayout.objectURL(
            named: try locator.indexObjectName(masterKey: keyA),
            in: root
        )
        let destination = V2StorageLayout.objectURL(
            named: try locator.indexObjectName(masterKey: keyB),
            in: root
        )
        try fileManager.copyItem(at: source, to: destination)

        XCTAssertThrowsError(try store.read(masterKey: keyB, in: root)) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
    }

    func testMetadataCiphertextCannotBeReboundToDifferentOpaqueNameUnderSameKey() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x4D, count: 32)
        let budget = try V2StorageBudget(totalBytes: 5_000, reserveBytes: 500)
        _ = try V2AccessMetadataStore().createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let otherName = String(repeating: "a", count: V2OpaqueObjectName.encodedLength)
        XCTAssertNotEqual(anchorName, otherName)
        let source = V2StorageLayout.objectURL(named: anchorName, in: root)
        let destination = V2StorageLayout.objectURL(named: otherName, in: root)
        try fileManager.copyItem(at: source, to: destination)

        XCTAssertThrowsError(
            try V2PoolObjectStore().readObject(
                named: otherName,
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }
        XCTAssertNoThrow(try V2AccessMetadataStore().read(masterKey: key, in: root))
    }

    func testAuthenticatedNonMetadataObjectAtAnchorIsRejected() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x4B, count: 32)
        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)
        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        let sealed = try V2PoolObjectCodec().seal(
            kind: .padding,
            content: Data(),
            masterKey: key,
            objectName: anchorName,
            paddedPlaintextByteCount: 4_096
        )
        try sealed.write(to: anchorURL)

        XCTAssertThrowsError(try V2AccessMetadataStore().read(masterKey: key, in: root)) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .unexpectedObjectKind)
        }
    }

    func testAuthenticatedMalformedMetadataPayloadIsRejected() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x4C, count: 32)
        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: true)
        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchorURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        let sealed = try V2PoolObjectCodec().seal(
            kind: .metadata,
            content: Data("not-json".utf8),
            masterKey: key,
            objectName: anchorName,
            paddedPlaintextByteCount: 4_096
        )
        try sealed.write(to: anchorURL)

        XCTAssertThrowsError(try V2AccessMetadataStore().read(masterKey: key, in: root)) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .malformedMetadata)
        }
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-access-metadata-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
