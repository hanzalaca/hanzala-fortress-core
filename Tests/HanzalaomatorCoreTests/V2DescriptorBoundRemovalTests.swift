import XCTest
@testable import HanzalaomatorCore

final class V2DescriptorBoundRemovalTests: XCTestCase {
    private let fileManager = FileManager.default

    func testObjectNameReplacementAfterAuthenticationFailsClosedAndPreservesReplacement() throws {
        #if canImport(Darwin)
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xD1, count: 32)
        let objectName = String(repeating: "a", count: V2OpaqueObjectName.encodedLength)
        let owned = Data("authenticated owned bytes".utf8)
        let replacement = Data("substituted foreign bytes".utf8)
        let store = V2PoolObjectStore(fileManager: fileManager)

        _ = try store.createObject(
            named: objectName,
            kind: .data,
            content: owned,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        let pool = V2StorageLayout.poolURL(in: root)
        let target = V2StorageLayout.objectURL(named: objectName, in: root)
        let savedOriginal = pool.appendingPathComponent(".saved-original-\(UUID().uuidString)")
        let preparedReplacement = pool.appendingPathComponent(".prepared-replacement-\(UUID().uuidString)")
        let replacementCiphertext = try V2PoolObjectCodec().seal(
            kind: .data,
            content: replacement,
            masterKey: key,
            objectName: objectName,
            paddedPlaintextByteCount: 4 * 1024
        )
        try replacementCiphertext.write(to: preparedReplacement)

        var hookRan = false
        store.authenticatedDeleteReadyHook = { name in
            XCTAssertEqual(name, objectName)
            hookRan = true
            try! self.fileManager.moveItem(at: target, to: savedOriginal)
            try! self.fileManager.moveItem(at: preparedReplacement, to: target)
        }

        XCTAssertThrowsError(
            try store.deleteAuthenticatedObject(
                named: objectName,
                masterKey: key,
                expectedKind: .data,
                expectedLogicalByteCount: UInt64(owned.count),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectDeleteFailed)
        }

        XCTAssertTrue(hookRan)
        XCTAssertTrue(fileManager.fileExists(atPath: savedOriginal.path))
        XCTAssertTrue(fileManager.fileExists(atPath: target.path))

        let stillCurrent = try V2PoolObjectStore(fileManager: fileManager).readObject(
            named: objectName,
            masterKey: key,
            in: root
        )
        XCTAssertEqual(stillCurrent.kind, .data)
        XCTAssertEqual(stillCurrent.content, replacement)
        #endif
    }

    func testPoolDirectoryReplacementAfterAuthenticationFailsClosedWithoutDeletingEitherTree() throws {
        #if canImport(Darwin)
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xD2, count: 32)
        let objectName = String(repeating: "b", count: V2OpaqueObjectName.encodedLength)
        let owned = Data("owned pool object".utf8)
        let replacement = Data("replacement pool object".utf8)
        let store = V2PoolObjectStore(fileManager: fileManager)

        _ = try store.createObject(
            named: objectName,
            kind: .data,
            content: owned,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        let pool = V2StorageLayout.poolURL(in: root)
        let detachedPool = root.appendingPathComponent("objects-detached-\(UUID().uuidString)", isDirectory: true)
        let replacementCiphertext = try V2PoolObjectCodec().seal(
            kind: .data,
            content: replacement,
            masterKey: key,
            objectName: objectName,
            paddedPlaintextByteCount: 4 * 1024
        )

        var hookRan = false
        store.authenticatedDeleteReadyHook = { _ in
            hookRan = true
            try! self.fileManager.moveItem(at: pool, to: detachedPool)
            try! self.fileManager.createDirectory(at: pool, withIntermediateDirectories: false)
            try! replacementCiphertext.write(
                to: pool.appendingPathComponent(objectName, isDirectory: false)
            )
        }

        XCTAssertThrowsError(
            try store.deleteAuthenticatedObject(
                named: objectName,
                masterKey: key,
                expectedKind: .data,
                expectedLogicalByteCount: UInt64(owned.count),
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectDeleteFailed)
        }

        XCTAssertTrue(hookRan)
        XCTAssertTrue(
            fileManager.fileExists(
                atPath: detachedPool.appendingPathComponent(objectName).path
            )
        )
        XCTAssertTrue(
            fileManager.fileExists(
                atPath: pool.appendingPathComponent(objectName).path
            )
        )

        let current = try V2PoolObjectStore(fileManager: fileManager).readObject(
            named: objectName,
            masterKey: key,
            in: root
        )
        XCTAssertEqual(current.content, replacement)
        #endif
    }

    func testNormalDescriptorBoundDeletionStillRemovesAuthenticatedObject() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xD3, count: 32)
        let objectName = String(repeating: "c", count: V2OpaqueObjectName.encodedLength)
        let content = Data("remove normally".utf8)
        let store = V2PoolObjectStore(fileManager: fileManager)

        _ = try store.createObject(
            named: objectName,
            kind: .data,
            content: content,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        try store.deleteAuthenticatedObject(
            named: objectName,
            masterKey: key,
            expectedKind: .data,
            expectedLogicalByteCount: UInt64(content.count),
            in: root
        )

        XCTAssertFalse(
            fileManager.fileExists(
                atPath: V2StorageLayout.objectURL(named: objectName, in: root).path
            )
        )
        XCTAssertNoThrow(
            try store.confirmAuthenticatedObjectAbsenceDurably(
                named: objectName,
                in: root
            )
        )
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-descriptor-removal-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        return root
    }
}
