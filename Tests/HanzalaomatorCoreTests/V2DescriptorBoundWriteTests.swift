import XCTest
@testable import HanzalaomatorCore

final class V2DescriptorBoundWriteTests: XCTestCase {
    private let fileManager = FileManager.default

    func testNormalExactNameCreationPublishesAuthenticatedObject() throws {
        let root = try makeRootWithPool()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xE1, count: 32)
        let objectName = String(repeating: "1", count: V2OpaqueObjectName.encodedLength)
        let content = Data("descriptor-bound ciphertext publication".utf8)
        let store = V2PoolObjectStore(fileManager: fileManager)

        let reference = try store.createObject(
            named: objectName,
            kind: .data,
            content: content,
            masterKey: key,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        XCTAssertEqual(reference.opaqueName, objectName)
        let object = try store.readObject(
            named: objectName,
            masterKey: key,
            in: root
        )
        XCTAssertEqual(object.kind, .data)
        XCTAssertEqual(object.content, content)
    }

    func testDestinationCreatedAfterStagingSyncIsPreservedAndReportedAsCollision() throws {
        #if canImport(Darwin)
        let root = try makeRootWithPool()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xE2, count: 32)
        let objectName = String(repeating: "2", count: V2OpaqueObjectName.encodedLength)
        let destination = V2StorageLayout.objectURL(named: objectName, in: root)
        let foreignBytes = Data("foreign namespace entry".utf8)
        var injected = false

        let committer = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, target in
                if !injected,
                   point == .afterStagingSync,
                   target.lastPathComponent == objectName {
                    injected = true
                    try foreignBytes.write(to: destination)
                }
            }
        )
        let store = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: committer
        )

        XCTAssertThrowsError(
            try store.createObject(
                named: objectName,
                kind: .data,
                content: Data("owned bytes".utf8),
                masterKey: key,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .objectAlreadyExists)
        }

        XCTAssertTrue(injected)
        XCTAssertEqual(try Data(contentsOf: destination), foreignBytes)
        XCTAssertTrue(try stagingNames(in: V2StorageLayout.poolURL(in: root)).isEmpty)
        #endif
    }

    func testPublicPoolReplacementAfterStagingSyncFailsClosedAndLeavesReplacementPoolUntouched() throws {
        #if canImport(Darwin)
        let root = try makeRootWithPool()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xE3, count: 32)
        let objectName = String(repeating: "3", count: V2OpaqueObjectName.encodedLength)
        let pool = V2StorageLayout.poolURL(in: root)
        let detachedPool = root.appendingPathComponent(
            "objects-detached-\(UUID().uuidString)",
            isDirectory: true
        )
        let sentinel = Data("replacement pool sentinel".utf8)
        let sentinelURL = pool.appendingPathComponent("sentinel.bin")
        var injected = false

        let committer = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, target in
                if !injected,
                   point == .afterStagingSync,
                   target.lastPathComponent == objectName {
                    injected = true
                    try self.fileManager.moveItem(at: pool, to: detachedPool)
                    try self.fileManager.createDirectory(
                        at: pool,
                        withIntermediateDirectories: false
                    )
                    try sentinel.write(to: sentinelURL)
                }
            }
        )
        let store = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: committer
        )

        XCTAssertThrowsError(
            try store.createObject(
                named: objectName,
                kind: .data,
                content: Data("owned bytes".utf8),
                masterKey: key,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .commitFailed)
        }

        XCTAssertTrue(injected)
        XCTAssertEqual(try Data(contentsOf: sentinelURL), sentinel)
        XCTAssertFalse(
            fileManager.fileExists(
                atPath: pool.appendingPathComponent(objectName).path
            )
        )
        XCTAssertFalse(
            fileManager.fileExists(
                atPath: detachedPool.appendingPathComponent(objectName).path
            )
        )
        XCTAssertTrue(try stagingNames(in: detachedPool).isEmpty)
        #endif
    }

    func testStagingPathReplacementBeforePublishFailsClosedWithoutDeletingSubstitute() throws {
        #if canImport(Darwin)
        let root = try makeRootWithPool()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0xE4, count: 32)
        let objectName = String(repeating: "4", count: V2OpaqueObjectName.encodedLength)
        let pool = V2StorageLayout.poolURL(in: root)
        let destination = V2StorageLayout.objectURL(named: objectName, in: root)
        let substitute = Data("attacker staging substitute".utf8)
        var substitutedStagingURL: URL?
        var savedOriginalURL: URL?
        var injected = false

        let committer = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { try $0.synchronize() },
            faultInjector: { point, target in
                guard !injected,
                      point == .afterStagingSync,
                      target.lastPathComponent == objectName else { return }
                injected = true

                let names = try self.stagingNames(in: pool)
                let stagingName = try XCTUnwrap(names.first)
                let staging = pool.appendingPathComponent(stagingName)
                let saved = pool.appendingPathComponent(
                    ".saved-owned-stage-\(UUID().uuidString)"
                )
                try self.fileManager.moveItem(at: staging, to: saved)
                try substitute.write(to: staging)
                substitutedStagingURL = staging
                savedOriginalURL = saved
            }
        )
        let store = V2PoolObjectStore(
            fileManager: fileManager,
            durableCommitter: committer
        )

        XCTAssertThrowsError(
            try store.createObject(
                named: objectName,
                kind: .data,
                content: Data("owned bytes".utf8),
                masterKey: key,
                in: root,
                paddedPlaintextByteCount: 4 * 1024
            )
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectStoreError, .commitFailed)
        }

        XCTAssertTrue(injected)
        XCTAssertFalse(fileManager.fileExists(atPath: destination.path))
        let substituteURL = try XCTUnwrap(substitutedStagingURL)
        let originalURL = try XCTUnwrap(savedOriginalURL)
        XCTAssertEqual(try Data(contentsOf: substituteURL), substitute)
        XCTAssertTrue(fileManager.fileExists(atPath: originalURL.path))
        #endif
    }

    private func makeRootWithPool() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-descriptor-write-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        try fileManager.createDirectory(
            at: V2StorageLayout.poolURL(in: root),
            withIntermediateDirectories: false
        )
        return root
    }

    private func stagingNames(in directory: URL) throws -> [String] {
        try fileManager.contentsOfDirectory(atPath: directory.path)
            .filter { $0.hasPrefix(".hanzala-v2-stage-") }
            .sorted()
    }
}
