import XCTest
@testable import HanzalaomatorCore

final class V2MetadataDescriptorCommitTests: XCTestCase {
    private let fileManager = FileManager.default

    #if canImport(Darwin)
    func testDescriptorBoundMetadataTransitionSucceeds() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x91, count: 32)
        let store = V2AccessMetadataStore(fileManager: fileManager)
        let current = try store.createInitialEmpty(
            budget: try budget(),
            masterKey: key,
            in: root
        )
        let next = try current.beginningImport(pending(name: opaque("a")))

        try store.commitTransition(
            from: current,
            to: next,
            masterKey: key,
            in: root
        )

        XCTAssertEqual(try store.read(masterKey: key, in: root), next)
    }

    func testAnchorReplacementBeforeRenameFailsClosedAndPreservesReplacement() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x92, count: 32)
        let store = V2AccessMetadataStore(fileManager: fileManager)
        let current = try store.createInitialEmpty(
            budget: try budget(),
            masterKey: key,
            in: root
        )
        let next = try current.beginningImport(pending(name: opaque("b")))

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let anchor = V2StorageLayout.objectURL(named: anchorName, in: root)
        let displaced = V2StorageLayout.poolURL(in: root)
            .appendingPathComponent("displaced-metadata", isDirectory: false)
        let replacement = Data("attacker replacement must survive".utf8)

        store.metadataBeforeNamespaceCommitHook = {
            try! self.fileManager.moveItem(at: anchor, to: displaced)
            try! replacement.write(to: anchor)
        }

        XCTAssertThrowsError(
            try store.commitTransition(
                from: current,
                to: next,
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .commitFailed)
        }

        XCTAssertEqual(try Data(contentsOf: anchor), replacement)
        XCTAssertTrue(fileManager.fileExists(atPath: displaced.path))
        let staging = try fileManager.contentsOfDirectory(
            atPath: V2StorageLayout.poolURL(in: root).path
        ).filter { $0.hasPrefix(".hanzala-v2-metadata-stage-") }
        XCTAssertTrue(staging.isEmpty)
    }

    func testPoolReplacementBeforeRenameFailsClosedAndDoesNotWriteIntoReplacementPool() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let key = Data(repeating: 0x93, count: 32)
        let store = V2AccessMetadataStore(fileManager: fileManager)
        let current = try store.createInitialEmpty(
            budget: try budget(),
            masterKey: key,
            in: root
        )
        let next = try current.beginningImport(pending(name: opaque("c")))

        let pool = V2StorageLayout.poolURL(in: root)
        let displacedPool = root.appendingPathComponent("objects-displaced", isDirectory: true)
        let sentinelName = "sentinel"
        let sentinelData = Data("replacement pool".utf8)

        store.metadataBeforeNamespaceCommitHook = {
            try! self.fileManager.moveItem(at: pool, to: displacedPool)
            try! self.fileManager.createDirectory(
                at: pool,
                withIntermediateDirectories: false
            )
            try! sentinelData.write(
                to: pool.appendingPathComponent(sentinelName, isDirectory: false)
            )
        }

        XCTAssertThrowsError(
            try store.commitTransition(
                from: current,
                to: next,
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataStoreError, .commitFailed)
        }

        XCTAssertEqual(
            try Data(contentsOf: pool.appendingPathComponent(sentinelName)),
            sentinelData
        )
        XCTAssertEqual(
            Set(try fileManager.contentsOfDirectory(atPath: pool.path)),
            Set([sentinelName])
        )

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(masterKey: key)
        let displacedAnchor = displacedPool.appendingPathComponent(anchorName)
        XCTAssertTrue(fileManager.fileExists(atPath: displacedAnchor.path))
        let staleStages = try fileManager.contentsOfDirectory(atPath: displacedPool.path)
            .filter { $0.hasPrefix(".hanzala-v2-metadata-stage-") }
        XCTAssertTrue(staleStages.isEmpty)
    }
    #endif

    private func pending(name: String) -> V2PendingImport {
        V2PendingImport(
            transactionID: UUID(),
            opaqueObjectName: name,
            originalName: "test.bin",
            logicalByteCount: 1,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func budget() throws -> V2StorageBudget {
        try V2StorageBudget(
            totalBytes: 64 * 1024 * 1024,
            reserveBytes: 4 * 1024 * 1024
        )
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hz-metadata-descriptor-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }
}
