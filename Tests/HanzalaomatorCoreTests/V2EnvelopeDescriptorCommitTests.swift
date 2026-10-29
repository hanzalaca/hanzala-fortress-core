import XCTest
@testable import HanzalaomatorCore

final class V2EnvelopeDescriptorCommitTests: XCTestCase {
    private let fileManager = FileManager.default

    #if canImport(Darwin)
    func testDescriptorBoundEnvelopeWriteSucceedsAgainstCapturedRoot() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let committer = V2DescriptorBoundEnvelopeCommitter()
        let identity = try committer.captureRootIdentity(at: root)
        let payload = Data("public-envelope".utf8)

        try committer.writeNew(
            payload,
            in: root,
            expectedRootIdentity: identity
        )

        XCTAssertEqual(
            try Data(contentsOf: V2StorageLayout.accessEnvelopeURL(in: root)),
            payload
        )
    }

    func testRootReplacementBeforeEnvelopeRenameFailsClosed() throws {
        let root = try makeRoot()
        let displaced = root.deletingLastPathComponent().appendingPathComponent(
            "displaced-envelope-root-\(UUID().uuidString)",
            isDirectory: true
        )
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displaced)
        }

        let committer = V2DescriptorBoundEnvelopeCommitter()
        let identity = try committer.captureRootIdentity(at: root)
        let sentinel = Data("replacement-root-must-survive".utf8)
        let sentinelURL = root.appendingPathComponent("sentinel", isDirectory: false)

        committer.beforeNamespaceCommitHook = {
            try! self.fileManager.moveItem(at: root, to: displaced)
            try! self.fileManager.createDirectory(at: root, withIntermediateDirectories: false)
            try! sentinel.write(to: sentinelURL)
        }

        XCTAssertThrowsError(
            try committer.writeNew(
                Data("must-not-publish".utf8),
                in: root,
                expectedRootIdentity: identity
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DescriptorBoundEnvelopeCommitError,
                .rootNamespaceChanged
            )
        }

        XCTAssertEqual(try Data(contentsOf: sentinelURL), sentinel)
        XCTAssertFalse(fileManager.fileExists(
            atPath: V2StorageLayout.accessEnvelopeURL(in: root).path
        ))
        XCTAssertFalse(fileManager.fileExists(
            atPath: V2StorageLayout.accessEnvelopeURL(in: displaced).path
        ))
        XCTAssertTrue(
            try fileManager.contentsOfDirectory(atPath: displaced.path)
                .filter { $0.hasPrefix(".hanzala-v2-envelope-stage-") }
                .isEmpty
        )
    }

    func testBootstrapRootReplacementDoesNotCleanupReplacementDirectory() throws {
        let root = try makeRoot()
        try fileManager.removeItem(at: root)
        let displaced = root.deletingLastPathComponent().appendingPathComponent(
            "displaced-bootstrap-root-\(UUID().uuidString)",
            isDirectory: true
        )
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displaced)
        }

        let store = makeStore()
        let sentinel = Data("unrelated replacement contents".utf8)
        let sentinelURL = root.appendingPathComponent("sentinel", isDirectory: false)

        store.envelopeBeforeNamespaceCommitHook = {
            try! self.fileManager.moveItem(at: root, to: displaced)
            try! self.fileManager.createDirectory(at: root, withIntermediateDirectories: false)
            try! sentinel.write(to: sentinelURL)
        }

        XCTAssertThrowsError(
            try store.createVisibleOnly(
                at: root,
                password: "ordinary-password",
                budget: V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000),
                vaultID: UUID(uuidString: "6A000000-0000-0000-0000-000000000001")!,
                createdAt: Date(timeIntervalSince1970: 1_700_200_000)
            )
        ) { error in
            XCTAssertEqual(
                error as? V2VaultBootstrapStoreError,
                .envelopeCommitFailed
            )
        }

        // Pathname-based rollback must not run against the substituted root.
        XCTAssertEqual(try Data(contentsOf: sentinelURL), sentinel)
        XCTAssertEqual(
            Set(try fileManager.contentsOfDirectory(atPath: root.path)),
            Set(["sentinel"])
        )

        // The displaced original contains only encrypted private bootstrap state.
        // No public envelope was committed because the root identity check failed
        // before the final descriptor-relative rename.
        XCTAssertFalse(fileManager.fileExists(
            atPath: V2StorageLayout.accessEnvelopeURL(in: displaced).path
        ))
        let pool = V2StorageLayout.poolURL(in: displaced)
        XCTAssertTrue(fileManager.fileExists(atPath: pool.path))
        XCTAssertEqual(
            try fileManager.contentsOfDirectory(
                at: pool,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ).filter {
                (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
            }.count,
            4
        )
    }
    #endif

    private func makeStore() -> V2VaultBootstrapStore {
        let keyEngine = PasswordKeyEngine()
        let envelopeEngine = DualAccessEnvelopeEngine(
            keyEngine: keyEngine,
            makeParameters: {
                try keyEngine.makeParameters(
                    operationsLimit: 2,
                    memoryLimit: 32 * 1024 * 1024
                )
            }
        )
        return V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: V2AccessMetadataStore(fileManager: fileManager)
        )
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hz-envelope-descriptor-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }
}
