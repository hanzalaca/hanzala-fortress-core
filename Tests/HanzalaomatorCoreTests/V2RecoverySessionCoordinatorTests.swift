import XCTest
@testable import HanzalaomatorCore

final class V2RecoverySessionCoordinatorTests: XCTestCase {
    private let fileManager = FileManager.default

    func testVisibleRecoveryKeyOpensStandardUsableSession() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 2 * 1024 * 1024, reserveBytes: 256 * 1024)
        let created = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)

        let passwordOpened = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        )
        let entry = try stores.sessions.importData(
            Data("recoverable newsroom evidence".utf8),
            originalName: "evidence.txt",
            into: passwordOpened.session
        )

        let recovered = try stores.recovery.openSession(
            at: root,
            recoveryKey: recoveryKey
        )

        XCTAssertEqual(recovered.session.role, .visible)
        XCTAssertEqual(recovered.session.accessID, passwordOpened.session.accessID)
        XCTAssertEqual(recovered.recovery.imports, V2PendingImportRecoveryReport())
        XCTAssertEqual(recovered.recovery.chunkImports, V2PendingChunkImportRecoveryReport())
        XCTAssertEqual(recovered.recovery.removals, V2PendingRemovalRecoveryReport())
        XCTAssertEqual(try stores.sessions.listEntries(in: recovered.session).map(\.id), [entry.id])

        let read = try stores.sessions.readEntry(id: entry.id, in: recovered.session)
        XCTAssertEqual(read.data, Data("recoverable newsroom evidence".utf8))
    }

    func testConcealedRecoverySessionCannotSeeVisibleEntries() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 4 * 1024 * 1024, reserveBytes: 512 * 1024)
        let created = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget
        )
        let concealedRecoveryKey = try XCTUnwrap(created.concealedRecoveryKey)

        let visible = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        )
        let visibleEntry = try stores.sessions.importData(
            Data("public decoy file".utf8),
            originalName: "ordinary.txt",
            into: visible.session
        )

        let concealed = try stores.sessions.openSession(
            at: root,
            password: "source-protection-password"
        )
        let concealedEntry = try stores.sessions.importData(
            Data("protected source file".utf8),
            originalName: "source.txt",
            into: concealed.session
        )

        let recovered = try stores.recovery.openSession(
            at: root,
            recoveryKey: concealedRecoveryKey
        )
        XCTAssertEqual(recovered.session.role, .concealed)
        XCTAssertEqual(recovered.session.accessID, concealed.session.accessID)

        let ids = Set(try stores.sessions.listEntries(in: recovered.session).map(\.id))
        XCTAssertEqual(ids, Set([concealedEntry.id]))
        XCTAssertFalse(ids.contains(visibleEntry.id))
        XCTAssertEqual(
            try stores.sessions.readEntry(id: concealedEntry.id, in: recovered.session).data,
            Data("protected source file".utf8)
        )
    }

    func testRecoverySessionRunsPendingImportRecoveryBeforePublication() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 2 * 1024 * 1024, reserveBytes: 256 * 1024)
        let created = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)
        let transactionID = UUID(uuidString: "A1000000-0000-0000-0000-000000000001")!

        let current = try stores.metadata.read(
            masterKey: created.visibleMasterKey,
            in: root
        )
        let pending = V2PendingImport(
            transactionID: transactionID,
            opaqueObjectName: String(repeating: "a", count: V2OpaqueObjectName.encodedLength),
            originalName: "interrupted.txt",
            logicalByteCount: 16,
            createdAt: Date(timeIntervalSince1970: 1_700_300_000)
        )
        let claimed = try current.beginningImport(pending)
        try stores.metadata.commitTransition(
            from: current,
            to: claimed,
            masterKey: created.visibleMasterKey,
            in: root
        )

        let opened = try stores.recovery.openSession(
            at: root,
            recoveryKey: recoveryKey
        )

        XCTAssertEqual(
            opened.recovery.imports.abortedMissingObjectTransactionIDs,
            [transactionID]
        )
        XCTAssertTrue(opened.recovery.imports.finalizedTransactionIDs.isEmpty)
        XCTAssertTrue(try stores.sessions.listEntries(in: opened.session).isEmpty)

        let after = try stores.metadata.read(
            masterKey: created.visibleMasterKey,
            in: root
        )
        XCTAssertTrue(after.pendingImports.isEmpty)
    }

    func testWrongRecoveryKeyKeepsGenericFailureAndPublishesNoSession() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 2 * 1024 * 1024, reserveBytes: 256 * 1024)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )

        XCTAssertThrowsError(
            try stores.recovery.openSession(
                at: root,
                recoveryKey: RecoveryKeyEngine().generateRecoveryKey()
            )
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }
    }

    private struct Stores {
        let bootstrap: V2VaultBootstrapStore
        let metadata: V2AccessMetadataStore
        let sessions: V2VaultSessionStore
        let recovery: V2RecoverySessionCoordinator
    }

    private func makeStores() -> Stores {
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
        let metadata = V2AccessMetadataStore(fileManager: fileManager)
        let objects = V2PoolObjectStore(fileManager: fileManager)
        let bootstrap = V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: metadata
        )
        let sessions = V2VaultSessionStore(
            bootstrapStore: bootstrap,
            metadataStore: metadata,
            objectStore: objects
        )
        let recovery = V2RecoverySessionCoordinator(
            bootstrapStore: bootstrap,
            sessionStore: sessions
        )
        return Stores(
            bootstrap: bootstrap,
            metadata: metadata,
            sessions: sessions,
            recovery: recovery
        )
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-recovery-session-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        try fileManager.removeItem(at: root)
        return root
    }
}
