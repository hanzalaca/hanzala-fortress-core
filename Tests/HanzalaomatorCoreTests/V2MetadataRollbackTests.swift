import XCTest
@testable import HanzalaomatorCore

/// Audit lead `v2-metadata-anchor-rollback-undetected` (Docs/security/AUDIT-2026-11-19.md):
/// someone who can write to the vault folder puts back an older, authentic
/// metadata anchor. With a device watermark the session store must notice.
final class V2MetadataRollbackTests: XCTestCase {
    private let fileManager = FileManager.default
    private let password = "ordinary-password"

    func testWithoutWatermarkStoreOlderAnchorIsStillAcceptedAsBefore() throws {
        let fixture = try makeRolledBackVault(watermark: nil)
        defer { try? fileManager.removeItem(at: fixture.root) }

        // Documents the audited behavior that the watermark exists to stop.
        let reopened = try fixture.sessions.openSession(at: fixture.root, password: password)
        XCTAssertEqual(
            try fixture.sessions.listEntries(in: reopened.session).map(\.id),
            [fixture.firstEntry]
        )
    }

    func testOlderAnchorIsRefusedOnPasswordOpen() throws {
        let watermark = V2InMemoryMetadataWatermarkStore()
        let fixture = try makeRolledBackVault(watermark: watermark)
        defer { try? fileManager.removeItem(at: fixture.root) }

        XCTAssertThrowsError(
            try fixture.sessions.openSession(at: fixture.root, password: password)
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .olderCopyDetected)
        }
    }

    func testOlderAnchorIsRefusedOnRecoveryKeyOpen() throws {
        let watermark = V2InMemoryMetadataWatermarkStore()
        let fixture = try makeRolledBackVault(watermark: watermark)
        defer { try? fileManager.removeItem(at: fixture.root) }

        let coordinator = V2RecoverySessionCoordinator(
            bootstrapStore: fixture.bootstrap,
            sessionStore: fixture.sessions
        )
        XCTAssertThrowsError(
            try coordinator.openSession(at: fixture.root, recoveryKey: fixture.recoveryKey)
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .olderCopyDetected)
        }

        let accepted = try coordinator.openSession(
            at: fixture.root,
            recoveryKey: fixture.recoveryKey,
            acceptingOlderCopy: true
        )
        XCTAssertEqual(
            try fixture.sessions.listEntries(in: accepted.session).map(\.id),
            [fixture.firstEntry]
        )
    }

    func testOwnerCanOpenOlderCopyOnPurposeAndItBecomesTheReference() throws {
        let watermark = V2InMemoryMetadataWatermarkStore()
        let fixture = try makeRolledBackVault(watermark: watermark)
        defer { try? fileManager.removeItem(at: fixture.root) }

        let accepted = try fixture.sessions.openSession(
            at: fixture.root,
            password: password,
            acceptingOlderCopy: true
        )
        XCTAssertEqual(
            try fixture.sessions.listEntries(in: accepted.session).map(\.id),
            [fixture.firstEntry]
        )

        // From now on the older copy opens normally and can be changed.
        let reopened = try fixture.sessions.openSession(at: fixture.root, password: password)
        _ = try fixture.sessions.importData(
            Data("after restore".utf8),
            originalName: "c.txt",
            into: reopened.session
        )
        XCTAssertEqual(try fixture.sessions.listEntries(in: reopened.session).count, 2)
    }

    func testOlderAnchorPutBackWhileOpenIsRefusedOnNextRead() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores(watermark: V2InMemoryMetadataWatermarkStore())
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: password, budget: try budget())

        let session = try stores.sessions.openSession(at: root, password: password).session
        _ = try stores.sessions.importData(Data("a".utf8), originalName: "a.txt", into: session)
        let anchor = try anchorURL(for: session)
        let saved = try Data(contentsOf: anchor)
        _ = try stores.sessions.importData(Data("b".utf8), originalName: "b.txt", into: session)

        try saved.write(to: anchor)

        XCTAssertThrowsError(try stores.sessions.listEntries(in: session)) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .olderCopyDetected)
        }
    }

    func testRestoringAnchorFromBeforeFixedCapacityIsRefused() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores(watermark: V2InMemoryMetadataWatermarkStore())
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: password,
            budget: try V2StorageBudget(totalBytes: 1024 * 1024 * 1024, reserveBytes: 1024 * 1024)
        )

        let session = try stores.sessions.openSession(at: root, password: password).session
        let anchor = try anchorURL(for: session)
        let beforeFill = try Data(contentsOf: anchor)
        try stores.sessions.prepareFixedCapacity(
            capacityBytes: V2FixedCapacityPlan.minimumCapacityBytes,
            in: session
        )
        XCTAssertNotNil(try stores.sessions.fixedCapacityStatus(in: session))

        try beforeFill.write(to: anchor)

        XCTAssertThrowsError(try stores.sessions.fixedCapacityStatus(in: session)) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .olderCopyDetected)
        }
    }

    func testWatermarkKeyIsOpaqueAndDiffersFromVaultObjectNames() throws {
        let guardian = V2MetadataWatermarkGuard(store: V2InMemoryMetadataWatermarkStore())
        let masterKey = Data(repeating: 7, count: 32)
        let vaultID = UUID()
        let accessID = UUID()

        let key = try guardian.key(masterKey: masterKey, vaultID: vaultID, accessID: accessID)
        XCTAssertEqual(key.count, 64)
        XCTAssertEqual(key, try guardian.key(masterKey: masterKey, vaultID: vaultID, accessID: accessID))
        XCTAssertNotEqual(key, try V2StorageNamespaceLocator().indexObjectName(masterKey: masterKey))
        XCTAssertNotEqual(key, try guardian.key(masterKey: masterKey, vaultID: UUID(), accessID: accessID))
    }

    func testUnavailableWatermarkStoreNeverLocksTheOwnerOut() throws {
        let fixture = try makeRolledBackVault(watermark: FailingWatermarkStore())
        defer { try? fileManager.removeItem(at: fixture.root) }

        // A fresh app launch: nothing could be stored, so nothing is compared.
        // (The same process still remembers the newer generation in memory.)
        let relaunched = makeStores(watermark: FailingWatermarkStore())
        XCTAssertNoThrow(try relaunched.sessions.openSession(at: fixture.root, password: password))
    }

    // MARK: - Fixture

    private struct RolledBackVault {
        let root: URL
        let bootstrap: V2VaultBootstrapStore
        let sessions: V2VaultSessionStore
        let recoveryKey: String
        let firstEntry: UUID
    }

    /// Imports A, saves the anchor, imports B, puts the saved anchor back.
    private func makeRolledBackVault(watermark: V2MetadataWatermarkStore?) throws -> RolledBackVault {
        let root = try makeRoot()
        let stores = makeStores(watermark: watermark)
        let created = try stores.bootstrap.createVisibleOnly(at: root, password: password, budget: try budget())
        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)

        let session = try stores.sessions.openSession(at: root, password: password).session
        let first = try stores.sessions.importData(Data("first".utf8), originalName: "a.txt", into: session)
        let anchor = try anchorURL(for: session)
        let saved = try Data(contentsOf: anchor)
        _ = try stores.sessions.importData(Data("second".utf8), originalName: "b.txt", into: session)
        XCTAssertEqual(try stores.sessions.listEntries(in: session).count, 2)

        try saved.write(to: anchor)

        return RolledBackVault(
            root: root,
            bootstrap: stores.bootstrap,
            sessions: stores.sessions,
            recoveryKey: recoveryKey,
            firstEntry: first.id
        )
    }

    private func anchorURL(for session: V2VaultSession) throws -> URL {
        try V2StorageNamespaceLocator().indexURL(masterKey: session.masterKey, in: session.root)
    }

    private func budget() throws -> V2StorageBudget {
        try V2StorageBudget(totalBytes: 16 * 1024 * 1024, reserveBytes: 2 * 1024 * 1024)
    }

    private func makeStores(
        watermark: V2MetadataWatermarkStore?
    ) -> (bootstrap: V2VaultBootstrapStore, sessions: V2VaultSessionStore) {
        let keyEngine = PasswordKeyEngine()
        let envelopeEngine = DualAccessEnvelopeEngine(
            keyEngine: keyEngine,
            makeParameters: {
                try keyEngine.makeParameters(operationsLimit: 2, memoryLimit: 32 * 1024 * 1024)
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
            objectStore: objects,
            metadataWatermarkStore: watermark
        )
        return (bootstrap, sessions)
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-rollback-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        // The bootstrap store creates the vault folder itself.
        XCTAssertFalse(fileManager.fileExists(atPath: url.path))
        return url
    }
}

private final class FailingWatermarkStore: V2MetadataWatermarkStore {
    func generation(forKey key: String) throws -> UInt64? {
        throw V2MetadataWatermarkStoreError.unavailable(-1)
    }

    func setGeneration(_ generation: UInt64, forKey key: String) throws {
        throw V2MetadataWatermarkStoreError.unavailable(-1)
    }
}
