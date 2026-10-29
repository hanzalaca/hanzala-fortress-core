import XCTest
@testable import HanzalaomatorCore

/// Changing a v2 password rewrites only the visible slot of the public
/// envelope. Files, metadata and the Recovery Key must keep working, the old
/// password must stop working, and a stale or racing change must fail closed.
final class V2PasswordChangeTests: XCTestCase {
    private let fileManager = FileManager.default

    func testChangedPasswordOpensTheSameFilesAndTheOldOneStopsWorking() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let created = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "old-password-123",
            budget: try budget()
        )
        let before = try stores.bootstrap.readEnvelope(at: root)

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "old-password-123")
        let entry = try importNote(into: lifecycle, root: root)

        try lifecycle.changePassword(to: "new-password-456")

        // The open session keeps working with the new envelope.
        XCTAssertEqual(try lifecycle.listEntries().map(\.id), [entry.id])
        XCTAssertEqual(
            try lifecycle.readEntryRange(id: entry.id, offset: 0, length: 9),
            Data("protected".utf8)
        )
        lifecycle.lock()

        XCTAssertThrowsError(try lifecycle.open(at: root, password: "old-password-123")) { error in
            XCTAssertEqual(error as? DualAccessEnvelopeError, .invalidPasswordOrCorruptedEnvelope)
        }
        _ = try lifecycle.open(at: root, password: "new-password-456")
        XCTAssertEqual(try lifecycle.listEntries().map(\.id), [entry.id])
        lifecycle.lock()

        // The Recovery Key is untouched.
        _ = try lifecycle.openRecovery(at: root, recoveryKey: try XCTUnwrap(created.visibleRecoveryKey))
        XCTAssertEqual(try lifecycle.listEntries().map(\.id), [entry.id])
        lifecycle.lock()

        // Only the visible slot changed; identity and the second slot did not.
        let after = try stores.bootstrap.readEnvelope(at: root)
        XCTAssertEqual(after.vaultID, before.vaultID)
        XCTAssertEqual(after.createdAt, before.createdAt)
        XCTAssertEqual(after.accessSlots.count, DualAccessEnvelopeV2.fixedSlotCount)
        XCTAssertNotEqual(after.accessSlots[0].wrappedPayload, before.accessSlots[0].wrappedPayload)
        XCTAssertNotEqual(after.accessSlots[0].kdf.salt, before.accessSlots[0].kdf.salt)
        XCTAssertEqual(after.accessSlots[1].wrappedPayload, before.accessSlots[1].wrappedPayload)
        XCTAssertEqual(after.accessSlots[1].kdf.salt, before.accessSlots[1].kdf.salt)
    }

    func testRecoveryOpenedSessionCanSetANewPassword() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let created = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "forgotten-password",
            budget: try budget()
        )

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.openRecovery(at: root, recoveryKey: try XCTUnwrap(created.visibleRecoveryKey))
        try lifecycle.changePassword(to: "remembered-password")
        lifecycle.lock()

        _ = try lifecycle.open(at: root, password: "remembered-password")
        XCTAssertTrue(lifecycle.isUnlocked)
        lifecycle.lock()
        XCTAssertThrowsError(try lifecycle.open(at: root, password: "forgotten-password"))
    }

    func testChangeRevokesFinderLeasesBoundToTheOldEnvelope() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: "old-password-123", budget: try budget())

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "old-password-123")
        let lease = try lifecycle.makeFinderLease()
        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 1)

        try lifecycle.changePassword(to: "new-password-456")

        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 0)
        XCTAssertThrowsError(try lease.session.listRoot()) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
        }
        // A fresh lease works against the new envelope.
        _ = try lifecycle.makeFinderLease()
        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 1)
        lifecycle.lock()
    }

    func testStaleSessionCannotOverwriteANewerPasswordChange() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: "old-password-123", budget: try budget())

        let first = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        let second = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try first.open(at: root, password: "old-password-123")
        _ = try second.open(at: root, password: "old-password-123")

        try first.changePassword(to: "first-new-password")
        let afterFirst = try stores.bootstrap.readEnvelope(at: root)

        XCTAssertThrowsError(try second.changePassword(to: "second-new-password")) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .envelopeIdentityChanged)
        }
        let afterSecond = try stores.bootstrap.readEnvelope(at: root)
        XCTAssertEqual(afterSecond.accessSlots[0].wrappedPayload, afterFirst.accessSlots[0].wrappedPayload)

        first.lock()
        second.lock()
        _ = try first.open(at: root, password: "first-new-password")
        first.lock()
    }

    func testBootstrapRefusesAnEnvelopeBindingThatNoLongerMatches() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        let created = try stores.bootstrap.createVisibleOnly(at: root, password: "old-password-123", budget: try budget())

        XCTAssertThrowsError(
            try stores.bootstrap.replaceVisiblePassword(
                at: root,
                masterKey: created.visibleMasterKey,
                expectedEnvelopeBinding: Data("not the envelope".utf8),
                newPassword: "new-password-456"
            )
        ) { error in
            XCTAssertEqual(error as? V2VaultBootstrapStoreError, .envelopeChangedDuringPasswordChange)
        }
        _ = try stores.sessions.openSession(at: root, password: "old-password-123")
    }

    func testEmptyNewPasswordIsRefusedAndNothingChanges() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createVisibleOnly(at: root, password: "old-password-123", budget: try budget())
        let before = try stores.bootstrap.readEnvelope(at: root)

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "old-password-123")
        XCTAssertThrowsError(try lifecycle.changePassword(to: "")) { error in
            XCTAssertEqual(error as? V2VaultBootstrapStoreError, .invalidNewPassword)
        }
        XCTAssertTrue(lifecycle.isUnlocked)
        XCTAssertEqual(
            try stores.bootstrap.readEnvelope(at: root).accessSlots[0].wrappedPayload,
            before.accessSlots[0].wrappedPayload
        )
        lifecycle.lock()
    }

    func testNewVisiblePasswordThatOpensTheSecondSlotIsRefused() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "visible-password-1",
            concealedPassword: "concealed-password-2",
            visibleBudget: try budget(),
            concealedBudget: try budget()
        )
        let before = try stores.bootstrap.readEnvelope(at: root)

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "visible-password-1")
        XCTAssertThrowsError(try lifecycle.changePassword(to: "concealed-password-2")) { error in
            XCTAssertEqual(error as? DualAccessEnvelopeError, .ambiguousPassword)
        }
        XCTAssertEqual(
            try stores.bootstrap.readEnvelope(at: root).accessSlots[0].wrappedPayload,
            before.accessSlots[0].wrappedPayload
        )
        lifecycle.lock()
    }

    func testConcealedSessionCannotChangeAPassword() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()
        _ = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "visible-password-1",
            concealedPassword: "concealed-password-2",
            visibleBudget: try budget(),
            concealedBudget: try budget()
        )

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "concealed-password-2")
        XCTAssertThrowsError(try lifecycle.changePassword(to: "another-password-3")) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .passwordChangeUnavailable)
        }
        lifecycle.lock()
        _ = try lifecycle.open(at: root, password: "visible-password-1")
        lifecycle.lock()
    }

    func testChangeWhileLockedIsRefused() throws {
        let stores = makeStores()
        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        XCTAssertThrowsError(try lifecycle.changePassword(to: "new-password-456")) { error in
            XCTAssertEqual(error as? V2VaultSessionLifecycleError, .locked)
        }
    }

    // MARK: - Helpers

    private func importNote(into lifecycle: V2VaultSessionLifecycle, root: URL) throws -> V2AccessEntry {
        let source = root.deletingLastPathComponent()
            .appendingPathComponent("source-\(UUID().uuidString).txt")
        defer { try? fileManager.removeItem(at: source) }
        try Data("protected bytes".utf8).write(to: source)
        return try lifecycle.importFile(at: source, originalName: "notes.txt")
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("hanzala-password-change-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func budget() throws -> V2StorageBudget {
        try V2StorageBudget(totalBytes: 16 * 1024 * 1024, reserveBytes: 2 * 1024 * 1024)
    }

    private func makeStores() -> (bootstrap: V2VaultBootstrapStore, sessions: V2VaultSessionStore) {
        let keyEngine = PasswordKeyEngine()
        let envelopeEngine = DualAccessEnvelopeEngine(
            keyEngine: keyEngine,
            makeParameters: {
                try keyEngine.makeParameters(operationsLimit: 2, memoryLimit: 32 * 1024 * 1024)
            }
        )
        let metadata = V2AccessMetadataStore(fileManager: fileManager)
        let bootstrap = V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: metadata
        )
        let sessions = V2VaultSessionStore(
            bootstrapStore: bootstrap,
            metadataStore: metadata,
            objectStore: V2PoolObjectStore(fileManager: fileManager)
        )
        return (bootstrap, sessions)
    }
}
