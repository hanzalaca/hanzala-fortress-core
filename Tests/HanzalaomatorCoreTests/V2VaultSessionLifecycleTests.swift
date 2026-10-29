import XCTest
@testable import HanzalaomatorCore

final class V2VaultSessionLifecycleTests: XCTestCase {
    private let fileManager = FileManager.default

    func testLifecycleKeepsRawSessionPrivateAndRevokesFinderOnLock() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 16 * 1024 * 1024,
            reserveBytes: 2 * 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        let opened = try lifecycle.open(at: root, password: "ordinary-password")
        XCTAssertTrue(lifecycle.isUnlocked)
        XCTAssertEqual(opened.identity.root, root)
        XCTAssertEqual(lifecycle.identity, opened.identity)

        let source = root.deletingLastPathComponent()
            .appendingPathComponent("source-\(UUID().uuidString).txt")
        defer { try? fileManager.removeItem(at: source) }
        try Data("protected bytes".utf8).write(to: source)

        let entry = try lifecycle.importFile(at: source, originalName: "notes.txt")
        XCTAssertEqual(try lifecycle.listEntries().map(\.id), [entry.id])

        let lease = try lifecycle.makeFinderLease()
        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 1)
        let handle = try lease.session.open(entryID: entry.id)
        XCTAssertEqual(
            try lease.session.read(handle: handle, offset: 0, length: 9),
            Data("protected".utf8)
        )

        lifecycle.lock()

        XCTAssertFalse(lifecycle.isUnlocked)
        XCTAssertNil(lifecycle.identity)
        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 0)
        XCTAssertThrowsError(try lifecycle.listEntries()) { error in
            XCTAssertEqual(error as? V2VaultSessionLifecycleError, .locked)
        }
        XCTAssertThrowsError(try lease.session.read(handle: handle, offset: 0, length: 1)) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
        }
    }

    func testPasswordAloneSelectsVisibleOrConcealedAccessWithoutModeFlag() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 24 * 1024 * 1024,
            reserveBytes: 3 * 1024 * 1024
        )
        _ = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-password",
            visibleBudget: budget,
            concealedBudget: budget
        )

        let visibleLifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        let visibleOpen = try visibleLifecycle.open(at: root, password: "ordinary-password")
        XCTAssertEqual(visibleOpen.identity.role, .visible)

        let visibleSource = try makeSource(contents: "ordinary material")
        defer { try? fileManager.removeItem(at: visibleSource) }
        let visibleEntry = try visibleLifecycle.importFile(
            at: visibleSource,
            originalName: "ordinary.txt"
        )
        visibleLifecycle.lock()

        let concealedLifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        let concealedOpen = try concealedLifecycle.open(at: root, password: "source-password")
        XCTAssertEqual(concealedOpen.identity.role, .concealed)
        XCTAssertFalse(try concealedLifecycle.listEntries().contains(where: { $0.id == visibleEntry.id }))

        let concealedSource = try makeSource(contents: "protected source")
        defer { try? fileManager.removeItem(at: concealedSource) }
        let concealedEntry = try concealedLifecycle.importFile(
            at: concealedSource,
            originalName: "source.txt"
        )
        XCTAssertEqual(try concealedLifecycle.listEntries().map(\.id), [concealedEntry.id])
    }

    func testRecoveryKeyOpensSameLifecycleCapabilitiesWithoutModeFlag() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 24 * 1024 * 1024,
            reserveBytes: 3 * 1024 * 1024
        )
        let created = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-password",
            visibleBudget: budget,
            concealedBudget: budget
        )
        let concealedRecoveryKey = try XCTUnwrap(created.concealedRecoveryKey)

        let visibleLifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try visibleLifecycle.open(at: root, password: "ordinary-password")
        let visibleSource = try makeSource(contents: "ordinary material")
        defer { try? fileManager.removeItem(at: visibleSource) }
        let visibleEntry = try visibleLifecycle.importFile(
            at: visibleSource,
            originalName: "ordinary.txt"
        )
        visibleLifecycle.lock()

        let concealedLifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try concealedLifecycle.open(at: root, password: "source-password")
        let concealedSource = try makeSource(contents: "protected source")
        defer { try? fileManager.removeItem(at: concealedSource) }
        let concealedEntry = try concealedLifecycle.importFile(
            at: concealedSource,
            originalName: "source.txt"
        )
        concealedLifecycle.lock()

        let recovery = V2RecoverySessionCoordinator(
            bootstrapStore: stores.bootstrap,
            sessionStore: stores.sessions
        )
        let recoveredLifecycle = V2VaultSessionLifecycle(
            sessionStore: stores.sessions,
            recoverySessionCoordinator: recovery
        )
        let opened = try recoveredLifecycle.openRecovery(
            at: root,
            recoveryKey: concealedRecoveryKey
        )

        XCTAssertTrue(recoveredLifecycle.isUnlocked)
        XCTAssertEqual(opened.identity.role, .concealed)
        XCTAssertEqual(recoveredLifecycle.identity, opened.identity)
        let ids = Set(try recoveredLifecycle.listEntries().map(\.id))
        XCTAssertEqual(ids, [concealedEntry.id])
        XCTAssertFalse(ids.contains(visibleEntry.id))

        let lease = try recoveredLifecycle.makeFinderLease()
        let handle = try lease.session.open(entryID: concealedEntry.id)
        XCTAssertEqual(
            try lease.session.read(handle: handle, offset: 0, length: 9),
            Data("protected".utf8)
        )

        recoveredLifecycle.lock()
        XCTAssertFalse(recoveredLifecycle.isUnlocked)
        XCTAssertThrowsError(
            try lease.session.read(handle: handle, offset: 0, length: 1)
        ) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
        }
    }

    func testFailedOpenLeavesLifecycleLockedAndCanRetry() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 8 * 1024 * 1024,
            reserveBytes: 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "correct-password",
            budget: budget
        )

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        XCTAssertThrowsError(try lifecycle.open(at: root, password: "wrong-password"))
        XCTAssertFalse(lifecycle.isUnlocked)
        XCTAssertNil(lifecycle.identity)

        let opened = try lifecycle.open(at: root, password: "correct-password")
        XCTAssertTrue(lifecycle.isUnlocked)
        XCTAssertEqual(opened.identity.root, root)
    }

    func testFailedRecoveryOpenLeavesLifecycleLockedAndPasswordRetryWorks() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 8 * 1024 * 1024,
            reserveBytes: 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "correct-password",
            budget: budget
        )

        let recovery = V2RecoverySessionCoordinator(
            bootstrapStore: stores.bootstrap,
            sessionStore: stores.sessions
        )
        let lifecycle = V2VaultSessionLifecycle(
            sessionStore: stores.sessions,
            recoverySessionCoordinator: recovery
        )

        XCTAssertThrowsError(
            try lifecycle.openRecovery(
                at: root,
                recoveryKey: RecoveryKeyEngine().generateRecoveryKey()
            )
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }
        XCTAssertFalse(lifecycle.isUnlocked)
        XCTAssertNil(lifecycle.identity)

        let opened = try lifecycle.open(at: root, password: "correct-password")
        XCTAssertTrue(lifecycle.isUnlocked)
        XCTAssertEqual(opened.identity.role, .visible)
    }

    func testFinderLeaseReleaseIsIdempotentAndClosesHandle() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 8 * 1024 * 1024,
            reserveBytes: 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )

        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "ordinary-password")
        let lease = try lifecycle.makeFinderLease()
        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 1)

        lifecycle.releaseFinderLease(id: lease.id)
        lifecycle.releaseFinderLease(id: lease.id)

        XCTAssertEqual(lifecycle.activeFinderLeaseCount(), 0)
        XCTAssertThrowsError(try lease.session.listRoot()) { error in
            XCTAssertEqual(error as? V2FinderReadOnlySessionError, .sessionInvalidated)
        }
    }

    private typealias Stores = (
        bootstrap: V2VaultBootstrapStore,
        sessions: V2VaultSessionStore
    )

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
        return (bootstrap, sessions)
    }

    private func makeRoot() throws -> URL {
        let root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("hz-life-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }

    private func makeSource(contents: String) throws -> URL {
        let url = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("hz-src-\(UUID().uuidString).bin")
        try Data(contents.utf8).write(to: url)
        return url
    }
}
