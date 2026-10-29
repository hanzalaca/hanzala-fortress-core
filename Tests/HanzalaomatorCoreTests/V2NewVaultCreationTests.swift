import XCTest
@testable import HanzalaomatorCore

/// The flow the Mac and iPhone apps use for a new vault: create a visible-only
/// v2 vault in a folder the user picked, route it by format, open it with the
/// password through the shared lifecycle.
final class V2NewVaultCreationTests: XCTestCase {
    private let fileManager = FileManager.default

    func testMacNewVaultBudgetIsAccepted() throws {
        let budget = try V2StorageBudget(
            totalBytes: 2 * 1024 * 1024 * 1024 * 1024,
            reserveBytes: 256 * 1024 * 1024
        )
        XCTAssertGreaterThan(budget.visibleWritableLimit, 0)
    }

    func testNewVaultInAnEmptyPickedFolderIsV2AndOpensWithThePassword() throws {
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("hanzala-new-vault-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: root) }
        let stores = makeStores()

        let created = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "new mac vault password",
            budget: try V2StorageBudget(totalBytes: 2 * 1024 * 1024, reserveBytes: 256 * 1024)
        )

        XCTAssertNotNil(created.visibleRecoveryKey)
        XCTAssertEqual(try VaultFormatDetector(fileManager: fileManager).detect(at: root), .v2)
        let lifecycle = V2VaultSessionLifecycle(sessionStore: stores.sessions)
        _ = try lifecycle.open(at: root, password: "new mac vault password")
        XCTAssertEqual(try lifecycle.listEntries().count, 0)
        lifecycle.lock()
        XCTAssertThrowsError(try lifecycle.open(at: root, password: "wrong password"))
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
