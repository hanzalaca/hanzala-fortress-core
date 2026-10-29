import XCTest
@testable import HanzalaomatorCore

final class V2DescriptorBoundEnvelopeReaderTests: XCTestCase {
    private let fileManager = FileManager.default

    #if canImport(Darwin)
    func testEnvelopePathReplacementAfterOpenCannotRetargetRead() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let store = makeStore()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let created = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget,
            vaultID: UUID(uuidString: "71000000-0000-0000-0000-000000000001")!
        )

        let envelopeURL = V2StorageLayout.accessEnvelopeURL(in: root)
        let displacedURL = root.appendingPathComponent("original-envelope")
        var fired = false
        store.envelopeReadOpenedHook = {
            guard !fired else { return }
            fired = true
            try! self.fileManager.moveItem(at: envelopeURL, to: displacedURL)
            try! Data("{}".utf8).write(to: envelopeURL)
        }

        let read = try store.readEnvelope(at: root)
        XCTAssertTrue(fired)
        XCTAssertEqual(read.vaultID, created.envelope.vaultID)
        XCTAssertEqual(read.accessSlots.count, DualAccessEnvelopeV2.fixedSlotCount)
        XCTAssertEqual(try Data(contentsOf: envelopeURL), Data("{}".utf8))
    }

    func testRootReplacementAfterEnvelopeOpenFailsPasswordOpenClosed() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let displacedRoot = root.deletingLastPathComponent()
            .appendingPathComponent("hz-envelope-old-\(UUID().uuidString.prefix(8))", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displacedRoot)
        }

        let store = makeStore()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        _ = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )

        var fired = false
        store.envelopeReadOpenedHook = {
            guard !fired else { return }
            fired = true
            try! self.fileManager.moveItem(at: root, to: displacedRoot)
            try! self.fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false
            )
            try! Data("replacement-root-sentinel".utf8).write(
                to: root.appendingPathComponent("sentinel")
            )
        }

        XCTAssertThrowsError(
            try store.openAccess(at: root, password: "ordinary-password")
        ) { error in
            XCTAssertEqual(
                error as? V2VaultBootstrapStoreError,
                .invalidEnvelope
            )
        }
        XCTAssertTrue(fired)
        XCTAssertEqual(
            try Data(contentsOf: root.appendingPathComponent("sentinel")),
            Data("replacement-root-sentinel".utf8)
        )
    }

    func testRootReplacementAfterEnvelopeOpenKeepsRecoveryFailureGeneric() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let displacedRoot = root.deletingLastPathComponent()
            .appendingPathComponent("hz-recovery-old-\(UUID().uuidString.prefix(8))", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displacedRoot)
        }

        let store = makeStore()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let created = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)

        var fired = false
        store.envelopeReadOpenedHook = {
            guard !fired else { return }
            fired = true
            try! self.fileManager.moveItem(at: root, to: displacedRoot)
            try! self.fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false
            )
        }

        XCTAssertThrowsError(
            try store.openRecoveryAccess(at: root, recoveryKey: recoveryKey)
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }
        XCTAssertTrue(fired)
    }

    /// A replace-and-restore attacker can make the public pathname point at a
    /// different, correctly authenticated metadata anchor while the password KDF
    /// is running, then restore the original root before a pathname identity
    /// recheck. The private read must stay on the root descriptor captured before
    /// the envelope was read instead of accepting that substituted metadata.
    func testPasswordUnlockPrivateMetadataCannotBeRetargetedByRootReplaceAndRestore() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let displacedRoot = root.deletingLastPathComponent()
            .appendingPathComponent("hz-unlock-original-\(UUID().uuidString.prefix(8))", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displacedRoot)
        }

        let store = makeStore()
        let originalBudget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let attackerBudget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 35_000)
        let created = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: originalBudget
        )
        let originalMetadata = try V2AccessMetadataStore(fileManager: fileManager).read(
            masterKey: created.visibleMasterKey,
            in: root
        )
        let attackerAccessID = UUID(uuidString: "71000000-0000-0000-0000-000000000099")!

        var beforePrivateFired = false
        var afterPrivateFired = false
        store.unlockBeforePrivateAnchorHook = {
            guard !beforePrivateFired else { return }
            beforePrivateFired = true

            try! self.fileManager.moveItem(at: root, to: displacedRoot)
            try! self.fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false
            )
            _ = try! V2AccessMetadataStore(fileManager: self.fileManager).createInitialEmpty(
                budget: attackerBudget,
                masterKey: created.visibleMasterKey,
                in: root,
                accessID: attackerAccessID
            )
        }
        store.unlockAfterPrivateAnchorHook = {
            guard !afterPrivateFired else { return }
            afterPrivateFired = true
            try! self.fileManager.removeItem(at: root)
            try! self.fileManager.moveItem(at: displacedRoot, to: root)
        }

        let opened = try store.openAccess(at: root, password: "ordinary-password")

        XCTAssertTrue(beforePrivateFired)
        XCTAssertTrue(afterPrivateFired)
        XCTAssertEqual(opened.metadata.accessID, originalMetadata.accessID)
        XCTAssertNotEqual(opened.metadata.accessID, attackerAccessID)
        XCTAssertEqual(opened.metadata.budget, originalBudget)
        XCTAssertNotEqual(opened.metadata.budget, attackerBudget)
    }

    /// Recovery has two private reads: the exact recovery anchor followed by the
    /// exact metadata anchor. Both must resolve through the root captured for the
    /// public envelope. A temporary replacement root can contain a valid copied
    /// recovery object and attacker-controlled authenticated metadata under the
    /// same master key/access ID; restoring the pathname before publication must
    /// not make that replacement metadata acceptable.
    func testRecoveryUnlockAnchorsCannotBeRetargetedByRootReplaceAndRestore() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let displacedRoot = root.deletingLastPathComponent()
            .appendingPathComponent("hz-recovery-original-\(UUID().uuidString.prefix(8))", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displacedRoot)
        }

        let store = makeStore()
        let originalBudget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let attackerBudget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 35_000)
        let created = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: originalBudget,
            vaultID: UUID(uuidString: "72000000-0000-0000-0000-000000000001")!
        )
        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)
        let originalMetadata = try V2AccessMetadataStore(fileManager: fileManager).read(
            masterKey: created.visibleMasterKey,
            in: root
        )
        let recoveryMaterial = try RecoveryKeyEngine().keyMaterial(from: recoveryKey)
        let recoveryName = try V2RecoveryNamespaceLocator().objectName(
            recoveryKeyMaterial: recoveryMaterial,
            vaultID: created.envelope.vaultID
        )

        var beforePrivateFired = false
        var afterPrivateFired = false
        store.unlockBeforePrivateAnchorHook = {
            guard !beforePrivateFired else { return }
            beforePrivateFired = true

            try! self.fileManager.moveItem(at: root, to: displacedRoot)
            try! self.fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false
            )
            let replacementPool = V2StorageLayout.poolURL(in: root)
            try! self.fileManager.createDirectory(
                at: replacementPool,
                withIntermediateDirectories: false
            )
            let originalRecovery = V2StorageLayout.objectURL(
                named: recoveryName,
                in: displacedRoot
            )
            let replacementRecovery = V2StorageLayout.objectURL(
                named: recoveryName,
                in: root
            )
            try! self.fileManager.copyItem(
                at: originalRecovery,
                to: replacementRecovery
            )
            _ = try! V2AccessMetadataStore(fileManager: self.fileManager).createInitialEmpty(
                budget: attackerBudget,
                masterKey: created.visibleMasterKey,
                in: root,
                accessID: originalMetadata.accessID
            )
        }
        store.unlockAfterPrivateAnchorHook = {
            guard !afterPrivateFired else { return }
            afterPrivateFired = true
            try! self.fileManager.removeItem(at: root)
            try! self.fileManager.moveItem(at: displacedRoot, to: root)
        }

        let opened = try store.openRecoveryAccess(
            at: root,
            recoveryKey: recoveryKey
        )

        XCTAssertTrue(beforePrivateFired)
        XCTAssertTrue(afterPrivateFired)
        XCTAssertEqual(opened.metadata.accessID, originalMetadata.accessID)
        XCTAssertEqual(opened.metadata.budget, originalBudget)
        XCTAssertNotEqual(opened.metadata.budget, attackerBudget)
        XCTAssertEqual(opened.access.masterKey, created.visibleMasterKey)
    }

    func testInPlaceEnvelopeMutationDuringDescriptorReadFailsClosed() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let store = makeStore()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        _ = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )

        let envelopeURL = V2StorageLayout.accessEnvelopeURL(in: root)
        let byteCount = try Data(contentsOf: envelopeURL).count
        var fired = false
        store.envelopeReadOpenedHook = {
            guard !fired else { return }
            fired = true
            let handle = try! FileHandle(forWritingTo: envelopeURL)
            try! handle.truncate(atOffset: 0)
            try! handle.write(contentsOf: Data(repeating: 0, count: byteCount))
            try! handle.synchronize()
            try! handle.close()
        }

        XCTAssertThrowsError(try store.readEnvelope(at: root)) { error in
            XCTAssertEqual(
                error as? V2VaultBootstrapStoreError,
                .invalidEnvelope
            )
        }
        XCTAssertTrue(fired)
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

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent(
                "hz-envelope-read-\(UUID().uuidString.prefix(8))",
                isDirectory: true
            )
        if !removeAfterCreating {
            try fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false
            )
        }
        return root
    }
}
