import XCTest
@testable import HanzalaomatorCore

final class V2VaultBootstrapStoreTests: XCTestCase {
    private let fileManager = FileManager.default

    func testVisibleOnlyBootstrapCreatesSymmetricOpaqueAnchorsAndRecovery() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let store = makeStore()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let created = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget,
            vaultID: UUID(uuidString: "61000000-0000-0000-0000-000000000001")!,
            createdAt: Date(timeIntervalSince1970: 1_700_100_000)
        )

        XCTAssertNil(created.concealedMasterKey)
        XCTAssertNotNil(created.visibleRecoveryKey)
        XCTAssertNil(created.concealedRecoveryKey)
        XCTAssertEqual(created.envelope.accessSlots.count, DualAccessEnvelopeV2.fixedSlotCount)
        XCTAssertTrue(fileManager.fileExists(
            atPath: V2StorageLayout.accessEnvelopeURL(in: root).path
        ))
        XCTAssertFalse(fileManager.fileExists(atPath: VaultLayout.indexURL(in: root).path))

        let poolItems = try regularPoolFiles(in: root)
        XCTAssertEqual(poolItems.count, 4)
        XCTAssertTrue(poolItems.allSatisfy { V2OpaqueObjectName.isValid($0.lastPathComponent) })

        let opened = try store.openAccess(at: root, password: "ordinary-password")
        XCTAssertEqual(opened.access.role, .visible)
        XCTAssertEqual(opened.access.masterKey, created.visibleMasterKey)
        XCTAssertTrue(opened.metadata.entries.isEmpty)
        XCTAssertTrue(opened.metadata.pendingImports.isEmpty)
        XCTAssertTrue(opened.metadata.pendingRemovals.isEmpty)

        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)
        let recovered = try store.openRecoveryAccess(at: root, recoveryKey: recoveryKey)
        XCTAssertEqual(recovered.access.role, .visible)
        XCTAssertEqual(recovered.access.masterKey, created.visibleMasterKey)
        XCTAssertEqual(recovered.metadata.accessID, opened.metadata.accessID)
    }

    func testDualBootstrapCreatesSamePublicObjectCountAndSizeShapeAsVisibleOnly() throws {
        let visibleRoot = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: visibleRoot) }
        let dualRoot = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: dualRoot) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let vaultID = UUID(uuidString: "62000000-0000-0000-0000-000000000001")!
        let createdAt = Date(timeIntervalSince1970: 1_700_100_100)

        _ = try makeStore().createVisibleOnly(
            at: visibleRoot,
            password: "ordinary-password",
            budget: budget,
            vaultID: vaultID,
            createdAt: createdAt
        )
        _ = try makeStore().createDualAccess(
            at: dualRoot,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget,
            vaultID: vaultID,
            createdAt: createdAt
        )

        let visibleHeaderSize = try Data(
            contentsOf: V2StorageLayout.accessEnvelopeURL(in: visibleRoot)
        ).count
        let dualHeaderSize = try Data(
            contentsOf: V2StorageLayout.accessEnvelopeURL(in: dualRoot)
        ).count
        XCTAssertEqual(visibleHeaderSize, dualHeaderSize)

        let visibleSizes = try regularPoolFiles(in: visibleRoot).map { try fileSize($0) }.sorted()
        let dualSizes = try regularPoolFiles(in: dualRoot).map { try fileSize($0) }.sorted()
        XCTAssertEqual(visibleSizes.count, 4)
        XCTAssertEqual(visibleSizes, dualSizes)
    }

    func testDualBootstrapPasswordsAndRecoveryKeysOpenIndependentAnchors() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let store = makeStore()
        let visibleBudget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 15_000)
        let concealedBudget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 35_000)
        let created = try store.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: visibleBudget,
            concealedBudget: concealedBudget
        )

        let visible = try store.openAccess(at: root, password: "ordinary-password")
        let concealed = try store.openAccess(at: root, password: "source-protection-password")
        let visibleRecoveryKey = try XCTUnwrap(created.visibleRecoveryKey)
        let concealedRecoveryKey = try XCTUnwrap(created.concealedRecoveryKey)
        let recoveredVisible = try store.openRecoveryAccess(
            at: root,
            recoveryKey: visibleRecoveryKey
        )
        let recoveredConcealed = try store.openRecoveryAccess(
            at: root,
            recoveryKey: concealedRecoveryKey
        )

        XCTAssertEqual(visible.access.role, .visible)
        XCTAssertEqual(concealed.access.role, .concealed)
        XCTAssertEqual(visible.access.masterKey, created.visibleMasterKey)
        XCTAssertEqual(concealed.access.masterKey, created.concealedMasterKey)
        XCTAssertNotEqual(visible.access.masterKey, concealed.access.masterKey)
        XCTAssertEqual(visible.metadata.budget, visibleBudget)
        XCTAssertEqual(concealed.metadata.budget, concealedBudget)
        XCTAssertNotEqual(visible.metadata.accessID, concealed.metadata.accessID)

        XCTAssertEqual(recoveredVisible.access.role, .visible)
        XCTAssertEqual(recoveredVisible.access.masterKey, visible.access.masterKey)
        XCTAssertEqual(recoveredVisible.metadata.accessID, visible.metadata.accessID)
        XCTAssertEqual(recoveredConcealed.access.role, .concealed)
        XCTAssertEqual(recoveredConcealed.access.masterKey, concealed.access.masterKey)
        XCTAssertEqual(recoveredConcealed.metadata.accessID, concealed.metadata.accessID)
    }

    func testSerializedBootstrapEnvelopeContainsNoRecoveryOrRoleMarker() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        _ = try makeStore().createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget
        )

        let bytes = try Data(contentsOf: V2StorageLayout.accessEnvelopeURL(in: root))
        let publicText = String(decoding: bytes, as: UTF8.self).lowercased()
        for forbidden in ["hidden", "concealed", "visible", "role", "enabled", "recovery", "hzrk"] {
            XCTAssertFalse(publicText.contains(forbidden), "public envelope leaked \(forbidden)")
        }
        XCTAssertTrue(publicText.contains("accessslots"))
    }

    func testWrongPasswordDoesNotScanOrRevealOtherAccessPath() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let store = makeStore()
        _ = try store.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget
        )

        XCTAssertThrowsError(
            try store.openAccess(at: root, password: "wrong-password")
        ) { error in
            XCTAssertEqual(
                error as? DualAccessEnvelopeError,
                .invalidPasswordOrCorruptedEnvelope
            )
        }
        XCTAssertEqual(try regularPoolFiles(in: root).count, 4)
    }

    func testPublicVaultIDTamperMakesPasswordOpenFailClosedWithoutPoolMutation() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let store = makeStore()
        let created = try store.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget,
            vaultID: UUID(uuidString: "65000000-0000-0000-0000-000000000001")!
        )
        let before = Set(try regularPoolFiles(in: root).map(\.lastPathComponent))

        let tampered = DualAccessEnvelopeV2(
            vaultID: UUID(uuidString: "65000000-0000-0000-0000-000000000002")!,
            createdAt: created.envelope.createdAt,
            accessSlots: created.envelope.accessSlots
        )
        try writeEnvelope(tampered, in: root)

        for password in ["ordinary-password", "source-protection-password"] {
            XCTAssertThrowsError(
                try store.openAccess(at: root, password: password)
            ) { error in
                XCTAssertEqual(
                    error as? DualAccessEnvelopeError,
                    .invalidPasswordOrCorruptedEnvelope
                )
            }
        }

        let after = Set(try regularPoolFiles(in: root).map(\.lastPathComponent))
        XCTAssertEqual(before, after)
    }

    func testPublicVaultIDTamperMakesRecoveryFailClosedWithoutPoolMutation() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let store = makeStore()
        let created = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget,
            vaultID: UUID(uuidString: "66000000-0000-0000-0000-000000000001")!
        )
        let recoveryKey = try XCTUnwrap(created.visibleRecoveryKey)
        let before = Set(try regularPoolFiles(in: root).map(\.lastPathComponent))

        let tampered = DualAccessEnvelopeV2(
            vaultID: UUID(uuidString: "66000000-0000-0000-0000-000000000002")!,
            createdAt: created.envelope.createdAt,
            accessSlots: created.envelope.accessSlots
        )
        try writeEnvelope(tampered, in: root)

        XCTAssertThrowsError(
            try store.openRecoveryAccess(at: root, recoveryKey: recoveryKey)
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }
        XCTAssertEqual(before, Set(try regularPoolFiles(in: root).map(\.lastPathComponent)))

        try writeEnvelope(created.envelope, in: root)
        let recovered = try store.openRecoveryAccess(at: root, recoveryKey: recoveryKey)
        XCTAssertEqual(recovered.access.masterKey, created.visibleMasterKey)
    }

    func testWrongRecoveryKeyReturnsGenericFailureAndDoesNotMutatePool() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let store = makeStore()
        _ = try store.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget
        )
        let before = Set(try regularPoolFiles(in: root).map(\.lastPathComponent))
        let wrong = RecoveryKeyEngine().generateRecoveryKey()

        XCTAssertThrowsError(
            try store.openRecoveryAccess(at: root, recoveryKey: wrong)
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }

        let after = Set(try regularPoolFiles(in: root).map(\.lastPathComponent))
        XCTAssertEqual(before, after)
    }

    func testMalformedRecoveryKeyUsesSameGenericFailure() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let store = makeStore()
        _ = try store.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )

        XCTAssertThrowsError(
            try store.openRecoveryAccess(at: root, recoveryKey: "not-a-recovery-key")
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }
    }

    func testCreationRefusesExistingLayoutAndPreservesContents() throws {
        let root = try makeRoot(removeAfterCreating: false)
        defer { try? fileManager.removeItem(at: root) }

        let pool = V2StorageLayout.poolURL(in: root)
        try fileManager.createDirectory(at: pool, withIntermediateDirectories: false)
        let sentinel = pool.appendingPathComponent("do-not-delete")
        try Data("existing-user-data".utf8).write(to: sentinel)

        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        XCTAssertThrowsError(
            try makeStore().createVisibleOnly(
                at: root,
                password: "ordinary-password",
                budget: budget
            )
        ) { error in
            XCTAssertEqual(
                error as? V2VaultBootstrapStoreError,
                .rootAlreadyContainsVaultLayout
            )
        }
        XCTAssertEqual(try Data(contentsOf: sentinel), Data("existing-user-data".utf8))
    }

    func testEnvelopeSymlinkIsRejectedBeforeDecode() throws {
        let root = try makeRoot(removeAfterCreating: false)
        defer { try? fileManager.removeItem(at: root) }
        let outside = try makeRoot(removeAfterCreating: false)
        defer { try? fileManager.removeItem(at: outside) }

        let target = outside.appendingPathComponent("fake-envelope")
        try Data("{}".utf8).write(to: target)
        try fileManager.createSymbolicLink(
            at: V2StorageLayout.accessEnvelopeURL(in: root),
            withDestinationURL: target
        )

        XCTAssertThrowsError(try makeStore().readEnvelope(at: root)) { error in
            XCTAssertEqual(
                error as? V2VaultBootstrapStoreError,
                .envelopeIsNotRegularFile
            )
        }
    }

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

    private func writeEnvelope(_ envelope: DualAccessEnvelopeV2, in root: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(envelope)
        try data.write(
            to: V2StorageLayout.accessEnvelopeURL(in: root),
            options: [.atomic]
        )
    }

    private func regularPoolFiles(in root: URL) throws -> [URL] {
        try fileManager.contentsOfDirectory(
            at: V2StorageLayout.poolURL(in: root),
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ).filter {
            (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
        }
    }

    private func fileSize(_ url: URL) throws -> Int {
        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        return try XCTUnwrap(values.fileSize)
    }

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-bootstrap-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        if removeAfterCreating {
            try fileManager.removeItem(at: url)
        }
        return url
    }
}
