import XCTest
@testable import HanzalaomatorCore

final class V2VaultSessionStoreTests: XCTestCase {
    private let fileManager = FileManager.default

    func testDualSessionsImportReadAndRemoveWithoutCrossAccessDiscovery() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 1_000_000, reserveBytes: 100_000)
        _ = try stores.bootstrap.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            visibleBudget: budget,
            concealedBudget: budget
        )

        let visible = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session
        let concealed = try stores.sessions.openSession(
            at: root,
            password: "source-protection-password"
        ).session

        XCTAssertEqual(visible.role, .visible)
        XCTAssertEqual(concealed.role, .concealed)
        XCTAssertNotEqual(visible.accessID, concealed.accessID)

        let visibleData = Data("ordinary decoy document".utf8)
        let concealedData = Data("protected journalist source".utf8)
        let visibleEntry = try stores.sessions.importData(
            visibleData,
            originalName: "notes.txt",
            into: visible
        )
        let concealedEntry = try stores.sessions.importData(
            concealedData,
            originalName: "source.txt",
            into: concealed
        )

        XCTAssertEqual(try stores.sessions.listEntries(in: visible), [visibleEntry])
        XCTAssertEqual(try stores.sessions.listEntries(in: concealed), [concealedEntry])
        XCTAssertEqual(
            try stores.sessions.readEntry(id: visibleEntry.id, in: visible).data,
            visibleData
        )
        XCTAssertEqual(
            try stores.sessions.readEntry(id: concealedEntry.id, in: concealed).data,
            concealedData
        )

        XCTAssertThrowsError(
            try stores.sessions.readEntry(id: concealedEntry.id, in: visible)
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .entryNotFound)
        }
        XCTAssertThrowsError(
            try stores.sessions.readEntry(id: visibleEntry.id, in: concealed)
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .entryNotFound)
        }

        let concealedObjectURL = V2StorageLayout.objectURL(
            named: concealedEntry.opaqueObjectName,
            in: root
        )
        XCTAssertTrue(fileManager.fileExists(atPath: concealedObjectURL.path))

        _ = try stores.sessions.removeEntry(id: visibleEntry.id, from: visible)
        XCTAssertTrue(try stores.sessions.listEntries(in: visible).isEmpty)
        XCTAssertTrue(fileManager.fileExists(atPath: concealedObjectURL.path))
        XCTAssertEqual(
            try stores.sessions.readEntry(id: concealedEntry.id, in: concealed).data,
            concealedData
        )
    }

    func testSessionImportUsesCentralPaddingBucket() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let opened = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        )
        XCTAssertEqual(opened.session.role, .visible)
        XCTAssertTrue(opened.recovery.imports.finalizedTransactionIDs.isEmpty)
        XCTAssertTrue(opened.recovery.removals.deletedTransactionIDs.isEmpty)

        let entry = try stores.sessions.importData(
            Data(repeating: 0xAB, count: 100),
            originalName: "small.bin",
            into: opened.session
        )
        let objectURL = V2StorageLayout.objectURL(named: entry.opaqueObjectName, in: root)
        let size = try XCTUnwrap(
            try objectURL.resourceValues(forKeys: [.fileSizeKey]).fileSize
        )
        XCTAssertEqual(size, 4 * 1024 + 8 + 24 + 16)
    }

    func testOpenSessionFinalizesAuthenticatedPendingImport() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let access = try stores.bootstrap.openAccess(
            at: root,
            password: "ordinary-password"
        )

        let transactionID = UUID(uuidString: "71000000-0000-0000-0000-000000000001")!
        let opaqueName = opaque("a")
        let content = Data("survived before reopen".utf8)
        let pending = V2PendingImport(
            transactionID: transactionID,
            opaqueObjectName: opaqueName,
            originalName: "survived.txt",
            logicalByteCount: UInt64(content.count),
            createdAt: Date(timeIntervalSince1970: 1_700_200_000)
        )
        let claimed = try access.metadata.beginningImport(pending)
        try stores.metadata.commitTransition(
            from: access.metadata,
            to: claimed,
            masterKey: access.access.masterKey,
            in: root
        )
        _ = try stores.objects.createObject(
            named: opaqueName,
            kind: .data,
            content: content,
            masterKey: access.access.masterKey,
            in: root,
            paddedPlaintextByteCount: 4 * 1024
        )

        let opened = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        )
        XCTAssertEqual(opened.recovery.imports.finalizedTransactionIDs, [transactionID])
        XCTAssertTrue(opened.recovery.imports.abortedMissingObjectTransactionIDs.isEmpty)

        let entries = try stores.sessions.listEntries(in: opened.session)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].id, transactionID)
        XCTAssertEqual(
            try stores.sessions.readEntry(id: transactionID, in: opened.session).data,
            content
        )
    }

    func testOpenSessionCompletesAuthenticatedPendingRemoval() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session
        let entry = try stores.sessions.importData(
            Data("remove after crash".utf8),
            originalName: "remove.txt",
            into: session
        )

        let transactionID = UUID(uuidString: "72000000-0000-0000-0000-000000000001")!
        let current = try stores.metadata.read(masterKey: session.masterKey, in: root)
        let claimed = try current.beginningRemoval(
            entryID: entry.id,
            transactionID: transactionID,
            createdAt: Date(timeIntervalSince1970: 1_700_200_100)
        )
        try stores.metadata.commitTransition(
            from: current,
            to: claimed,
            masterKey: session.masterKey,
            in: root
        )
        let objectURL = V2StorageLayout.objectURL(named: entry.opaqueObjectName, in: root)
        XCTAssertTrue(fileManager.fileExists(atPath: objectURL.path))

        let reopened = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        )
        XCTAssertEqual(reopened.recovery.removals.deletedTransactionIDs, [transactionID])
        XCTAssertTrue(reopened.recovery.removals.finalizedAlreadyMissingTransactionIDs.isEmpty)
        XCTAssertTrue(try stores.sessions.listEntries(in: reopened.session).isEmpty)
        XCTAssertFalse(fileManager.fileExists(atPath: objectURL.path))
    }

    func testEnvelopeReplacementInvalidatesExistingSession() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }
        let otherRoot = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: otherRoot) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget,
            vaultID: UUID(uuidString: "73000000-0000-0000-0000-000000000001")!
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        _ = try makeStores().bootstrap.createVisibleOnly(
            at: otherRoot,
            password: "other-password",
            budget: budget,
            vaultID: UUID(uuidString: "73000000-0000-0000-0000-000000000002")!
        )
        let replacement = try Data(
            contentsOf: V2StorageLayout.accessEnvelopeURL(in: otherRoot)
        )
        try replacement.write(
            to: V2StorageLayout.accessEnvelopeURL(in: root),
            options: [.atomic]
        )

        XCTAssertThrowsError(try stores.sessions.listEntries(in: session)) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .envelopeIdentityChanged)
        }
    }

    func testAuthenticatedMetadataFromSameKeyButDifferentAccessIdentityInvalidatesSession() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }
        let otherRoot = try makeRoot(removeAfterCreating: false)
        defer { try? fileManager.removeItem(at: otherRoot) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let replacementAccessID = UUID(uuidString: "74000000-0000-0000-0000-000000000001")!
        _ = try stores.metadata.createInitialEmpty(
            budget: budget,
            masterKey: session.masterKey,
            in: otherRoot,
            accessID: replacementAccessID
        )
        XCTAssertNotEqual(session.accessID, replacementAccessID)

        let anchorName = try V2StorageNamespaceLocator().indexObjectName(
            masterKey: session.masterKey
        )
        let replacementBytes = try Data(
            contentsOf: V2StorageLayout.objectURL(named: anchorName, in: otherRoot)
        )
        try replacementBytes.write(
            to: V2StorageLayout.objectURL(named: anchorName, in: root),
            options: [.atomic]
        )

        XCTAssertThrowsError(try stores.sessions.listEntries(in: session)) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .accessIdentityChanged)
        }
    }

    func testMutationIsBlockedUntilAuthenticatedPendingWorkIsRecovered() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 10_000)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let pending = V2PendingImport(
            transactionID: UUID(uuidString: "75000000-0000-0000-0000-000000000001")!,
            opaqueObjectName: opaque("b"),
            originalName: "missing.txt",
            logicalByteCount: 10
        )
        let current = try stores.metadata.read(masterKey: session.masterKey, in: root)
        let claimed = try current.beginningImport(pending)
        try stores.metadata.commitTransition(
            from: current,
            to: claimed,
            masterKey: session.masterKey,
            in: root
        )

        XCTAssertThrowsError(
            try stores.sessions.importData(
                Data("new".utf8),
                originalName: "new.txt",
                into: session
            )
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .recoveryRequired)
        }

        let report = try stores.sessions.recover(session: session)
        XCTAssertEqual(
            report.imports.abortedMissingObjectTransactionIDs,
            [pending.transactionID]
        )
        XCTAssertNoThrow(
            try stores.sessions.importData(
                Data("new".utf8),
                originalName: "new.txt",
                into: session
            )
        )
    }

    private typealias Stores = (
        bootstrap: V2VaultBootstrapStore,
        metadata: V2AccessMetadataStore,
        objects: V2PoolObjectStore,
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
        return (bootstrap, metadata, objects, sessions)
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-session-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        if removeAfterCreating {
            try fileManager.removeItem(at: url)
        }
        return url
    }
}