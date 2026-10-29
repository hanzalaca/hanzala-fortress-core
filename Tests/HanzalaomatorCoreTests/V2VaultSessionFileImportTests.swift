import XCTest
@testable import HanzalaomatorCore

final class V2VaultSessionFileImportTests: XCTestCase {
    private let fileManager = FileManager.default

    func testSessionImportsSmallRegularFileThroughSingleObjectPath() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-session-small-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 8 * 1024 * 1024, reserveBytes: 1024 * 1024)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let source = sourceDirectory.appendingPathComponent("notes.txt")
        let content = Data("bounded journalist notes".utf8)
        try content.write(to: source)

        let entry = try stores.sessions.importFile(at: source, into: session)

        XCTAssertEqual(entry.originalName, "notes.txt")
        XCTAssertEqual(entry.logicalByteCount, UInt64(content.count))
        XCTAssertTrue(entry.auxiliaryObjectNames.isEmpty)
        XCTAssertEqual(try stores.sessions.listEntries(in: session), [entry])
        XCTAssertEqual(
            try stores.sessions.readEntry(id: entry.id, in: session).data,
            content
        )
        XCTAssertNoThrow(
            try stores.sessions.verifyEntryIntegrity(id: entry.id, in: session)
        )
    }

    func testSessionAutomaticallyStreamsLargeFileAndSupportsBoundedReadAndRemoval() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-session-large-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let source = sourceDirectory.appendingPathComponent("large-evidence.mov")
        let byteCount = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        try writeRepeatingFile(at: source, byte: 0x6B, byteCount: byteCount)

        let entry = try stores.sessions.importFile(
            at: source,
            originalName: "evidence.mov",
            into: session
        )

        XCTAssertEqual(entry.originalName, "evidence.mov")
        XCTAssertEqual(entry.logicalByteCount, UInt64(byteCount))
        XCTAssertFalse(entry.auxiliaryObjectNames.isEmpty)

        let boundary = UInt64(V2ChunkManifest.maximumLogicalChunkByteCount)
        let range = try stores.sessions.readEntryRange(
            id: entry.id,
            offset: boundary - 19,
            length: 73,
            in: session
        )
        XCTAssertEqual(range, Data(repeating: 0x6B, count: 73))
        XCTAssertNoThrow(
            try stores.sessions.verifyEntryIntegrity(id: entry.id, in: session)
        )

        let ownedNames = [entry.opaqueObjectName] + entry.auxiliaryObjectNames
        XCTAssertTrue(ownedNames.allSatisfy {
            stores.objects.containsObject(named: $0, in: root)
        })

        _ = try stores.sessions.removeEntry(id: entry.id, from: session)
        XCTAssertTrue(try stores.sessions.listEntries(in: session).isEmpty)
        XCTAssertTrue(ownedNames.allSatisfy {
            !stores.objects.containsObject(named: $0, in: root)
        })
    }

    func testSessionFileImportRejectsSymbolicLinkWithoutCreatingEntry() throws {
        let root = try makeRoot(removeAfterCreating: true)
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-session-link-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 8 * 1024 * 1024, reserveBytes: 1024 * 1024)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let target = sourceDirectory.appendingPathComponent("target.txt")
        try Data("do not follow link".utf8).write(to: target)
        let link = sourceDirectory.appendingPathComponent("linked.txt")
        try fileManager.createSymbolicLink(at: link, withDestinationURL: target)

        XCTAssertThrowsError(
            try stores.sessions.importFile(at: link, into: session)
        ) { error in
            XCTAssertEqual(
                error as? V2VaultSessionFileImportError,
                .sourceIsSymbolicLink
            )
        }
        XCTAssertTrue(try stores.sessions.listEntries(in: session).isEmpty)
    }

    func testPendingRecoveryBlocksFileImportBeforeSourceInspection() throws {
        let root = try makeRoot(removeAfterCreating: true)
        defer { try? fileManager.removeItem(at: root) }

        let stores = makeStores()
        let budget = try V2StorageBudget(totalBytes: 8 * 1024 * 1024, reserveBytes: 1024 * 1024)
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "ordinary-password",
            budget: budget
        )
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let current = try stores.metadata.read(masterKey: session.masterKey, in: root)
        let pending = V2PendingImport(
            opaqueObjectName: opaque("a"),
            originalName: "pending.txt",
            logicalByteCount: 10
        )
        let claimed = try current.beginningImport(pending)
        try stores.metadata.commitTransition(
            from: current,
            to: claimed,
            masterKey: session.masterKey,
            in: root
        )

        let nonexistent = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-source-that-does-not-exist-\(UUID().uuidString)"
        )
        XCTAssertThrowsError(
            try stores.sessions.importFile(at: nonexistent, into: session)
        ) { error in
            XCTAssertEqual(error as? V2VaultSessionError, .recoveryRequired)
        }
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

    private func writeRepeatingFile(
        at url: URL,
        byte: UInt8,
        byteCount: Int
    ) throws {
        XCTAssertTrue(fileManager.createFile(atPath: url.path, contents: nil))
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }

        let blockSize = 1024 * 1024
        let block = Data(repeating: byte, count: blockSize)
        var remaining = byteCount
        while remaining > 0 {
            let next = min(blockSize, remaining)
            if next == blockSize {
                try handle.write(contentsOf: block)
            } else {
                try handle.write(contentsOf: Data(repeating: byte, count: next))
            }
            remaining -= next
        }
        try handle.synchronize()
    }

    private func opaque(_ character: Character) -> String {
        String(repeating: String(character), count: V2OpaqueObjectName.encodedLength)
    }

    private func makeDirectory(prefix: String) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "\(prefix)-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func makeRoot(removeAfterCreating: Bool) throws -> URL {
        let url = try makeDirectory(prefix: "hanzala-v2-session-file-import-tests")
        if removeAfterCreating {
            try fileManager.removeItem(at: url)
        }
        return url
    }
}
