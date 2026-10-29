import XCTest
@testable import HanzalaomatorCore

final class V2StreamingSecureSourceTests: XCTestCase {
    private let fileManager = FileManager.default

    func testPathReplacementBetweenStreamingPassesCannotRedirectPlaintext() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-identity pathname replacement guarantee is Darwin-specific.")
        #else
        let root = try makeDirectory(prefix: "hz-stream-secure-vault")
        let sourceDirectory = try makeDirectory(prefix: "hz-stream-secure-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let source = sourceDirectory.appendingPathComponent("selected-evidence.bin")
        let retained = sourceDirectory.appendingPathComponent("renamed-original.bin")
        let byteCount = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        try writeRepeatingFile(at: source, byte: 0x41, byteCount: byteCount)

        let key = Data(repeating: 0xB1, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let objectStore = V2PoolObjectStore(fileManager: fileManager)
        let budget = try V2StorageBudget(
            totalBytes: 128 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let coordinator = V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        )
        coordinator.streamingPassBoundaryHook = { [fileManager] in
            do {
                try fileManager.moveItem(at: source, to: retained)
                try self.writeRepeatingFile(
                    at: source,
                    byte: 0xE2,
                    byteCount: byteCount
                )
            } catch {
                XCTFail("Failed to replace streaming source pathname: \(error)")
            }
        }

        // On Darwin, renaming the already-open source may update inode change-time.
        // The secure descriptor intentionally treats that as a suspicious source
        // mutation and fails closed. The important invariant is that the attacker
        // replacement pathname is never reopened or published as encrypted data.
        XCTAssertThrowsError(
            try coordinator.importChunkedFile(
                at: source,
                originalName: "selected-evidence.bin",
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2ChunkOwnershipTransactionError,
                .sourceChangedDuringImport
            )
        }

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(metadata.entries.isEmpty)
        XCTAssertTrue(metadata.pendingChunkImports.isEmpty)

        let replacement = try Data(contentsOf: source, options: [.mappedIfSafe])
        XCTAssertEqual(replacement.prefix(64), Data(repeating: 0xE2, count: 64))
        let original = try Data(contentsOf: retained, options: [.mappedIfSafe])
        XCTAssertEqual(original.prefix(64), Data(repeating: 0x41, count: 64))
        #endif
    }

    func testSessionLargeImportKeepsDescriptorOpenedBeforeRouting() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-identity pathname replacement guarantee is Darwin-specific.")
        #else
        let root = try makeDirectory(prefix: "hz-session-stream-secure-vault")
        let sourceDirectory = try makeDirectory(prefix: "hz-session-stream-secure-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let stores = makeStores()
        let budget = try V2StorageBudget(
            totalBytes: 128 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try stores.bootstrap.createVisibleOnly(
            at: root,
            password: "descriptor-password",
            budget: budget
        )
        let opened = try stores.sessions.openSession(
            at: root,
            password: "descriptor-password"
        )

        let source = sourceDirectory.appendingPathComponent("session-selected.bin")
        let retained = sourceDirectory.appendingPathComponent("session-original.bin")
        let byteCount = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        try writeRepeatingFile(at: source, byte: 0x52, byteCount: byteCount)

        stores.sessions.secureSourceOpenedHook = { [fileManager] in
            do {
                try fileManager.moveItem(at: source, to: retained)
                try self.writeRepeatingFile(
                    at: source,
                    byte: 0xF3,
                    byteCount: byteCount
                )
            } catch {
                XCTFail("Failed to replace session source pathname: \(error)")
            }
        }

        XCTAssertThrowsError(
            try stores.sessions.importFile(
                at: source,
                originalName: "session-selected.bin",
                into: opened.session
            )
        ) { error in
            XCTAssertEqual(
                error as? V2VaultSessionFileImportError,
                .sourceChangedDuringImport
            )
        }

        XCTAssertTrue(try stores.sessions.listEntries(in: opened.session).isEmpty)
        let replacement = try Data(contentsOf: source, options: [.mappedIfSafe])
        XCTAssertEqual(replacement.prefix(64), Data(repeating: 0xF3, count: 64))
        let original = try Data(contentsOf: retained, options: [.mappedIfSafe])
        XCTAssertEqual(original.prefix(64), Data(repeating: 0x52, count: 64))
        #endif
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
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let objectStore = V2PoolObjectStore(fileManager: fileManager)
        let bootstrap = V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: metadataStore
        )
        let sessions = V2VaultSessionStore(
            bootstrapStore: bootstrap,
            metadataStore: metadataStore,
            objectStore: objectStore
        )
        return (bootstrap, sessions)
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
            try handle.write(contentsOf: next == blockSize
                ? block
                : Data(repeating: byte, count: next))
            remaining -= next
        }
        try handle.synchronize()
    }

    private func makeDirectory(prefix: String) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "\(prefix)-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
