import Foundation
import XCTest
@testable import HanzalaomatorCore

final class V2VaultSessionSecureSourceImportTests: XCTestCase {
    private let fileManager = FileManager.default

    func testSmallImportPathReplacementNeverImportsReplacementBytes() throws {
        let root = try makeRoot()
        let sourceDirectory = try makeDirectory(prefix: "hz-secure-session-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

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
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let source = sourceDirectory.appendingPathComponent("source.txt")
        let retired = sourceDirectory.appendingPathComponent("opened-original.txt")
        let original = Data("ORIGINAL-DESCRIPTOR-CONTENT".utf8)
        let replacement = Data("ATTACKER-REPLACEMENT-CONTEN".utf8)
        XCTAssertEqual(original.count, replacement.count)
        try original.write(to: source)

        var hookError: Error?
        stores.sessions.secureSourceOpenedHook = {
            do {
                try self.fileManager.moveItem(at: source, to: retired)
                try replacement.write(to: source)
            } catch {
                hookError = error
            }
        }
        defer { stores.sessions.secureSourceOpenedHook = nil }

        do {
            let entry = try stores.sessions.importFile(
                at: source,
                originalName: "source.txt",
                into: session
            )
            let imported = try stores.sessions.readEntry(id: entry.id, in: session).data
            XCTAssertEqual(imported, original)
            XCTAssertNotEqual(imported, replacement)
        } catch {
            // A rename can update the opened inode's ctime on some filesystems.
            // Failing closed is equally safe; the replacement must never publish.
            XCTAssertEqual(
                error as? V2VaultSessionFileImportError,
                .sourceChangedDuringImport
            )
            XCTAssertTrue(try stores.sessions.listEntries(in: session).isEmpty)
        }

        XCTAssertNil(hookError)
        XCTAssertEqual(try Data(contentsOf: source), replacement)
    }

    func testSmallImportInPlaceMutationAfterDescriptorOpenFailsClosed() throws {
        let root = try makeRoot()
        let sourceDirectory = try makeDirectory(prefix: "hz-secure-session-mutation")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

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
        let session = try stores.sessions.openSession(
            at: root,
            password: "ordinary-password"
        ).session

        let source = sourceDirectory.appendingPathComponent("changing.txt")
        try Data("stable-source".utf8).write(to: source)

        var hookError: Error?
        stores.sessions.secureSourceOpenedHook = {
            do {
                let writer = try FileHandle(forWritingTo: source)
                try writer.seekToEnd()
                try writer.write(contentsOf: Data("-changed".utf8))
                try writer.synchronize()
                try writer.close()
            } catch {
                hookError = error
            }
        }
        defer { stores.sessions.secureSourceOpenedHook = nil }

        XCTAssertThrowsError(
            try stores.sessions.importFile(at: source, into: session)
        ) { error in
            XCTAssertEqual(
                error as? V2VaultSessionFileImportError,
                .sourceChangedDuringImport
            )
        }
        XCTAssertNil(hookError)
        XCTAssertTrue(try stores.sessions.listEntries(in: session).isEmpty)
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
        let root = try makeDirectory(prefix: "hz-secure-session-root")
        try fileManager.removeItem(at: root)
        return root
    }

    private func makeDirectory(prefix: String) throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "\(prefix)-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }
}
