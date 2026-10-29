import XCTest
@testable import HanzalaomatorCore

final class V2StreamingChunkImportTests: XCTestCase {
    private let fileManager = FileManager.default

    func testStreamingImportPublishesLargeFileWithoutWholeFileDataInput() throws {
        let root = try makeDirectory(prefix: "hanzala-v2-streaming-vault")
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-streaming-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let source = sourceDirectory.appendingPathComponent("large-evidence.mov")
        let byteCount = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        try writeRepeatingFile(at: source, byte: 0xA7, byteCount: byteCount)

        let key = Data(repeating: 0xA1, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let objectStore = V2PoolObjectStore(fileManager: fileManager)
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
            reserveBytes: 8 * 1024 * 1024
        )
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        let entry = try V2ChunkOwnershipTransactionCoordinator(
            metadataStore: metadataStore,
            objectStore: objectStore
        ).importChunkedFile(
            at: source,
            originalName: "large-evidence.mov",
            masterKey: key,
            in: root
        )

        XCTAssertEqual(entry.logicalByteCount, UInt64(byteCount))
        XCTAssertFalse(entry.auxiliaryObjectNames.isEmpty)
        XCTAssertLessThanOrEqual(
            V2ChunkOwnershipTransactionCoordinator.maximumStreamingReadByteCount,
            V2ChunkManifest.chunkPaddedPlaintextByteCount
        )

        let reader = V2ChunkedFileReader(objectStore: objectStore)
        let boundary = UInt64(V2ChunkManifest.maximumLogicalChunkByteCount)
        let range = try reader.read(
            entry: entry,
            offset: boundary - 19,
            length: 73,
            masterKey: key,
            in: root
        )
        XCTAssertEqual(range, Data(repeating: 0xA7, count: 73))
        XCTAssertNoThrow(
            try reader.verifyWholeFile(entry: entry, masterKey: key, in: root)
        )

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertEqual(metadata.entries, [entry])
        XCTAssertTrue(metadata.pendingChunkImports.isEmpty)
        XCTAssertEqual(metadata.usage.logicalBytes, UInt64(byteCount))
        XCTAssertEqual(metadata.usage.objectCount, 1)
    }

    func testSourceMutationBetweenPassesRollsBackClaimedChunksAndAbortsPendingMetadata() throws {
        let root = try makeDirectory(prefix: "hanzala-v2-streaming-mutation-vault")
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-streaming-mutation-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let source = sourceDirectory.appendingPathComponent("changing-source.bin")
        let byteCount = V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
        try writeRepeatingFile(at: source, byte: 0x31, byteCount: byteCount)

        let key = Data(repeating: 0xA2, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let objectStore = V2PoolObjectStore(fileManager: fileManager)
        let budget = try V2StorageBudget(
            totalBytes: 96 * 1024 * 1024,
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
        coordinator.streamingPassBoundaryHook = {
            guard let handle = try? FileHandle(forWritingTo: source) else {
                return
            }
            defer { try? handle.close() }
            do {
                try handle.seek(toOffset: 0)
                try handle.write(contentsOf: Data([0x99]))
                try handle.synchronize()
            } catch {
                XCTFail("Failed to mutate streaming test source: \(error)")
            }
        }

        XCTAssertThrowsError(
            try coordinator.importChunkedFile(
                at: source,
                originalName: "changing-source.bin",
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
        XCTAssertTrue(metadata.authenticatedOwnedObjectNames.isEmpty)
        XCTAssertEqual(metadata.usage, V2LogicalUsageLedger())
    }

    func testStreamingImportRejectsSymbolicLinkSourceBeforeClaim() throws {
        let root = try makeDirectory(prefix: "hanzala-v2-streaming-symlink-vault")
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-streaming-symlink-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let target = sourceDirectory.appendingPathComponent("target.bin")
        try Data(repeating: 0x11, count: 1_024).write(to: target)
        let link = sourceDirectory.appendingPathComponent("source-link.bin")
        try fileManager.createSymbolicLink(at: link, withDestinationURL: target)

        let key = Data(repeating: 0xA3, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let budget = try V2StorageBudget(totalBytes: 1_000_000, reserveBytes: 100_000)
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        XCTAssertThrowsError(
            try V2ChunkOwnershipTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: V2PoolObjectStore(fileManager: fileManager)
            ).importChunkedFile(
                at: link,
                originalName: "source-link.bin",
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2ChunkOwnershipTransactionError,
                .sourceIsSymbolicLink
            )
        }

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(metadata.pendingChunkImports.isEmpty)
        XCTAssertTrue(metadata.entries.isEmpty)
    }

    func testStreamingImportRejectsSmallFileWithoutCreatingPendingClaim() throws {
        let root = try makeDirectory(prefix: "hanzala-v2-streaming-small-vault")
        let sourceDirectory = try makeDirectory(prefix: "hanzala-v2-streaming-small-source")
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: sourceDirectory)
        }

        let source = sourceDirectory.appendingPathComponent("small.bin")
        try Data(repeating: 0x22, count: 4_096).write(to: source)

        let key = Data(repeating: 0xA4, count: 32)
        let metadataStore = V2AccessMetadataStore(fileManager: fileManager)
        let budget = try V2StorageBudget(totalBytes: 1_000_000, reserveBytes: 100_000)
        _ = try metadataStore.createInitialEmpty(
            budget: budget,
            masterKey: key,
            in: root
        )

        XCTAssertThrowsError(
            try V2ChunkOwnershipTransactionCoordinator(
                metadataStore: metadataStore,
                objectStore: V2PoolObjectStore(fileManager: fileManager)
            ).importChunkedFile(
                at: source,
                originalName: "small.bin",
                masterKey: key,
                in: root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2ChunkOwnershipTransactionError,
                .chunkingNotRequired
            )
        }

        let metadata = try metadataStore.read(masterKey: key, in: root)
        XCTAssertTrue(metadata.pendingChunkImports.isEmpty)
        XCTAssertTrue(metadata.entries.isEmpty)
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
        let fullBlock = Data(repeating: byte, count: blockSize)
        var remaining = byteCount
        while remaining > 0 {
            let next = min(blockSize, remaining)
            if next == blockSize {
                try handle.write(contentsOf: fullBlock)
            } else {
                try handle.write(contentsOf: Data(repeating: byte, count: next))
            }
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
