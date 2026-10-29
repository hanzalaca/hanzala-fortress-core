import XCTest
@testable import HanzalaomatorCore

final class V2DurableFileCommitterTests: XCTestCase {
    private let fileManager = FileManager.default

    func testWriteNewPublishesExactBytesAndLeavesNoStagingFile() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("opaque-object")
        let payload = Data("durable ciphertext".utf8)

        try V2DurableFileCommitter(fileManager: fileManager).writeNew(
            payload,
            to: destination,
            stagingPrefix: ".stage-"
        )

        XCTAssertEqual(try Data(contentsOf: destination), payload)
        XCTAssertTrue(try stagingFiles(in: root).isEmpty)
    }

    func testWriteNewNeverReplacesExistingDestination() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("opaque-object")
        let original = Data("existing authenticated object".utf8)
        try original.write(to: destination)

        XCTAssertThrowsError(
            try V2DurableFileCommitter(fileManager: fileManager).writeNew(
                Data("replacement".utf8),
                to: destination,
                stagingPrefix: ".stage-"
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DurableFileCommitError,
                .destinationAlreadyExists
            )
        }

        XCTAssertEqual(try Data(contentsOf: destination), original)
        XCTAssertTrue(try stagingFiles(in: root).isEmpty)
    }

    func testSyncFailureOccursBeforeNewDestinationIsPublished() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("opaque-object")
        let committer = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { _ in throw TestFailure.injected }
        )

        XCTAssertThrowsError(
            try committer.writeNew(
                Data("not committed".utf8),
                to: destination,
                stagingPrefix: ".stage-"
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DurableFileCommitError,
                .stagingSyncFailed
            )
        }

        XCTAssertFalse(fileManager.fileExists(atPath: destination.path))
        XCTAssertTrue(try stagingFiles(in: root).isEmpty)
    }

    func testSyncFailurePreservesExistingDestinationDuringReplacement() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("metadata-anchor")
        let original = Data("generation zero".utf8)
        try original.write(to: destination)
        let committer = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { _ in throw TestFailure.injected }
        )

        XCTAssertThrowsError(
            try committer.replaceExisting(
                Data("generation one".utf8),
                at: destination,
                stagingPrefix: ".metadata-stage-"
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DurableFileCommitError,
                .stagingSyncFailed
            )
        }

        XCTAssertEqual(try Data(contentsOf: destination), original)
        XCTAssertTrue(try stagingFiles(in: root).isEmpty)
    }

    func testReplaceExistingPublishesOnlyAfterSuccessfulSync() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("metadata-anchor")
        try Data("generation zero".utf8).write(to: destination)
        var synchronized = false
        let committer = V2DurableFileCommitter(
            fileManager: fileManager,
            synchronizeFile: { handle in
                try handle.synchronize()
                synchronized = true
            }
        )

        try committer.replaceExisting(
            Data("generation one".utf8),
            at: destination,
            stagingPrefix: ".metadata-stage-"
        )

        XCTAssertTrue(synchronized)
        XCTAssertEqual(
            try Data(contentsOf: destination),
            Data("generation one".utf8)
        )
        XCTAssertTrue(try stagingFiles(in: root).isEmpty)
    }

    func testReplaceRefusesMissingDestination() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let destination = root.appendingPathComponent("missing-anchor")

        XCTAssertThrowsError(
            try V2DurableFileCommitter(fileManager: fileManager).replaceExisting(
                Data("unexpected".utf8),
                at: destination,
                stagingPrefix: ".metadata-stage-"
            )
        ) { error in
            XCTAssertEqual(
                error as? V2DurableFileCommitError,
                .destinationMissing
            )
        }
        XCTAssertTrue(try stagingFiles(in: root).isEmpty)
    }

    private enum TestFailure: Error {
        case injected
    }

    private func makeRoot() throws -> URL {
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-durable-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }

    private func stagingFiles(in root: URL) throws -> [URL] {
        try fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: []
        ).filter { $0.lastPathComponent.contains("stage-") }
    }
}
