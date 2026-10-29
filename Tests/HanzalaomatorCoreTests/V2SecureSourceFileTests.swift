import Foundation
import XCTest
@testable import HanzalaomatorCore

final class V2SecureSourceFileTests: XCTestCase {
    private let fileManager = FileManager.default

    func testRegularFileReadsAndRewindsOnSameDescriptor() throws {
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let source = directory.appendingPathComponent("evidence.txt")
        let content = Data("protected-journalist-material".utf8)
        try content.write(to: source)

        let opened = try V2SecureSourceFile(url: source)
        XCTAssertEqual(opened.byteCount, content.count)
        XCTAssertEqual(try opened.read(upToCount: content.count), content)
        XCTAssertEqual(try opened.read(upToCount: 1), Data())

        try opened.rewind()
        XCTAssertEqual(try opened.read(upToCount: 9), Data("protected".utf8))
        try opened.validateUnchanged()
    }

    func testFinalComponentSymbolicLinkIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target.txt")
        let link = directory.appendingPathComponent("source-link.txt")
        try Data("secret".utf8).write(to: target)
        try fileManager.createSymbolicLink(at: link, withDestinationURL: target)

        XCTAssertThrowsError(try V2SecureSourceFile(url: link)) { error in
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceIsSymbolicLink)
        }
    }

    func testSymbolicLinkAncestorIsRejectedWithoutFollowingIt() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-relative ancestor traversal is Darwin-specific.")
        #else
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }

        let realDirectory = directory.appendingPathComponent("real", isDirectory: true)
        let linkedDirectory = directory.appendingPathComponent("linked", isDirectory: true)
        try fileManager.createDirectory(at: realDirectory, withIntermediateDirectories: false)
        let source = realDirectory.appendingPathComponent("evidence.txt")
        try Data("must-not-follow-ancestor".utf8).write(to: source)
        try fileManager.createSymbolicLink(
            at: linkedDirectory,
            withDestinationURL: realDirectory
        )

        XCTAssertThrowsError(
            try V2SecureSourceFile(
                url: linkedDirectory.appendingPathComponent("evidence.txt")
            )
        ) { error in
            // Ancestor failures intentionally collapse onto the existing generic
            // source-open error rather than exposing which path component failed.
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceOpenFailed)
        }
        #endif
    }

    func testDirectoryIsRejectedAsImportSource() throws {
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }

        XCTAssertThrowsError(try V2SecureSourceFile(url: directory)) { error in
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceNotRegularFile)
        }
    }

    func testPathReplacementAfterOpenCannotRetargetReads() throws {
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let source = directory.appendingPathComponent("source.bin")
        let retired = directory.appendingPathComponent("original.bin")
        let original = Data("original-descriptor-bytes".utf8)
        let replacement = Data("attacker-replacement-data".utf8)
        try original.write(to: source)

        let opened = try V2SecureSourceFile(url: source)

        try fileManager.moveItem(at: source, to: retired)
        try replacement.write(to: source)

        // Reads come from the descriptor opened before the pathname swap. The
        // replacement path is never reopened by this capability.
        XCTAssertEqual(try opened.read(upToCount: original.count), original)
        XCTAssertEqual(try Data(contentsOf: source), replacement)
    }

    func testOpenedAncestorDescriptorCannotBeRetargetedByDirectoryReplacement() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-relative ancestor traversal is Darwin-specific.")
        #else
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }

        let trustedName = "trusted-\(UUID().uuidString)"
        let trusted = directory.appendingPathComponent(trustedName, isDirectory: true)
        let retired = directory.appendingPathComponent("retired", isDirectory: true)
        let attacker = directory.appendingPathComponent("attacker", isDirectory: true)
        try fileManager.createDirectory(at: trusted, withIntermediateDirectories: false)
        try fileManager.createDirectory(at: attacker, withIntermediateDirectories: false)

        let original = Data("original-through-open-directory-fd".utf8)
        let replacement = Data("attacker-through-replacement-path".utf8)
        try original.write(to: trusted.appendingPathComponent("evidence.bin"))
        try replacement.write(to: attacker.appendingPathComponent("evidence.bin"))

        var swapped = false
        let opened = try V2SecureSourceFile(
            url: trusted.appendingPathComponent("evidence.bin"),
            ancestorOpenedHook: { _, component in
                guard component == trustedName, !swapped else { return }
                swapped = true
                try self.fileManager.moveItem(at: trusted, to: retired)
                try self.fileManager.moveItem(at: attacker, to: trusted)
            }
        )

        XCTAssertTrue(swapped)
        XCTAssertEqual(try opened.read(upToCount: original.count), original)
        XCTAssertEqual(
            try Data(contentsOf: trusted.appendingPathComponent("evidence.bin")),
            replacement
        )
        XCTAssertEqual(
            try Data(contentsOf: retired.appendingPathComponent("evidence.bin")),
            original
        )
        #endif
    }

    /// A real iPhone's sandbox refuses to open the system folders above the
    /// app, so a trusted folder the app owns must be where the walk starts.
    func testTrustedDirectoryWalkNeverOpensFoldersAboveIt() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-relative ancestor traversal is Darwin-specific.")
        #else
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let inner = directory.appendingPathComponent("inner", isDirectory: true)
        try fileManager.createDirectory(at: inner, withIntermediateDirectories: false)
        let source = inner.appendingPathComponent("photo.jpg")
        let content = Data("staged-photo".utf8)
        try content.write(to: source)

        var opened: [String] = []
        let file = try V2SecureSourceFile(
            url: source,
            trustedDirectory: directory,
            ancestorOpenedHook: { _, component in opened.append(component) }
        )

        XCTAssertEqual(opened, ["inner"])
        XCTAssertEqual(try file.read(upToCount: content.count), content)
        #endif
    }

    func testTrustedDirectoryDirectChildOpens() throws {
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let source = directory.appendingPathComponent("camera.jpg")
        let content = Data("camera-shot".utf8)
        try content.write(to: source)

        let file = try V2SecureSourceFile(url: source, trustedDirectory: directory)
        XCTAssertEqual(file.byteCount, content.count)
        XCTAssertEqual(try file.read(upToCount: content.count), content)
    }

    func testSourceOutsideTrustedDirectoryIsRejected() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-relative ancestor traversal is Darwin-specific.")
        #else
        let trusted = try makeDirectory()
        let other = try makeDirectory()
        defer {
            try? fileManager.removeItem(at: trusted)
            try? fileManager.removeItem(at: other)
        }
        let source = other.appendingPathComponent("evidence.txt")
        try Data("outside".utf8).write(to: source)

        XCTAssertThrowsError(
            try V2SecureSourceFile(url: source, trustedDirectory: trusted)
        ) { error in
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceOpenFailed)
        }
        #endif
    }

    func testSymbolicLinkBelowTrustedDirectoryIsStillRejected() throws {
        #if !canImport(Darwin)
        throw XCTSkip("Descriptor-relative ancestor traversal is Darwin-specific.")
        #else
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let realDirectory = directory.appendingPathComponent("real", isDirectory: true)
        let linkedDirectory = directory.appendingPathComponent("linked", isDirectory: true)
        try fileManager.createDirectory(at: realDirectory, withIntermediateDirectories: false)
        try Data("must-not-follow".utf8).write(to: realDirectory.appendingPathComponent("evidence.txt"))
        try fileManager.createSymbolicLink(at: linkedDirectory, withDestinationURL: realDirectory)

        XCTAssertThrowsError(
            try V2SecureSourceFile(
                url: linkedDirectory.appendingPathComponent("evidence.txt"),
                trustedDirectory: directory
            )
        ) { error in
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceOpenFailed)
        }
        #endif
    }

    func testInPlaceSizeMutationIsDetectedBeforeReuse() throws {
        let directory = try makeDirectory()
        defer { try? fileManager.removeItem(at: directory) }
        let source = directory.appendingPathComponent("changing.bin")
        try Data("stable".utf8).write(to: source)

        let opened = try V2SecureSourceFile(url: source)
        let writer = try FileHandle(forWritingTo: source)
        try writer.seekToEnd()
        try writer.write(contentsOf: Data("-changed".utf8))
        try writer.synchronize()
        try writer.close()

        XCTAssertThrowsError(try opened.validateUnchanged()) { error in
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceChanged)
        }
        XCTAssertThrowsError(try opened.rewind()) { error in
            XCTAssertEqual(error as? V2SecureSourceFileError, .sourceChanged)
        }
    }

    private func makeDirectory() throws -> URL {
        let directory = fileManager.temporaryDirectory
            .appendingPathComponent("hz-source-fd-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}
