import XCTest
@testable import HanzalaomatorCore

final class VaultFormatDetectorTests: XCTestCase {
    private let fileManager = FileManager.default

    func testDetectsV1HeaderWithoutTryingPassword() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let header = VaultHeader(
            formatVersion: 1,
            vaultID: UUID(),
            createdAt: Date(),
            kdf: KDFParameters(
                salt: Data(repeating: 0x11, count: 16),
                operationsLimit: 2,
                memoryLimit: 32 * 1024 * 1024
            ),
            wrappedMasterKey: Data(repeating: 0x22, count: 64)
        )
        let data = try JSONEncoder().encode(header)
        try data.write(to: VaultLayout.headerURL(in: root))

        XCTAssertEqual(try VaultFormatDetector().detect(at: root), .v1)
    }

    func testDetectsRealV2VaultWithoutExposingAccessRole() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

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
        let bootstrap = V2VaultBootstrapStore(
            fileManager: fileManager,
            envelopeEngine: envelopeEngine,
            metadataStore: metadata
        )
        let budget = try V2StorageBudget(
            totalBytes: 8 * 1024 * 1024,
            reserveBytes: 1024 * 1024
        )
        _ = try bootstrap.createDualAccess(
            at: root,
            visiblePassword: "ordinary-password",
            concealedPassword: "source-password",
            visibleBudget: budget,
            concealedBudget: budget
        )

        XCTAssertEqual(try VaultFormatDetector().detect(at: root), .v2)
    }

    func testRejectsSymlinkHeader() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let target = root.appendingPathComponent("target.json")
        try Data("{\"formatVersion\":1}".utf8).write(to: target)
        try fileManager.createSymbolicLink(
            at: VaultLayout.headerURL(in: root),
            withDestinationURL: target
        )

        XCTAssertThrowsError(try VaultFormatDetector().detect(at: root)) { error in
            XCTAssertEqual(error as? VaultFormatDetectorError, .headerIsNotRegularFile)
        }
    }

    func testRejectsOversizedHeaderBeforeUnboundedRead() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let header = VaultLayout.headerURL(in: root)
        XCTAssertTrue(fileManager.createFile(atPath: header.path, contents: nil))
        let writer = try FileHandle(forWritingTo: header)
        defer { try? writer.close() }
        try writer.truncate(atOffset: UInt64(VaultFormatDetector.maximumHeaderByteCount + 1))

        XCTAssertThrowsError(try VaultFormatDetector().detect(at: root)) { error in
            XCTAssertEqual(error as? VaultFormatDetectorError, .headerTooLarge)
        }
    }

    func testRejectsUnsupportedVersionWithoutFallback() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        try Data("{\"formatVersion\":99}".utf8).write(to: VaultLayout.headerURL(in: root))

        XCTAssertThrowsError(try VaultFormatDetector().detect(at: root)) { error in
            XCTAssertEqual(error as? VaultFormatDetectorError, .unsupportedVersion(99))
        }
    }

    func testRejectsMalformedOrMissingVersion() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        try Data("{\"vaultID\":\"not-a-format-probe\"}".utf8).write(
            to: VaultLayout.headerURL(in: root)
        )

        XCTAssertThrowsError(try VaultFormatDetector().detect(at: root)) { error in
            XCTAssertEqual(error as? VaultFormatDetectorError, .malformedHeader)
        }
    }

    #if canImport(Darwin)
    func testHeaderPathReplacementAfterOpenCannotRetargetDetectedFormat() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let headerURL = VaultLayout.headerURL(in: root)
        try Data("{\"formatVersion\":1}".utf8).write(to: headerURL)
        let displacedURL = root.appendingPathComponent("opened-original-header")

        let detector = VaultFormatDetector()
        var fired = false
        detector.headerOpenedHook = {
            guard !fired else { return }
            fired = true
            try! self.fileManager.moveItem(at: headerURL, to: displacedURL)
            try! Data("{\"formatVersion\":2}".utf8).write(to: headerURL)
        }

        XCTAssertEqual(try detector.detect(at: root), .v1)
        XCTAssertTrue(fired)
        XCTAssertEqual(
            try Data(contentsOf: headerURL),
            Data("{\"formatVersion\":2}".utf8)
        )
    }

    func testRootReplacementAfterHeaderOpenFailsRoutingClosed() throws {
        let root = try makeRoot()
        let displacedRoot = root.deletingLastPathComponent()
            .appendingPathComponent("hz-format-old-\(UUID().uuidString.prefix(8))", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: root)
            try? fileManager.removeItem(at: displacedRoot)
        }

        try Data("{\"formatVersion\":1}".utf8).write(
            to: VaultLayout.headerURL(in: root)
        )

        let detector = VaultFormatDetector()
        var fired = false
        detector.headerOpenedHook = {
            guard !fired else { return }
            fired = true
            try! self.fileManager.moveItem(at: root, to: displacedRoot)
            try! self.fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false
            )
            try! Data("replacement-root".utf8).write(
                to: root.appendingPathComponent("sentinel")
            )
        }

        XCTAssertThrowsError(try detector.detect(at: root)) { error in
            XCTAssertEqual(error as? VaultFormatDetectorError, .headerReadFailed)
        }
        XCTAssertTrue(fired)
        XCTAssertEqual(
            try Data(contentsOf: root.appendingPathComponent("sentinel")),
            Data("replacement-root".utf8)
        )
    }
    #endif

    private func makeRoot() throws -> URL {
        let root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("hz-format-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }
}
