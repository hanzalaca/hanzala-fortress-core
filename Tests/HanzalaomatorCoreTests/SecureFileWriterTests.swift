import XCTest
@testable import HanzalaomatorCore

final class SecureFileWriterTests: XCTestCase {
    private let fm = FileManager.default

    private func tempDirectory() throws -> URL {
        let url = fm.temporaryDirectory
            .appendingPathComponent("hanzala-secure-writer-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func testAtomicWriteCreatesDestinationAndParentDirectories() throws {
        let root = try tempDirectory()
        defer { try? fm.removeItem(at: root) }

        let destination = root
            .appendingPathComponent("nested", isDirectory: true)
            .appendingPathComponent("vault.hanzala", isDirectory: false)
        let payload = Data("first encrypted representation".utf8)

        try SecureFileWriter.atomicallyWrite(payload, to: destination)

        XCTAssertTrue(fm.fileExists(atPath: destination.path))
        XCTAssertEqual(try Data(contentsOf: destination), payload)
    }

    func testAtomicWriteReplacesExistingDestinationCompletely() throws {
        let root = try tempDirectory()
        defer { try? fm.removeItem(at: root) }

        let destination = root.appendingPathComponent("index.hanzala")
        let oldPayload = Data(repeating: 0x11, count: 64 * 1024)
        let newPayload = Data(repeating: 0xA7, count: 3 * 1024 + 17)

        try oldPayload.write(to: destination)
        try SecureFileWriter.atomicallyWrite(newPayload, to: destination)

        XCTAssertEqual(try Data(contentsOf: destination), newPayload)
    }

    func testAtomicWriteLeavesNoHanzalaTemporaryFilesAfterSuccess() throws {
        let root = try tempDirectory()
        defer { try? fm.removeItem(at: root) }

        let destination = root.appendingPathComponent("vault.hanzala")
        try SecureFileWriter.atomicallyWrite(Data("ciphertext".utf8), to: destination)

        let names = try fm.contentsOfDirectory(atPath: root.path)
        XCTAssertFalse(names.contains { $0.hasPrefix(".hanzala-") && $0.hasSuffix(".tmp") })
    }

    func testAtomicWriteSupportsEmptyEncryptedRepresentation() throws {
        let root = try tempDirectory()
        defer { try? fm.removeItem(at: root) }

        let destination = root.appendingPathComponent("empty.hanzala")
        try SecureFileWriter.atomicallyWrite(Data(), to: destination)

        XCTAssertEqual(try Data(contentsOf: destination), Data())
    }

    func testRepeatedReplacementDoesNotAccumulateTemporaryFiles() throws {
        let root = try tempDirectory()
        defer { try? fm.removeItem(at: root) }

        let destination = root.appendingPathComponent("index.hanzala")

        for generation in 0..<20 {
            let payload = Data(repeating: UInt8(truncatingIfNeeded: generation), count: 4096 + generation)
            try SecureFileWriter.atomicallyWrite(payload, to: destination)
            XCTAssertEqual(try Data(contentsOf: destination), payload)
        }

        let names = try fm.contentsOfDirectory(atPath: root.path)
        XCTAssertEqual(names.filter { $0.hasPrefix(".hanzala-") && $0.hasSuffix(".tmp") }.count, 0)
    }
}
