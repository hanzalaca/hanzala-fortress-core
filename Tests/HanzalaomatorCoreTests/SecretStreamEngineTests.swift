import XCTest
@testable import HanzalaomatorCore

final class SecretStreamEngineTests: XCTestCase {
    private let fm = FileManager.default

    private func tempURL(_ suffix: String) -> URL {
        fm.temporaryDirectory.appendingPathComponent("hanzala-\(UUID().uuidString)-\(suffix)")
    }

    func testRoundTripAcrossMultipleChunks() throws {
        let engine = SecretStreamEngine()
        let key = try engine.generateKey()
        let input = tempURL("input.bin")
        let encrypted = tempURL("encrypted.hz")
        let output = tempURL("output.bin")
        defer {
            try? fm.removeItem(at: input)
            try? fm.removeItem(at: encrypted)
            try? fm.removeItem(at: output)
        }

        var plaintext = Data()
        for i in 0..<(2 * 1024 * 1024 + 12345) {
            plaintext.append(UInt8(truncatingIfNeeded: i &* 31))
        }
        try plaintext.write(to: input)

        try engine.encryptFile(at: input, to: encrypted, key: key)
        try engine.decryptFile(at: encrypted, to: output, key: key)

        XCTAssertEqual(try Data(contentsOf: output), plaintext)
    }

    func testEmptyFileRoundTrip() throws {
        let engine = SecretStreamEngine()
        let key = try engine.generateKey()
        let input = tempURL("empty.bin")
        let encrypted = tempURL("empty.hz")
        let output = tempURL("empty-out.bin")
        defer {
            try? fm.removeItem(at: input)
            try? fm.removeItem(at: encrypted)
            try? fm.removeItem(at: output)
        }

        try Data().write(to: input)
        try engine.encryptFile(at: input, to: encrypted, key: key)
        try engine.decryptFile(at: encrypted, to: output, key: key)
        XCTAssertEqual(try Data(contentsOf: output), Data())
    }

    func testWrongKeyFailsAndDoesNotPublishPlaintext() throws {
        let engine = SecretStreamEngine()
        let correctKey = try engine.generateKey()
        let wrongKey = try engine.generateKey()
        let input = tempURL("source.bin")
        let encrypted = tempURL("source.hz")
        let output = tempURL("should-not-exist.bin")
        defer {
            try? fm.removeItem(at: input)
            try? fm.removeItem(at: encrypted)
            try? fm.removeItem(at: output)
        }

        try Data("confidential source material".utf8).write(to: input)
        try engine.encryptFile(at: input, to: encrypted, key: correctKey)
        XCTAssertThrowsError(try engine.decryptFile(at: encrypted, to: output, key: wrongKey))
        XCTAssertFalse(fm.fileExists(atPath: output.path))
    }

    func testTamperFailsAndDoesNotPublishPlaintext() throws {
        let engine = SecretStreamEngine()
        let key = try engine.generateKey()
        let input = tempURL("tamper-source.bin")
        let encrypted = tempURL("tamper.hz")
        let output = tempURL("tamper-out.bin")
        defer {
            try? fm.removeItem(at: input)
            try? fm.removeItem(at: encrypted)
            try? fm.removeItem(at: output)
        }

        try Data(repeating: 0x42, count: 128 * 1024).write(to: input)
        try engine.encryptFile(at: input, to: encrypted, key: key)
        var bytes = try Data(contentsOf: encrypted)
        XCTAssertGreaterThan(bytes.count, 64)
        bytes[bytes.count - 8] ^= 0x01
        try bytes.write(to: encrypted)

        XCTAssertThrowsError(try engine.decryptFile(at: encrypted, to: output, key: key))
        XCTAssertFalse(fm.fileExists(atPath: output.path))
    }

    func testTruncationFailsAndDoesNotPublishPlaintext() throws {
        let engine = SecretStreamEngine()
        let key = try engine.generateKey()
        let input = tempURL("truncate-source.bin")
        let encrypted = tempURL("truncate.hz")
        let output = tempURL("truncate-out.bin")
        defer {
            try? fm.removeItem(at: input)
            try? fm.removeItem(at: encrypted)
            try? fm.removeItem(at: output)
        }

        try Data(repeating: 0x7C, count: 2 * 1024 * 1024).write(to: input)
        try engine.encryptFile(at: input, to: encrypted, key: key)
        var bytes = try Data(contentsOf: encrypted)
        bytes.removeLast(min(100, bytes.count))
        try bytes.write(to: encrypted)

        XCTAssertThrowsError(try engine.decryptFile(at: encrypted, to: output, key: key))
        XCTAssertFalse(fm.fileExists(atPath: output.path))
    }
}
