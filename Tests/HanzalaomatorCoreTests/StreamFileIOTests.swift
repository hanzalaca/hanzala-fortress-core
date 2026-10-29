import XCTest
@testable import HanzalaomatorCore

final class StreamFileIOTests: XCTestCase {
    func testOversizedFrameIsRejectedBeforeAllocation() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(atPath: url.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: url) }

        let writer = try FileHandle(forWritingTo: url)
        let oversized = UInt32(StreamFileIO.maximumCiphertextFrameSize + 1)
        try writer.write(contentsOf: StreamFormat.encodeUInt32(oversized))
        try writer.close()

        let reader = try FileHandle(forReadingFrom: url)
        defer { try? reader.close() }
        XCTAssertThrowsError(try StreamFileIO.readFrame(from: reader))
    }

    func testTruncatedFrameIsRejected() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        var bytes = StreamFormat.encodeUInt32(100)
        bytes.append(Data(repeating: 0xAA, count: 10))
        try bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let reader = try FileHandle(forReadingFrom: url)
        defer { try? reader.close() }
        XCTAssertThrowsError(try StreamFileIO.readFrame(from: reader))
    }

    func testFrameRoundTrip() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(atPath: url.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: url) }

        let payload = Data(repeating: 0x5A, count: 8192)
        let writer = try FileHandle(forWritingTo: url)
        try StreamFileIO.writeFrame(payload, to: writer)
        try writer.close()

        let reader = try FileHandle(forReadingFrom: url)
        defer { try? reader.close() }
        XCTAssertEqual(try StreamFileIO.readFrame(from: reader), payload)
    }
}
