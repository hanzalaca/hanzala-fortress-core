import XCTest
@testable import HanzalaomatorCore

final class StreamFormatTests: XCTestCase {
    func testMagicAndVersionAreFrozen() {
        XCTAssertEqual(String(data: StreamFormat.magic, encoding: .utf8), "HZSTRM01")
        XCTAssertEqual(StreamFormat.version, 1)
    }

    func testUInt32FramingRoundTrip() {
        for value: UInt32 in [0, 1, 1024, UInt32.max] {
            XCTAssertEqual(StreamFormat.decodeUInt32(StreamFormat.encodeUInt32(value)), value)
        }
    }

    func testChunkSizeIsBoundedForLargeFiles() {
        XCTAssertEqual(StreamFormat.defaultPlaintextChunkSize, 1024 * 1024)
    }
}
