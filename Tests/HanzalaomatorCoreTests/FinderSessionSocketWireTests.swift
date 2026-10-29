import XCTest
@testable import HanzalaomatorCore

final class FinderSessionSocketWireTests: XCTestCase {
    func testRequestRoundTripPreservesBoundedReadFields() throws {
        let sessionID = UUID()
        let entryID = UUID()
        let handleID = UUID()
        let request = FinderSessionSocketWire.Request(
            sessionID: sessionID,
            operation: .read,
            entryID: entryID,
            handleID: handleID,
            offset: 42,
            length: 4096
        )

        let frame = try FinderSessionSocketWire.encodeFrame(request)
        let decoded = try FinderSessionSocketWire.decodeFrame(
            FinderSessionSocketWire.Request.self,
            from: frame
        )

        XCTAssertEqual(decoded, request)
        XCTAssertNoThrow(try FinderSessionSocketWire.validateVersion(decoded))
    }

    func testResponseRoundTripPreservesMetadataAndBytes() throws {
        let requestID = UUID()
        let entryID = UUID()
        let file = FinderSessionSocketWire.RemoteFile(
            id: entryID,
            name: "photo.jpg",
            byteCount: 123_456,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let response = FinderSessionSocketWire.Response(
            requestID: requestID,
            files: [file],
            handle: .init(id: UUID(), entryID: entryID),
            data: Data("abcd".utf8)
        )

        let frame = try FinderSessionSocketWire.encodeFrame(response)
        let decoded = try FinderSessionSocketWire.decodeFrame(
            FinderSessionSocketWire.Response.self,
            from: frame
        )

        XCTAssertEqual(decoded, response)
        XCTAssertNoThrow(try FinderSessionSocketWire.validateVersion(decoded))
    }

    func testTruncatedAndTrailingFramesFailClosed() throws {
        let request = FinderSessionSocketWire.Request(
            sessionID: UUID(),
            operation: .listRoot
        )
        let frame = try FinderSessionSocketWire.encodeFrame(request)

        XCTAssertThrowsError(
            try FinderSessionSocketWire.decodeFrame(
                FinderSessionSocketWire.Request.self,
                from: frame.dropLast()
            )
        ) { error in
            XCTAssertEqual(error as? FinderSessionSocketWire.WireError, .truncatedFrame)
        }

        var trailing = frame
        trailing.append(0)
        XCTAssertThrowsError(
            try FinderSessionSocketWire.decodeFrame(
                FinderSessionSocketWire.Request.self,
                from: trailing
            )
        ) { error in
            XCTAssertEqual(error as? FinderSessionSocketWire.WireError, .trailingBytes)
        }
    }

    func testOversizedLengthPrefixIsRejectedBeforePayloadDecode() {
        var oversized = UInt32(FinderSessionSocketWire.maximumPayloadLength + 1).bigEndian
        let frame = Data(bytes: &oversized, count: MemoryLayout<UInt32>.size)

        XCTAssertThrowsError(
            try FinderSessionSocketWire.decodeFrame(
                FinderSessionSocketWire.Request.self,
                from: frame
            )
        ) { error in
            XCTAssertEqual(error as? FinderSessionSocketWire.WireError, .payloadTooLarge)
        }
    }
}
