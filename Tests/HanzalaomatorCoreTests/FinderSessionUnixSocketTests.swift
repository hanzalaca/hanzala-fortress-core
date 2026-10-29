import XCTest
import Darwin
@testable import HanzalaomatorCore

final class FinderSessionUnixSocketTests: XCTestCase {
    func testLiveUnixSocketRoundTrip() throws {
        let root = shortTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let sessionID = UUID()
        let socketURL = try FinderSessionUnixSocket.makeSessionSocketURL(
            containerURL: root,
            sessionID: sessionID
        )

        let request = FinderSessionSocketWire.Request(
            sessionID: sessionID,
            operation: .listRoot
        )
        let requestFrame = try FinderSessionSocketWire.encodeFrame(request)

        let listener = try FinderSessionUnixSocket.Listener(socketURL: socketURL) { frame in
            do {
                let decoded = try FinderSessionSocketWire.decodeFrame(
                    FinderSessionSocketWire.Request.self,
                    from: frame
                )
                let response = FinderSessionSocketWire.Response(
                    requestID: decoded.requestID,
                    files: [
                        .init(id: UUID(), name: "visible.txt", byteCount: 42, createdAt: Date(timeIntervalSince1970: 1))
                    ]
                )
                return try FinderSessionSocketWire.encodeFrame(response)
            } catch {
                return Data()
            }
        }
        defer { listener.stop() }

        let responseFrame = try FinderSessionUnixSocket.roundTrip(
            socketURL: socketURL,
            requestFrame: requestFrame
        )
        let response = try FinderSessionSocketWire.decodeFrame(
            FinderSessionSocketWire.Response.self,
            from: responseFrame
        )

        XCTAssertEqual(response.requestID, request.requestID)
        XCTAssertEqual(response.files?.first?.name, "visible.txt")
    }

    func testUnauthorizedPeerIsRejectedBeforeProtocolHandling() throws {
        let root = shortTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let sessionID = UUID()
        let socketURL = try FinderSessionUnixSocket.makeSessionSocketURL(
            containerURL: root,
            sessionID: sessionID
        )
        let requestFrame = try FinderSessionSocketWire.encodeFrame(
            FinderSessionSocketWire.Request(sessionID: sessionID, operation: .listRoot)
        )

        let listener = try FinderSessionUnixSocket.Listener(
            socketURL: socketURL,
            authorizePeer: { _ in false }
        ) { _ in
            // This must never be reached for a rejected peer.
            Data([0xFF])
        }
        defer { listener.stop() }

        XCTAssertThrowsError(
            try FinderSessionUnixSocket.roundTrip(
                socketURL: socketURL,
                requestFrame: requestFrame
            )
        ) { error in
            // Rejection is deliberately allowed to race the client's first write.
            // Depending on scheduling, the client can observe EOF after writing or
            // EPIPE while writing. Both mean the unauthorized peer was closed before
            // protocol handling. Do not accept unrelated transport failures here.
            switch error as? FinderSessionUnixSocketError {
            case .peerClosed:
                break
            case .writeFailed(let code):
                XCTAssertEqual(code, EPIPE)
            default:
                XCTFail("Unexpected unauthorized-peer failure: \(error)")
            }
        }
    }

    func testSocketPathIsCompactSessionScopedAndRemovedOnStop() throws {
        let root = shortTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let first = try FinderSessionUnixSocket.makeSessionSocketURL(containerURL: root, sessionID: UUID())
        let second = try FinderSessionUnixSocket.makeSessionSocketURL(containerURL: root, sessionID: UUID())
        XCTAssertNotEqual(first.deletingLastPathComponent(), second.deletingLastPathComponent())
        XCTAssertEqual(first.lastPathComponent, "x")
        XCTAssertEqual(first.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent, "s")

        let listener = try FinderSessionUnixSocket.Listener(socketURL: first) { $0 }
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.path))
        listener.stop()
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.deletingLastPathComponent().deletingLastPathComponent().path))
    }

    func testNonFileContainerURLFailsClosed() {
        let root = URL(string: "https://example.invalid/finder-session")!
        XCTAssertThrowsError(
            try FinderSessionUnixSocket.makeSessionSocketURL(containerURL: root, sessionID: UUID())
        ) { error in
            XCTAssertEqual(error as? FinderSessionUnixSocketError, .invalidPath)
        }
    }

    func testOverlongSocketPathFailsClosedBeforeListenerCreation() throws {
        let root = URL(fileURLWithPath: "/tmp/" + String(repeating: "a", count: 180), isDirectory: true)
        XCTAssertThrowsError(
            try FinderSessionUnixSocket.makeSessionSocketURL(containerURL: root, sessionID: UUID())
        ) { error in
            XCTAssertEqual(error as? FinderSessionUnixSocketError, .pathTooLong)
        }
    }

    private func shortTemporaryRoot() -> URL {
        URL(fileURLWithPath: "/tmp/hz-\(UUID().uuidString.prefix(8))", isDirectory: true)
    }
}
