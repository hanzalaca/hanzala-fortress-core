import XCTest
@testable import HanzalaomatorCore

final class FinderSessionXPCTests: XCTestCase {
    func testSecureCodingRoundTripForFileAndHandle() throws {
        let fileID = UUID()
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let file = FinderSessionXPCFile(id: fileID, name: "photo.jpg", byteCount: 1234, createdAt: date)
        let fileData = try NSKeyedArchiver.archivedData(withRootObject: file, requiringSecureCoding: true)
        let decodedFile = try XCTUnwrap(
            NSKeyedUnarchiver.unarchivedObject(ofClass: FinderSessionXPCFile.self, from: fileData)
        )
        XCTAssertEqual(decodedFile.id, fileID.uuidString)
        XCTAssertEqual(decodedFile.name, "photo.jpg")
        XCTAssertEqual(decodedFile.byteCount, 1234)
        XCTAssertEqual(decodedFile.createdAt, date)

        let handleID = UUID()
        let handle = FinderSessionXPCHandle(id: handleID, entryID: fileID)
        let handleData = try NSKeyedArchiver.archivedData(withRootObject: handle, requiringSecureCoding: true)
        let decodedHandle = try XCTUnwrap(
            NSKeyedUnarchiver.unarchivedObject(ofClass: FinderSessionXPCHandle.self, from: handleData)
        )
        XCTAssertEqual(decodedHandle.id, handleID.uuidString)
        XCTAssertEqual(decodedHandle.entryID, fileID.uuidString)
    }

    func testExportedServiceUsesOpaqueHandleAndHonorsReadLimit() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FinderSessionXPC-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let vault = try VaultStore().createVault(
            at: root.appendingPathComponent("vault", isDirectory: true),
            password: "test-password"
        )
        let source = root.appendingPathComponent("source.txt")
        try Data("abcdefghij".utf8).write(to: source)
        let entry = try VaultObjectStore().importFile(at: source, into: vault)

        let session = FinderReadOnlySession(
            vault: vault,
            leaseStore: OnDemandPlaintextLeaseStore(
                rootDirectory: root.appendingPathComponent("leases", isDirectory: true)
            )
        )
        let service = FinderSessionXPCService(
            rpc: FinderSessionRPC(session: session, maximumReadLength: 4)
        )

        let openExpectation = expectation(description: "open")
        var remoteHandle: FinderSessionXPCHandle?
        service.open(entryID: entry.id.uuidString) { handle, error in
            XCTAssertNil(error)
            remoteHandle = handle
            openExpectation.fulfill()
        }
        wait(for: [openExpectation], timeout: 1)
        let handle = try XCTUnwrap(remoteHandle)
        XCTAssertNotEqual(handle.id, entry.id.uuidString)
        XCTAssertEqual(session.activeEntryIDs(), [entry.id])

        let readExpectation = expectation(description: "read")
        service.read(handleID: handle.id, entryID: handle.entryID, offset: 2, length: 4) { data, error in
            XCTAssertNil(error)
            XCTAssertEqual(data, Data("cdef".utf8))
            readExpectation.fulfill()
        }
        wait(for: [readExpectation], timeout: 1)

        let oversizedExpectation = expectation(description: "oversized")
        service.read(handleID: handle.id, entryID: handle.entryID, offset: 0, length: 5) { data, error in
            XCTAssertNil(data)
            XCTAssertNotNil(error)
            oversizedExpectation.fulfill()
        }
        wait(for: [oversizedExpectation], timeout: 1)

        let invalidateExpectation = expectation(description: "invalidate")
        service.invalidate { invalidateExpectation.fulfill() }
        wait(for: [invalidateExpectation], timeout: 1)
        XCTAssertTrue(session.activeEntryIDs().isEmpty)
    }
}
