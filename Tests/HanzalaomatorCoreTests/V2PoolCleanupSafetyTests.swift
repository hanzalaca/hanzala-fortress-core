import XCTest
@testable import HanzalaomatorCore

final class V2PoolCleanupSafetyTests: XCTestCase {
    func testGeneratedOpaqueNamesAreRoleNeutralAndValid() throws {
        let first = try V2OpaqueObjectName.generate()
        let second = try V2OpaqueObjectName.generate()

        XCTAssertTrue(V2OpaqueObjectName.isValid(first))
        XCTAssertTrue(V2OpaqueObjectName.isValid(second))
        XCTAssertEqual(first.count, V2OpaqueObjectName.encodedLength)
        XCTAssertNotEqual(first, second)
        XCTAssertFalse(first.contains("hidden"))
        XCTAssertFalse(first.contains("decoy"))
        XCTAssertFalse(first.contains("index"))
    }

    func testValidatedURLRejectsTraversalAndNonOpaqueNames() throws {
        let root = URL(fileURLWithPath: "/tmp/example-vault")

        XCTAssertThrowsError(
            try V2OpaqueObjectName.validatedURL(named: "../vault.hanzala", in: root)
        ) { error in
            XCTAssertEqual(error as? V2OpaqueObjectNameError, .invalidName)
        }

        let valid = String(repeating: "a", count: V2OpaqueObjectName.encodedLength)
        let url = try V2OpaqueObjectName.validatedURL(named: valid, in: root)
        XCTAssertEqual(url.lastPathComponent, valid)
        XCTAssertEqual(url.deletingLastPathComponent().lastPathComponent, VaultLayout.objectsDirectoryName)
    }

    func testUnknownObjectIsNeverDeletable() {
        let policy = V2PoolCleanupPolicy()
        let unknown = String(repeating: "1", count: V2OpaqueObjectName.encodedLength)

        let decision = policy.decision(
            for: unknown,
            authenticatedOwnedObjectNames: [],
            authenticatedTombstonedObjectNames: [unknown]
        )

        XCTAssertEqual(decision, .preserveUnknown)
    }

    func testOwnedLiveObjectIsPreserved() {
        let policy = V2PoolCleanupPolicy()
        let owned = String(repeating: "2", count: V2OpaqueObjectName.encodedLength)

        let decision = policy.decision(
            for: owned,
            authenticatedOwnedObjectNames: [owned],
            authenticatedTombstonedObjectNames: []
        )

        XCTAssertEqual(decision, .preserveLiveOwned)
    }

    func testOnlyOwnedAuthenticatedTombstoneCanBeDeleted() {
        let policy = V2PoolCleanupPolicy()
        let deletable = String(repeating: "3", count: V2OpaqueObjectName.encodedLength)
        let unknown = String(repeating: "4", count: V2OpaqueObjectName.encodedLength)
        let live = String(repeating: "5", count: V2OpaqueObjectName.encodedLength)
        let invalid = "not-an-opaque-object-name"

        let result = policy.deletableObjectNames(
            from: [deletable, unknown, live, invalid],
            authenticatedOwnedObjectNames: [deletable, live],
            authenticatedTombstonedObjectNames: [deletable, unknown]
        )

        XCTAssertEqual(result, [deletable])
    }

    func testTombstoneWithoutAuthenticatedOwnershipCannotDeleteAnotherAccessPathObject() {
        let policy = V2PoolCleanupPolicy()
        let otherAccessObject = String(repeating: "6", count: V2OpaqueObjectName.encodedLength)

        let result = policy.deletableObjectNames(
            from: [otherAccessObject],
            authenticatedOwnedObjectNames: [],
            authenticatedTombstonedObjectNames: [otherAccessObject]
        )

        XCTAssertTrue(result.isEmpty)
    }
}
