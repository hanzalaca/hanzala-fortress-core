import XCTest
@testable import HanzalaomatorCore

final class V2AccessMetadataTests: XCTestCase {
    func testValidMetadataMatchesLedgerAndOwnedNames() throws {
        let budget = try V2StorageBudget(totalBytes: 10_000, reserveBytes: 2_000)
        let live = String(repeating: "a", count: V2OpaqueObjectName.encodedLength)
        let tombstone = String(repeating: "b", count: V2OpaqueObjectName.encodedLength)
        let entry = V2AccessEntry(
            opaqueObjectName: live,
            originalName: "report.pdf",
            logicalByteCount: 1_200
        )
        let metadata = V2AccessMetadata(
            entries: [entry],
            tombstonedObjectNames: [tombstone],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 1_200, objectCount: 1)
        )

        XCTAssertNoThrow(try metadata.validate())
        XCTAssertEqual(metadata.authenticatedOwnedObjectNames, Set([live, tombstone]))
        XCTAssertEqual(metadata.authenticatedTombstonedObjectNames, Set([tombstone]))
    }

    func testDuplicateEntryIDIsRejected() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let id = UUID()
        let first = V2AccessEntry(
            id: id,
            opaqueObjectName: String(repeating: "1", count: V2OpaqueObjectName.encodedLength),
            originalName: "a.txt",
            logicalByteCount: 10
        )
        let second = V2AccessEntry(
            id: id,
            opaqueObjectName: String(repeating: "2", count: V2OpaqueObjectName.encodedLength),
            originalName: "b.txt",
            logicalByteCount: 20
        )
        let metadata = V2AccessMetadata(
            entries: [first, second],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 30, objectCount: 2)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .duplicateEntryID)
        }
    }

    func testDuplicateObjectNameIsRejected() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let name = String(repeating: "3", count: V2OpaqueObjectName.encodedLength)
        let metadata = V2AccessMetadata(
            entries: [
                V2AccessEntry(opaqueObjectName: name, originalName: "a.txt", logicalByteCount: 10),
                V2AccessEntry(opaqueObjectName: name, originalName: "b.txt", logicalByteCount: 20)
            ],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 30, objectCount: 2)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .duplicateObjectName)
        }
    }

    func testLiveObjectCannotAlsoBeTombstoned() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let name = String(repeating: "4", count: V2OpaqueObjectName.encodedLength)
        let metadata = V2AccessMetadata(
            entries: [V2AccessEntry(
                opaqueObjectName: name,
                originalName: "evidence.jpg",
                logicalByteCount: 50
            )],
            tombstonedObjectNames: [name],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 50, objectCount: 1)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .liveObjectIsTombstoned)
        }
    }

    func testUnsafeOriginalLeafNameIsRejected() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let metadata = V2AccessMetadata(
            entries: [V2AccessEntry(
                opaqueObjectName: String(repeating: "5", count: V2OpaqueObjectName.encodedLength),
                originalName: "../escape.txt",
                logicalByteCount: 10
            )],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 10, objectCount: 1)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .invalidOriginalName)
        }
    }

    func testLedgerByteMismatchIsRejected() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let metadata = V2AccessMetadata(
            entries: [V2AccessEntry(
                opaqueObjectName: String(repeating: "6", count: V2OpaqueObjectName.encodedLength),
                originalName: "file.bin",
                logicalByteCount: 100
            )],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 99, objectCount: 1)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .usageByteMismatch)
        }
    }

    func testLedgerObjectCountMismatchIsRejected() throws {
        let budget = try V2StorageBudget(totalBytes: 1_000, reserveBytes: 100)
        let metadata = V2AccessMetadata(
            entries: [V2AccessEntry(
                opaqueObjectName: String(repeating: "7", count: V2OpaqueObjectName.encodedLength),
                originalName: "file.bin",
                logicalByteCount: 100
            )],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 100, objectCount: 2)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .usageObjectCountMismatch)
        }
    }

    func testUsageAboveBudgetIsRejected() throws {
        let budget = try V2StorageBudget(totalBytes: 100, reserveBytes: 20)
        let metadata = V2AccessMetadata(
            entries: [V2AccessEntry(
                opaqueObjectName: String(repeating: "8", count: V2OpaqueObjectName.encodedLength),
                originalName: "large.bin",
                logicalByteCount: 81
            )],
            budget: budget,
            usage: V2LogicalUsageLedger(logicalBytes: 81, objectCount: 1)
        )

        XCTAssertThrowsError(try metadata.validate()) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .usageExceedsBudget)
        }
    }

    func testPaddingPolicyUsesCoarseBuckets() throws {
        XCTAssertEqual(
            try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
                forEncodedMetadataByteCount: 4_096 - V2PoolObjectCodec.encryptedPayloadHeaderByteCount
            ),
            4_096
        )
        XCTAssertEqual(
            try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
                forEncodedMetadataByteCount: 4_097 - V2PoolObjectCodec.encryptedPayloadHeaderByteCount
            ),
            16_384
        )
    }

    func testPaddingPolicyRejectsMetadataBeyondMaximumPayload() {
        XCTAssertThrowsError(
            try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
                forEncodedMetadataByteCount: V2PoolObjectCodec.maximumPlaintextByteCount
            )
        ) { error in
            XCTAssertEqual(error as? V2AccessMetadataValidationError, .metadataTooLarge)
        }
    }
}
