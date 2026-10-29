import XCTest
@testable import HanzalaomatorCore

final class V2DataObjectPaddingPolicyTests: XCTestCase {
    func testSmallContentUsesFirstBucket() throws {
        XCTAssertEqual(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(forContentByteCount: 0),
            4 * 1024
        )
        XCTAssertEqual(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(forContentByteCount: 100),
            4 * 1024
        )
    }

    func testBoundaryAccountsForEncryptedPayloadHeader() throws {
        let firstBucket = 4 * 1024
        let exactContent = firstBucket - V2PoolObjectCodec.encryptedPayloadHeaderByteCount
        XCTAssertEqual(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(
                forContentByteCount: exactContent
            ),
            firstBucket
        )
        XCTAssertEqual(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(
                forContentByteCount: exactContent + 1
            ),
            16 * 1024
        )
    }

    func testMaximumLogicalContentFitsFinalBucket() throws {
        XCTAssertEqual(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(
                forContentByteCount: V2DataObjectPaddingPolicy.maximumLogicalContentByteCount
            ),
            V2PoolObjectCodec.maximumPlaintextByteCount
        )
    }

    func testOversizedOrNegativeContentIsRejected() {
        XCTAssertThrowsError(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(
                forContentByteCount: V2DataObjectPaddingPolicy.maximumLogicalContentByteCount + 1
            )
        ) { error in
            XCTAssertEqual(error as? V2DataObjectPaddingPolicyError, .contentTooLarge)
        }

        XCTAssertThrowsError(
            try V2DataObjectPaddingPolicy.targetPlaintextByteCount(forContentByteCount: -1)
        ) { error in
            XCTAssertEqual(error as? V2DataObjectPaddingPolicyError, .invalidContentByteCount)
        }
    }

    func testBucketsAreStrictlyIncreasingAndBounded() {
        let buckets = V2DataObjectPaddingPolicy.plaintextBuckets
        XCTAssertFalse(buckets.isEmpty)
        XCTAssertEqual(buckets.last, V2PoolObjectCodec.maximumPlaintextByteCount)
        for pair in zip(buckets, buckets.dropFirst()) {
            XCTAssertLessThan(pair.0, pair.1)
        }
    }
}