import XCTest
@testable import HanzalaomatorCore

final class V2PhysicalCapacityGuardTests: XCTestCase {
    func testSealedEnvelopeByteCountMatchesCodecOutput() throws {
        let paddedPlaintextByteCount = 4 * 1024
        let expected = try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
            paddedPlaintextByteCount: paddedPlaintextByteCount
        )

        let sealed = try V2PoolObjectCodec().seal(
            kind: .data,
            content: Data("capacity".utf8),
            masterKey: Data(repeating: 0x71, count: 32),
            objectName: String(repeating: "a", count: V2OpaqueObjectName.encodedLength),
            paddedPlaintextByteCount: paddedPlaintextByteCount
        )

        XCTAssertEqual(expected, UInt64(sealed.count))
    }

    func testInvalidSealedEnvelopeTargetIsRejected() throws {
        XCTAssertThrowsError(
            try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
                paddedPlaintextByteCount: V2PoolObjectCodec.encryptedPayloadHeaderByteCount - 1
            )
        ) { error in
            XCTAssertEqual(
                error as? V2PhysicalCapacityGuardError,
                .invalidPhysicalWriteSize
            )
        }
    }

    func testRequiredCapacityIncludesCiphertextReserveAndSafetyMargin() throws {
        let budget = try V2StorageBudget(
            totalBytes: 100_000,
            reserveBytes: 20_000,
            safetyMarginBytes: 5_000
        )
        let guardrail = V2PhysicalCapacityGuard { _ in 100_000 }

        XCTAssertEqual(
            try guardrail.requiredAvailableBytes(
                forPhysicalWriteByteCount: 4_096,
                budget: budget
            ),
            29_096
        )
    }

    func testDataWriteAlsoPreservesControlPlaneHeadroom() throws {
        let budget = try V2StorageBudget(
            totalBytes: 100_000,
            reserveBytes: 20_000,
            safetyMarginBytes: 5_000
        )
        let guardrail = V2PhysicalCapacityGuard { _ in UInt64.max }

        let required = try guardrail.requiredAvailableBytesForDataWrite(
            physicalWriteByteCount: 4_096,
            budget: budget
        )

        XCTAssertEqual(
            required,
            4_096 + 20_000 + 5_000 + V2PhysicalCapacityGuard.controlPlaneHeadroomBytes
        )
    }

    func testExactBoundaryIsAdmitted() throws {
        let budget = try V2StorageBudget(
            totalBytes: 50_000,
            reserveBytes: 10_000,
            safetyMarginBytes: 2_000
        )
        let guardrail = V2PhysicalCapacityGuard { _ in 16_096 }

        XCTAssertNoThrow(
            try guardrail.validateWrite(
                physicalWriteByteCount: 4_096,
                budget: budget,
                at: URL(fileURLWithPath: "/ignored")
            )
        )
    }

    func testInsufficientCapacityFailsClosed() throws {
        let budget = try V2StorageBudget(
            totalBytes: 50_000,
            reserveBytes: 10_000,
            safetyMarginBytes: 2_000
        )
        let guardrail = V2PhysicalCapacityGuard { _ in 16_095 }

        XCTAssertThrowsError(
            try guardrail.validateWrite(
                physicalWriteByteCount: 4_096,
                budget: budget,
                at: URL(fileURLWithPath: "/ignored")
            )
        ) { error in
            XCTAssertEqual(
                error as? V2PhysicalCapacityGuardError,
                .insufficientPhysicalCapacity(
                    requiredBytes: 16_096,
                    availableBytes: 16_095
                )
            )
        }
    }

    func testDataWriteBoundaryIncludesControlPlaneHeadroom() throws {
        let budget = try V2StorageBudget(
            totalBytes: 50_000,
            reserveBytes: 10_000,
            safetyMarginBytes: 2_000
        )
        let required = try V2PhysicalCapacityGuard { _ in UInt64.max }
            .requiredAvailableBytesForDataWrite(
                physicalWriteByteCount: 4_096,
                budget: budget
            )

        let guardrail = V2PhysicalCapacityGuard { _ in required - 1 }
        XCTAssertThrowsError(
            try guardrail.validateDataWrite(
                physicalWriteByteCount: 4_096,
                budget: budget,
                at: URL(fileURLWithPath: "/ignored")
            )
        ) { error in
            XCTAssertEqual(
                error as? V2PhysicalCapacityGuardError,
                .insufficientPhysicalCapacity(
                    requiredBytes: required,
                    availableBytes: required - 1
                )
            )
        }
    }

    func testUnavailableCapacityFailsClosed() throws {
        let budget = try V2StorageBudget(
            totalBytes: 50_000,
            reserveBytes: 10_000
        )
        let guardrail = V2PhysicalCapacityGuard { _ in nil }

        XCTAssertThrowsError(
            try guardrail.validateWrite(
                physicalWriteByteCount: 1,
                budget: budget,
                at: URL(fileURLWithPath: "/ignored")
            )
        ) { error in
            XCTAssertEqual(
                error as? V2PhysicalCapacityGuardError,
                .capacityUnavailable
            )
        }
    }

    func testProviderFailureCollapsesToUnavailableCapacity() throws {
        enum ProviderError: Error { case failed }

        let budget = try V2StorageBudget(
            totalBytes: 50_000,
            reserveBytes: 10_000
        )
        let guardrail = V2PhysicalCapacityGuard { _ in
            throw ProviderError.failed
        }

        XCTAssertThrowsError(
            try guardrail.validateWrite(
                physicalWriteByteCount: 1,
                budget: budget,
                at: URL(fileURLWithPath: "/ignored")
            )
        ) { error in
            XCTAssertEqual(
                error as? V2PhysicalCapacityGuardError,
                .capacityUnavailable
            )
        }
    }

    func testArithmeticOverflowFailsBeforeCapacityProviderRuns() throws {
        let budget = try V2StorageBudget(
            totalBytes: UInt64.max,
            reserveBytes: UInt64.max - 2,
            safetyMarginBytes: 1
        )
        var providerCalled = false
        let guardrail = V2PhysicalCapacityGuard { _ in
            providerCalled = true
            return UInt64.max
        }

        XCTAssertThrowsError(
            try guardrail.validateWrite(
                physicalWriteByteCount: 3,
                budget: budget,
                at: URL(fileURLWithPath: "/ignored")
            )
        ) { error in
            XCTAssertEqual(
                error as? V2PhysicalCapacityGuardError,
                .arithmeticOverflow
            )
        }
        XCTAssertFalse(providerCalled)
    }
}
