import XCTest
@testable import HanzalaomatorCore

final class V2CapacityProtectionTests: XCTestCase {
    func testDecodingRejectsABudgetThatWouldUnderflow() throws {
        let bad = [
            #"{"totalBytes":100,"reserveBytes":100,"safetyMarginBytes":0}"#,
            #"{"totalBytes":100,"reserveBytes":10,"safetyMarginBytes":91}"#,
            #"{"totalBytes":0,"reserveBytes":0,"safetyMarginBytes":0}"#
        ]
        for json in bad {
            XCTAssertThrowsError(try JSONDecoder().decode(V2StorageBudget.self, from: Data(json.utf8)))
        }
        let good = try V2StorageBudget(totalBytes: 100, reserveBytes: 10, safetyMarginBytes: 5)
        let decoded = try JSONDecoder().decode(V2StorageBudget.self, from: JSONEncoder().encode(good))
        XCTAssertEqual(decoded, good)
        XCTAssertEqual(decoded.visibleWritableLimit, 85)
    }

    func testBudgetEnforcesReservedCapacity() throws {
        let budget = try V2StorageBudget(
            totalBytes: 1_000,
            reserveBytes: 300,
            safetyMarginBytes: 50
        )

        XCTAssertEqual(budget.visibleWritableLimit, 650)
        XCTAssertEqual(
            try budget.admittingVisibleWrite(currentVisibleBytes: 600, requestedBytes: 50),
            650
        )

        XCTAssertThrowsError(
            try budget.admittingVisibleWrite(currentVisibleBytes: 600, requestedBytes: 51)
        ) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .writeWouldExceedVisibleLimit)
        }
    }

    func testBudgetRejectsAlreadyInvalidVisibleUsage() throws {
        let budget = try V2StorageBudget(totalBytes: 100, reserveBytes: 25)

        XCTAssertThrowsError(try budget.validateVisibleUsage(76)) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .visibleUsageExceedsLimit)
        }
    }

    func testWriteAdmissionRejectsUInt64Overflow() throws {
        let budget = try V2StorageBudget(
            totalBytes: UInt64.max,
            reserveBytes: 1
        )

        XCTAssertThrowsError(
            try budget.admittingVisibleWrite(
                currentVisibleBytes: UInt64.max - 2,
                requestedBytes: 10
            )
        ) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .arithmeticOverflow)
        }
    }

    func testLedgerTracksLogicalUsageWithoutPublicRoleState() throws {
        let budget = try V2StorageBudget(totalBytes: 10_000, reserveBytes: 2_000)
        let empty = V2LogicalUsageLedger()
        let first = try empty.admittingObject(byteCount: 1_500, budget: budget)
        let second = try first.admittingObject(byteCount: 500, budget: budget)

        XCTAssertEqual(first.logicalBytes, 1_500)
        XCTAssertEqual(first.objectCount, 1)
        XCTAssertEqual(second.logicalBytes, 2_000)
        XCTAssertEqual(second.objectCount, 2)

        let removed = try second.removingObject(byteCount: 500)
        XCTAssertEqual(removed.logicalBytes, 1_500)
        XCTAssertEqual(removed.objectCount, 1)
    }

    func testLedgerRemovalFailsClosedOnAccountingMismatch() {
        let empty = V2LogicalUsageLedger()
        XCTAssertThrowsError(try empty.removingObject(byteCount: 0)) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .removalWouldUnderflowObjectCount)
        }

        let inconsistent = V2LogicalUsageLedger(logicalBytes: 100, objectCount: 1)
        XCTAssertThrowsError(try inconsistent.removingObject(byteCount: 101)) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .removalWouldUnderflowUsage)
        }
    }

    func testHiddenCapacityPlanMapsToGenericReserve() throws {
        let plan = try HiddenVaultCapacityPlan(
            totalBytes: 1_000,
            hiddenBytes: 250,
            protectedReservationBytes: 50
        )
        let budget = try plan.v2StorageBudget()

        XCTAssertEqual(budget.totalBytes, 1_000)
        XCTAssertEqual(budget.reserveBytes, 300)
        XCTAssertEqual(budget.visibleWritableLimit, plan.outerWritableBytes)
    }

    func testSerializedBudgetContainsNoHiddenOrConcealedFieldNames() throws {
        let budget = try V2StorageBudget(
            totalBytes: 2_000,
            reserveBytes: 400,
            safetyMarginBytes: 100
        )
        let data = try JSONEncoder().encode(budget)
        let json = try XCTUnwrap(String(data: data, encoding: .utf8)).lowercased()

        XCTAssertFalse(json.contains("hidden"))
        XCTAssertFalse(json.contains("concealed"))
        XCTAssertTrue(json.contains("reservebytes"))
    }

    func testInvalidBudgetShapesAreRejected() {
        XCTAssertThrowsError(
            try V2StorageBudget(totalBytes: 0, reserveBytes: 0)
        ) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .totalCapacityMustBePositive)
        }

        XCTAssertThrowsError(
            try V2StorageBudget(totalBytes: 100, reserveBytes: 100)
        ) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .reserveMustLeaveWritableSpace)
        }

        XCTAssertThrowsError(
            try V2StorageBudget(totalBytes: 100, reserveBytes: 20, safetyMarginBytes: 81)
        ) { error in
            XCTAssertEqual(error as? V2CapacityProtectionError, .safetyMarginExceedsWritableSpace)
        }
    }
}
