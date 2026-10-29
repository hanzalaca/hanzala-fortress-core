import XCTest
@testable import HanzalaomatorCore

final class HiddenVaultPolicyTests: XCTestCase {
    func testDistinctPasswordsAreRequired() throws {
        XCTAssertNoThrow(
            try HiddenVaultPolicy.validateDistinctPasswords(
                primary: "visible-password",
                hidden: "hidden-password"
            )
        )

        XCTAssertThrowsError(
            try HiddenVaultPolicy.validateDistinctPasswords(
                primary: "same-password",
                hidden: "same-password"
            )
        ) { error in
            XCTAssertEqual(error as? HiddenVaultPolicyError, .passwordsMustDiffer)
        }
    }

    func testEmptyPasswordsAreRejected() {
        XCTAssertThrowsError(
            try HiddenVaultPolicy.validateDistinctPasswords(primary: "", hidden: "hidden")
        ) { error in
            XCTAssertEqual(error as? HiddenVaultPolicyError, .emptyPrimaryPassword)
        }

        XCTAssertThrowsError(
            try HiddenVaultPolicy.validateDistinctPasswords(primary: "visible", hidden: "")
        ) { error in
            XCTAssertEqual(error as? HiddenVaultPolicyError, .emptyHiddenPassword)
        }
    }

    func testCapacityPlanDoesNotImposeFixedHiddenRatio() throws {
        let smallHidden = try HiddenVaultCapacityPlan(
            totalBytes: 100,
            hiddenBytes: 20,
            protectedReservationBytes: 5
        )
        let largeHidden = try HiddenVaultCapacityPlan(
            totalBytes: 100,
            hiddenBytes: 73,
            protectedReservationBytes: 7
        )

        XCTAssertEqual(smallHidden.outerWritableBytes, 75)
        XCTAssertEqual(largeHidden.outerWritableBytes, 20)
        XCTAssertEqual(smallHidden.hiddenFraction, 0.20, accuracy: 0.0001)
        XCTAssertEqual(largeHidden.hiddenFraction, 0.73, accuracy: 0.0001)
    }

    func testHiddenCapacityMustLeaveVisibleSpace() {
        XCTAssertThrowsError(
            try HiddenVaultCapacityPlan(totalBytes: 100, hiddenBytes: 100)
        ) { error in
            XCTAssertEqual(error as? HiddenVaultPolicyError, .hiddenCapacityMustBeSmallerThanTotal)
        }
    }

    func testProtectedReservationCannotExceedVisibleSpace() {
        XCTAssertThrowsError(
            try HiddenVaultCapacityPlan(
                totalBytes: 100,
                hiddenBytes: 60,
                protectedReservationBytes: 41
            )
        ) { error in
            XCTAssertEqual(error as? HiddenVaultPolicyError, .protectedReservationExceedsOuterSpace)
        }
    }

    func testLockedPresentationDoesNotExposeHiddenState() {
        XCTAssertFalse(HiddenVaultPolicy.exposesHiddenStateWhileLocked)
    }

    func testVisibleSessionMayNotOverwriteHiddenReservation() {
        XCTAssertFalse(HiddenVaultPolicy.permitsOuterOverwriteOfHiddenReservation)
    }
}
