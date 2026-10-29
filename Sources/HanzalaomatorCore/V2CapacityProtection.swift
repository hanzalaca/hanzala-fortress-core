import Foundation

public enum V2CapacityProtectionError: Error, Equatable, Sendable {
    case totalCapacityMustBePositive
    case reserveMustLeaveWritableSpace
    case safetyMarginExceedsWritableSpace
    case visibleUsageExceedsLimit
    case writeWouldExceedVisibleLimit
    case removalWouldUnderflowUsage
    case removalWouldUnderflowObjectCount
    case arithmeticOverflow
}

/// Generic encrypted capacity policy for a v2 access path.
///
/// `reserveBytes` is intentionally role-neutral. A v2 vault that has no
/// concealed access path may still carry a reserve. Callers must not serialize
/// this structure into public plaintext metadata; it belongs inside authenticated
/// encrypted metadata for the unlocked access path.
public struct V2StorageBudget: Codable, Equatable, Sendable {
    public let totalBytes: UInt64
    public let reserveBytes: UInt64
    public let safetyMarginBytes: UInt64

    public init(
        totalBytes: UInt64,
        reserveBytes: UInt64,
        safetyMarginBytes: UInt64 = 0
    ) throws {
        guard totalBytes > 0 else {
            throw V2CapacityProtectionError.totalCapacityMustBePositive
        }
        guard reserveBytes < totalBytes else {
            throw V2CapacityProtectionError.reserveMustLeaveWritableSpace
        }

        let writableBeforeMargin = totalBytes - reserveBytes
        guard safetyMarginBytes <= writableBeforeMargin else {
            throw V2CapacityProtectionError.safetyMarginExceedsWritableSpace
        }

        self.totalBytes = totalBytes
        self.reserveBytes = reserveBytes
        self.safetyMarginBytes = safetyMarginBytes
    }

    private enum CodingKeys: String, CodingKey {
        case totalBytes, reserveBytes, safetyMarginBytes
    }

    /// Decoding runs the same checks as `init`, so a malformed budget fails
    /// closed instead of underflowing `visibleWritableLimit` later.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            totalBytes: try container.decode(UInt64.self, forKey: .totalBytes),
            reserveBytes: try container.decode(UInt64.self, forKey: .reserveBytes),
            safetyMarginBytes: try container.decode(UInt64.self, forKey: .safetyMarginBytes)
        )
    }

    public var visibleWritableLimit: UInt64 {
        totalBytes - reserveBytes - safetyMarginBytes
    }

    public func validateVisibleUsage(_ visibleBytes: UInt64) throws {
        guard visibleBytes <= visibleWritableLimit else {
            throw V2CapacityProtectionError.visibleUsageExceedsLimit
        }
    }

    /// Returns the admitted post-write logical usage or throws before any write
    /// should be attempted. The calculation is overflow-safe and deliberately
    /// does not consult the contents of reserved storage.
    public func admittingVisibleWrite(
        currentVisibleBytes: UInt64,
        requestedBytes: UInt64
    ) throws -> UInt64 {
        try validateVisibleUsage(currentVisibleBytes)

        let (newUsage, overflow) = currentVisibleBytes.addingReportingOverflow(requestedBytes)
        guard !overflow else {
            throw V2CapacityProtectionError.arithmeticOverflow
        }
        guard newUsage <= visibleWritableLimit else {
            throw V2CapacityProtectionError.writeWouldExceedVisibleLimit
        }
        return newUsage
    }
}

/// Minimal accounting state intended to be stored only inside authenticated
/// encrypted metadata for the currently unlocked access path. It avoids any
/// public directory/file marker for visible vs concealed usage.
public struct V2LogicalUsageLedger: Codable, Equatable, Sendable {
    public let logicalBytes: UInt64
    public let objectCount: UInt64

    public init(logicalBytes: UInt64 = 0, objectCount: UInt64 = 0) {
        self.logicalBytes = logicalBytes
        self.objectCount = objectCount
    }

    public func admittingObject(
        byteCount: UInt64,
        budget: V2StorageBudget
    ) throws -> V2LogicalUsageLedger {
        let nextBytes = try budget.admittingVisibleWrite(
            currentVisibleBytes: logicalBytes,
            requestedBytes: byteCount
        )
        let (nextCount, overflow) = objectCount.addingReportingOverflow(1)
        guard !overflow else {
            throw V2CapacityProtectionError.arithmeticOverflow
        }
        return V2LogicalUsageLedger(logicalBytes: nextBytes, objectCount: nextCount)
    }

    /// Accounting removal is fail-closed. A mismatch means encrypted metadata is
    /// inconsistent and must be repaired explicitly; silently clamping to zero
    /// could grant ordinary writes capacity that was never actually released.
    public func removingObject(byteCount: UInt64) throws -> V2LogicalUsageLedger {
        guard objectCount > 0 else {
            throw V2CapacityProtectionError.removalWouldUnderflowObjectCount
        }
        guard byteCount <= logicalBytes else {
            throw V2CapacityProtectionError.removalWouldUnderflowUsage
        }
        return V2LogicalUsageLedger(
            logicalBytes: logicalBytes - byteCount,
            objectCount: objectCount - 1
        )
    }
}

public extension HiddenVaultCapacityPlan {
    /// Converts the approved hidden-capacity policy into the generic v2 reserve
    /// model. The resulting public field names do not encode a hidden/decoy role.
    /// The value itself must still remain encrypted at rest.
    func v2StorageBudget() throws -> V2StorageBudget {
        let (combinedReserve, overflow) = hiddenBytes.addingReportingOverflow(protectedReservationBytes)
        guard !overflow else {
            throw V2CapacityProtectionError.arithmeticOverflow
        }
        return try V2StorageBudget(
            totalBytes: totalBytes,
            reserveBytes: combinedReserve,
            safetyMarginBytes: 0
        )
    }
}
