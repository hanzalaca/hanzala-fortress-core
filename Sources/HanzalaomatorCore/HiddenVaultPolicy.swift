import Foundation

public enum HiddenVaultPolicyError: Error, Equatable, Sendable {
    case emptyPrimaryPassword
    case emptyHiddenPassword
    case passwordsMustDiffer
    case totalCapacityMustBePositive
    case hiddenCapacityMustBePositive
    case hiddenCapacityMustBeSmallerThanTotal
    case protectedReservationExceedsOuterSpace
}

/// Capacity policy for a future hidden/decoy vault implementation.
///
/// This type deliberately models only capacity and overwrite protection. It does
/// not define an on-disk hidden offset, marker, magic value, or fixed hidden
/// percentage. Those details must remain outside the public format until the
/// authenticated storage design has been reviewed.
public struct HiddenVaultCapacityPlan: Codable, Equatable, Sendable {
    public let totalBytes: UInt64
    public let hiddenBytes: UInt64
    public let protectedReservationBytes: UInt64

    public init(
        totalBytes: UInt64,
        hiddenBytes: UInt64,
        protectedReservationBytes: UInt64 = 0
    ) throws {
        guard totalBytes > 0 else {
            throw HiddenVaultPolicyError.totalCapacityMustBePositive
        }
        guard hiddenBytes > 0 else {
            throw HiddenVaultPolicyError.hiddenCapacityMustBePositive
        }
        guard hiddenBytes < totalBytes else {
            throw HiddenVaultPolicyError.hiddenCapacityMustBeSmallerThanTotal
        }

        let outerSpace = totalBytes - hiddenBytes
        guard protectedReservationBytes <= outerSpace else {
            throw HiddenVaultPolicyError.protectedReservationExceedsOuterSpace
        }

        self.totalBytes = totalBytes
        self.hiddenBytes = hiddenBytes
        self.protectedReservationBytes = protectedReservationBytes
    }

    /// Maximum bytes available to the visible/decoy side after reserving both
    /// hidden capacity and an explicit safety margin.
    public var outerWritableBytes: UInt64 {
        totalBytes - hiddenBytes - protectedReservationBytes
    }

    /// Reporting only. The implementation must never assume a fixed ratio.
    public var hiddenFraction: Double {
        Double(hiddenBytes) / Double(totalBytes)
    }
}

public enum HiddenVaultPolicy {
    /// Hidden and visible vaults must never share the same password. We compare
    /// exact password bytes at this layer and intentionally avoid trimming or
    /// Unicode rewriting that could silently change a user's secret.
    public static func validateDistinctPasswords(primary: String, hidden: String) throws {
        guard !primary.isEmpty else {
            throw HiddenVaultPolicyError.emptyPrimaryPassword
        }
        guard !hidden.isEmpty else {
            throw HiddenVaultPolicyError.emptyHiddenPassword
        }
        guard primary != hidden else {
            throw HiddenVaultPolicyError.passwordsMustDiffer
        }
    }

    /// Locked UI must not advertise whether a hidden vault exists. This is a
    /// product/security contract consumed by future UI work rather than a claim
    /// that plausible deniability is already complete.
    public static let exposesHiddenStateWhileLocked = false

    /// A visible/decoy session must never be allowed to consume the capacity
    /// reserved for hidden data once hidden storage is implemented.
    public static let permitsOuterOverwriteOfHiddenReservation = false
}
