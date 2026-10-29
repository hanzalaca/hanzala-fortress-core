import Foundation

public enum V2PhysicalCapacityGuardError: Error, Equatable, Sendable {
    case capacityUnavailable
    case invalidPhysicalWriteSize
    case arithmeticOverflow
    case insufficientPhysicalCapacity(requiredBytes: UInt64, availableBytes: UInt64)
}

/// Conservative host-volume free-space admission guard for v2 ciphertext writes.
///
/// `V2StorageBudget` remains authenticated logical accounting. This guard adds a
/// separate physical check so an ordinary write is not intentionally started when
/// doing so would consume the access path's encrypted `reserveBytes` or
/// `safetyMarginBytes`.
///
/// A narrowly-scoped recovery admission also exists for authenticated
/// space-releasing metadata transitions. It requires enough room for the exact new
/// metadata ciphertext but does not require the ordinary reserve to remain free;
/// otherwise external disk pressure could prevent the vault from deleting its own
/// authenticated objects to recover space. The metadata store, not arbitrary
/// callers, decides which transitions qualify for that exception.
///
/// This is deliberately *not* described as a physical partition or hard hidden
/// allocation. APFS snapshots, other processes, cloud/versioning behavior, and a
/// hostile OS can consume capacity after a check. Every filesystem write must
/// still fail closed if the operating system later reports ENOSPC or another I/O
/// error.
public final class V2PhysicalCapacityGuard {
    public typealias AvailableCapacityProvider = (URL) throws -> UInt64?

    /// Data/manifest writes are followed by authenticated metadata transitions.
    /// Preserve enough additional free space for one maximum-sized metadata
    /// staging envelope so a successful data admission does not immediately make
    /// its required pending->live/recovery transition impossible at the boundary.
    public static let controlPlaneHeadroomBytes = UInt64(
        V2PoolObjectCodec.maximumEnvelopeByteCount
    )

    private let availableCapacityProvider: AvailableCapacityProvider

    public init(
        availableCapacityProvider: @escaping AvailableCapacityProvider = V2PhysicalCapacityGuard.systemAvailableCapacity
    ) {
        self.availableCapacityProvider = availableCapacityProvider
    }

    /// Computes the public ciphertext-envelope size for a v2 object whose
    /// authenticated plaintext has already been assigned a padding target.
    /// XChaCha20-Poly1305's nonce/tag plus the generic object magic form a fixed
    /// overhead, so this does not require sealing the object twice.
    public static func sealedEnvelopeByteCount(
        paddedPlaintextByteCount: Int
    ) throws -> UInt64 {
        guard paddedPlaintextByteCount >= V2PoolObjectCodec.encryptedPayloadHeaderByteCount,
              paddedPlaintextByteCount <= V2PoolObjectCodec.maximumPlaintextByteCount else {
            throw V2PhysicalCapacityGuardError.invalidPhysicalWriteSize
        }

        let overhead = V2PoolObjectCodec.maximumEnvelopeByteCount
            - V2PoolObjectCodec.maximumPlaintextByteCount
        let (total, overflow) = paddedPlaintextByteCount.addingReportingOverflow(overhead)
        guard !overflow, total >= 0 else {
            throw V2PhysicalCapacityGuardError.arithmeticOverflow
        }
        return UInt64(total)
    }

    /// Returns the minimum host-volume free capacity that must exist immediately
    /// before one ordinary staging/ciphertext write starts.
    public func requiredAvailableBytes(
        forPhysicalWriteByteCount physicalWriteByteCount: UInt64,
        budget: V2StorageBudget
    ) throws -> UInt64 {
        let (reserveWithMargin, reserveOverflow) = budget.reserveBytes.addingReportingOverflow(
            budget.safetyMarginBytes
        )
        guard !reserveOverflow else {
            throw V2PhysicalCapacityGuardError.arithmeticOverflow
        }

        let (required, requiredOverflow) = physicalWriteByteCount.addingReportingOverflow(
            reserveWithMargin
        )
        guard !requiredOverflow else {
            throw V2PhysicalCapacityGuardError.arithmeticOverflow
        }
        return required
    }

    /// Data-plane admission also leaves a bounded control-plane cushion for the
    /// authenticated metadata write that must follow object creation.
    public func requiredAvailableBytesForDataWrite(
        physicalWriteByteCount: UInt64,
        budget: V2StorageBudget
    ) throws -> UInt64 {
        let (withHeadroom, overflow) = physicalWriteByteCount.addingReportingOverflow(
            Self.controlPlaneHeadroomBytes
        )
        guard !overflow else {
            throw V2PhysicalCapacityGuardError.arithmeticOverflow
        }
        return try requiredAvailableBytes(
            forPhysicalWriteByteCount: withHeadroom,
            budget: budget
        )
    }

    /// Fails before an ordinary physical staging/control-plane write when free
    /// space is below the reserve-preserving boundary.
    public func validateWrite(
        physicalWriteByteCount: UInt64,
        budget: V2StorageBudget,
        at root: URL
    ) throws {
        let required = try requiredAvailableBytes(
            forPhysicalWriteByteCount: physicalWriteByteCount,
            budget: budget
        )
        try validateMeasuredCapacity(requiredBytes: required, at: root)
    }

    /// Fails before a data/manifest object write while additionally preserving
    /// control-plane headroom for a later authenticated metadata transition.
    public func validateDataWrite(
        physicalWriteByteCount: UInt64,
        budget: V2StorageBudget,
        at root: URL
    ) throws {
        let required = try requiredAvailableBytesForDataWrite(
            physicalWriteByteCount: physicalWriteByteCount,
            budget: budget
        )
        try validateMeasuredCapacity(requiredBytes: required, at: root)
    }

    /// Internal emergency admission for a metadata transition that has already
    /// been proven by `V2AccessMetadataStore` to be one exact removal claim or
    /// removal finalization. It may temporarily consume free space that would
    /// normally be protected by the encrypted reserve, but it still requires the
    /// complete new ciphertext staging allocation to fit before any write begins.
    ///
    /// Keeping this internal prevents arbitrary data/import callers from opting
    /// themselves into the low-space exception.
    func validateSpaceReleasingMetadataWrite(
        physicalWriteByteCount: UInt64,
        at root: URL
    ) throws {
        try validateMeasuredCapacity(
            requiredBytes: physicalWriteByteCount,
            at: root
        )
    }

    private func validateMeasuredCapacity(requiredBytes: UInt64, at root: URL) throws {
        let available: UInt64
        do {
            guard let measured = try availableCapacityProvider(root) else {
                throw V2PhysicalCapacityGuardError.capacityUnavailable
            }
            available = measured
        } catch let error as V2PhysicalCapacityGuardError {
            throw error
        } catch {
            throw V2PhysicalCapacityGuardError.capacityUnavailable
        }

        guard available >= requiredBytes else {
            throw V2PhysicalCapacityGuardError.insufficientPhysicalCapacity(
                requiredBytes: requiredBytes,
                availableBytes: available
            )
        }
    }

    /// System provider used by production. Prefer APFS/Foundation's capacity for
    /// important usage; fall back to the filesystem free-size attribute when the
    /// richer value is unavailable on a supported host/filesystem.
    public static func systemAvailableCapacity(at root: URL) throws -> UInt64? {
        let values = try root.resourceValues(forKeys: [
            .volumeAvailableCapacityForImportantUsageKey
        ])
        if let important = values.volumeAvailableCapacityForImportantUsage,
           important >= 0 {
            return UInt64(important)
        }

        let attributes = try FileManager.default.attributesOfFileSystem(
            forPath: root.path
        )
        if let number = attributes[.systemFreeSize] as? NSNumber {
            return number.uint64Value
        }
        return nil
    }
}
