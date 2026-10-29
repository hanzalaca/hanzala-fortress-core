import Foundation

public enum V2DataObjectPaddingPolicyError: Error, Equatable, Sendable {
    case invalidContentByteCount
    case contentTooLarge
}

/// Coarse authenticated plaintext buckets for v2 data objects.
///
/// The target includes the private encrypted payload header, logical content,
/// and random padding. Callers of the session API do not choose an exact object
/// size; this policy keeps ordinary/decoy and concealed access paths on the same
/// role-neutral allocation behavior.
///
/// This is intentionally a bounded single-object policy. Files larger than the
/// maximum supported v2 pool object remain reserved for the later chunked-file
/// format rather than silently bypassing the padding rules.
public enum V2DataObjectPaddingPolicy {
    public static let plaintextBuckets: [Int] = [
        4 * 1024,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        V2PoolObjectCodec.maximumPlaintextByteCount
    ]

    public static var maximumLogicalContentByteCount: Int {
        V2PoolObjectCodec.maximumPlaintextByteCount
            - V2PoolObjectCodec.encryptedPayloadHeaderByteCount
    }

    public static func targetPlaintextByteCount(forContentByteCount byteCount: Int) throws -> Int {
        guard byteCount >= 0 else {
            throw V2DataObjectPaddingPolicyError.invalidContentByteCount
        }
        guard byteCount <= maximumLogicalContentByteCount else {
            throw V2DataObjectPaddingPolicyError.contentTooLarge
        }

        let (minimumPlaintextByteCount, overflow) = byteCount.addingReportingOverflow(
            V2PoolObjectCodec.encryptedPayloadHeaderByteCount
        )
        guard !overflow else {
            throw V2DataObjectPaddingPolicyError.contentTooLarge
        }
        guard let bucket = plaintextBuckets.first(where: { $0 >= minimumPlaintextByteCount }) else {
            throw V2DataObjectPaddingPolicyError.contentTooLarge
        }
        return bucket
    }
}