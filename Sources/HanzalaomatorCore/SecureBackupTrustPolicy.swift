import Foundation

/// Security boundary for any current or future remote backup implementation.
///
/// Remote storage is an untrusted ciphertext carrier. Hanzalaomator, HANZALA,
/// and the storage provider must never receive vault master keys, recovery-key
/// material, or any server-side decryption/escrow capability.
public enum SecureBackupTrustPolicy {
    public static let permitsProviderDecryption = false
    public static let permitsHANZALAKeyEscrow = false
    public static let permitsServerSideRecovery = false

    /// Backup integrations may persist only encrypted archive bytes plus
    /// non-secret transport metadata required to store and retrieve them.
    public static func validateRemoteArchive(
        ciphertext: Data,
        containsKeyMaterial: Bool
    ) -> Bool {
        !ciphertext.isEmpty && !containsKeyMaterial
    }
}
