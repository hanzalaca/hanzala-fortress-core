import Foundation

/// Private authenticated payload stored inside a role-neutral v2 recovery object.
///
/// Kept as one shared wire model so ordinary recovery and descriptor-bound unlock
/// recovery cannot drift into subtly different decoders.
struct V2RecoveryAnchorPayload: Codable, Sendable {
    static let formatVersion: UInt32 = 1

    let formatVersion: UInt32
    let vaultID: UUID
    let accessID: UUID
    let roleRawValue: UInt8
    let masterKey: Data

    init(vaultID: UUID, accessID: UUID, access: UnlockedVaultAccess) {
        self.formatVersion = Self.formatVersion
        self.vaultID = vaultID
        self.accessID = accessID
        self.roleRawValue = access.role.rawValue
        self.masterKey = access.masterKey
    }
}
