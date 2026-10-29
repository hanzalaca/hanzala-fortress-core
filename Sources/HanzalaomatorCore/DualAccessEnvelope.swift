import Foundation

public enum VaultAccessRole: UInt8, Sendable {
    case visible = 1
    case concealed = 2
}

/// Public slot metadata intentionally contains no role or enabled-state field.
/// Every v2 envelope carries the same number of slots so the public shape alone
/// does not reveal whether the second access path is real or a dummy.
public struct VaultAccessSlot: Codable, Sendable {
    public let kdf: KDFParameters
    public let wrappedPayload: Data

    public init(kdf: KDFParameters, wrappedPayload: Data) {
        self.kdf = kdf
        self.wrappedPayload = wrappedPayload
    }
}

/// Standalone v2 access envelope. This is not yet wired into `VaultHeader`, so
/// existing v1 vaults and their on-disk layout remain unchanged.
public struct DualAccessEnvelopeV2: Codable, Sendable {
    public static let formatVersion: UInt32 = 2
    public static let fixedSlotCount = 2

    public let formatVersion: UInt32
    public let vaultID: UUID
    public let createdAt: Date
    public let accessSlots: [VaultAccessSlot]

    public init(
        vaultID: UUID,
        createdAt: Date = Date(),
        accessSlots: [VaultAccessSlot]
    ) {
        self.formatVersion = Self.formatVersion
        self.vaultID = vaultID
        self.createdAt = createdAt
        self.accessSlots = accessSlots
    }
}

public struct CreatedDualAccessEnvelope: Sendable {
    public let envelope: DualAccessEnvelopeV2
    public let visibleMasterKey: Data
    public let concealedMasterKey: Data?

    /// Both public slots need indistinguishable storage anchors during v2 vault
    /// bootstrap. In visible-only mode the second element is the dummy slot's
    /// random master key and is deliberately not exposed as `concealedMasterKey`.
    /// The bootstrap layer consumes it once to create a dummy encrypted metadata
    /// anchor, then no persistent reference to that key is retained.
    let storageInitializationMasterKeys: [Data]

    public init(
        envelope: DualAccessEnvelopeV2,
        visibleMasterKey: Data,
        concealedMasterKey: Data?
    ) {
        self.envelope = envelope
        self.visibleMasterKey = visibleMasterKey
        self.concealedMasterKey = concealedMasterKey
        if let concealedMasterKey {
            self.storageInitializationMasterKeys = [visibleMasterKey, concealedMasterKey]
        } else {
            self.storageInitializationMasterKeys = [visibleMasterKey]
        }
    }

    init(
        envelope: DualAccessEnvelopeV2,
        visibleMasterKey: Data,
        concealedMasterKey: Data?,
        storageInitializationMasterKeys: [Data]
    ) {
        self.envelope = envelope
        self.visibleMasterKey = visibleMasterKey
        self.concealedMasterKey = concealedMasterKey
        self.storageInitializationMasterKeys = storageInitializationMasterKeys
    }
}

public struct UnlockedVaultAccess: Sendable {
    public let role: VaultAccessRole
    public let masterKey: Data

    public init(role: VaultAccessRole, masterKey: Data) {
        self.role = role
        self.masterKey = masterKey
    }
}

public enum DualAccessEnvelopeError: Error, Equatable, Sendable {
    case invalidEnvelopeVersion
    case invalidSlotCount
    case invalidPayload
    case invalidPasswordOrCorruptedEnvelope
    case ambiguousPassword
}

public final class DualAccessEnvelopeEngine {
    /// Payload revision 2 cryptographically binds every wrapped slot to the
    /// public vault UUID. Revision 1 carried only role + master key and therefore
    /// allowed an unauthenticated public vaultID edit to go unnoticed by password
    /// unlock. v2 storage remains disabled, so the old foundation payload is not
    /// accepted through a compatibility path.
    private static let payloadVersion: UInt8 = 2
    private static let vaultIDStringByteCount = 36
    private static let payloadByteCount = 2 + vaultIDStringByteCount + 32

    private let keyEngine: PasswordKeyEngine
    private let makeParameters: () throws -> KDFParameters

    public init(keyEngine: PasswordKeyEngine = PasswordKeyEngine()) {
        self.keyEngine = keyEngine
        self.makeParameters = { try keyEngine.makeDefaultParameters() }
    }

    /// Test-only/internal initializer that allows lower-cost KDF parameters while
    /// still generating a fresh independent salt for every access slot.
    init(
        keyEngine: PasswordKeyEngine,
        makeParameters: @escaping () throws -> KDFParameters
    ) {
        self.keyEngine = keyEngine
        self.makeParameters = makeParameters
    }

    /// Creates the same two-slot public shape used by dual-access vaults, but the
    /// second slot is protected by an unretained random password. The dummy slot
    /// key survives only in the returned bootstrap-only key list long enough to
    /// create a matching dummy storage anchor; it is not exposed as a concealed
    /// user access path.
    public func createVisibleOnly(
        password: String,
        vaultID: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> CreatedDualAccessEnvelope {
        let dummyPassword = keyEngine.generateMasterKey().base64EncodedString()
        try HiddenVaultPolicy.validateDistinctPasswords(
            primary: password,
            hidden: dummyPassword
        )

        let visibleMasterKey = keyEngine.generateMasterKey()
        let visibleSlot = try makeSlot(
            role: .visible,
            masterKey: visibleMasterKey,
            password: password,
            vaultID: vaultID
        )

        let dummyMasterKey = keyEngine.generateMasterKey()
        let dummySlot = try makeSlot(
            role: .concealed,
            masterKey: dummyMasterKey,
            password: dummyPassword,
            vaultID: vaultID
        )

        let envelope = DualAccessEnvelopeV2(
            vaultID: vaultID,
            createdAt: createdAt,
            accessSlots: [visibleSlot, dummySlot]
        )
        return CreatedDualAccessEnvelope(
            envelope: envelope,
            visibleMasterKey: visibleMasterKey,
            concealedMasterKey: nil,
            storageInitializationMasterKeys: [visibleMasterKey, dummyMasterKey]
        )
    }

    public func createDualAccess(
        visiblePassword: String,
        concealedPassword: String,
        vaultID: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> CreatedDualAccessEnvelope {
        try HiddenVaultPolicy.validateDistinctPasswords(
            primary: visiblePassword,
            hidden: concealedPassword
        )

        let visibleMasterKey = keyEngine.generateMasterKey()
        let concealedMasterKey = keyEngine.generateMasterKey()

        let visibleSlot = try makeSlot(
            role: .visible,
            masterKey: visibleMasterKey,
            password: visiblePassword,
            vaultID: vaultID
        )
        let concealedSlot = try makeSlot(
            role: .concealed,
            masterKey: concealedMasterKey,
            password: concealedPassword,
            vaultID: vaultID
        )

        let envelope = DualAccessEnvelopeV2(
            vaultID: vaultID,
            createdAt: createdAt,
            accessSlots: [visibleSlot, concealedSlot]
        )
        return CreatedDualAccessEnvelope(
            envelope: envelope,
            visibleMasterKey: visibleMasterKey,
            concealedMasterKey: concealedMasterKey,
            storageInitializationMasterKeys: [visibleMasterKey, concealedMasterKey]
        )
    }

    /// Tries every public slot before returning. Do not early-return on the first
    /// successful slot: keeping the same number of KDF/decrypt attempts avoids a
    /// simple slot-position timing signal at the locked password surface.
    ///
    /// Each successfully decrypted payload must also carry the exact public
    /// `vaultID`. A modified UUID is therefore treated like a wrong password or
    /// damaged envelope rather than silently redirecting recovery namespace
    /// derivation to a different identifier.
    public func unlock(
        envelope: DualAccessEnvelopeV2,
        password: String
    ) throws -> UnlockedVaultAccess {
        guard envelope.formatVersion == DualAccessEnvelopeV2.formatVersion else {
            throw DualAccessEnvelopeError.invalidEnvelopeVersion
        }
        guard envelope.accessSlots.count == DualAccessEnvelopeV2.fixedSlotCount else {
            throw DualAccessEnvelopeError.invalidSlotCount
        }

        var matches: [UnlockedVaultAccess] = []
        matches.reserveCapacity(DualAccessEnvelopeV2.fixedSlotCount)

        for slot in envelope.accessSlots {
            do {
                let plaintext = try keyEngine.unwrapPayload(
                    slot.wrappedPayload,
                    password: password,
                    parameters: slot.kdf
                )
                let decoded = try decodePayload(
                    plaintext,
                    expectedVaultID: envelope.vaultID
                )
                matches.append(decoded)
            } catch {
                // Wrong passwords, damaged slots, malformed payloads, and public
                // vault-ID tampering are deliberately indistinguishable here.
                // Continue so every slot receives the same unlock attempt pattern.
                continue
            }
        }

        if matches.count == 1, let match = matches.first {
            return match
        }
        if matches.count > 1 {
            throw DualAccessEnvelopeError.ambiguousPassword
        }
        throw DualAccessEnvelopeError.invalidPasswordOrCorruptedEnvelope
    }

    /// Re-protects the visible access path under a new password.
    ///
    /// The master key does not change, so encrypted files, metadata anchors and
    /// recovery anchors all stay valid. Bootstrap always writes the visible slot
    /// first, so only slot 0 is rewritten, with a fresh salt and nonce. The
    /// second slot is copied unchanged: the public shape stays the same, and a
    /// visible password change never moves the slot a concealed path would use.
    ///
    /// The result is unlocked with the new password before it is returned. It
    /// must yield exactly this master key on the visible role; a new password
    /// that also opens the second slot fails as `ambiguousPassword`.
    public func replacingVisiblePassword(
        in envelope: DualAccessEnvelopeV2,
        masterKey: Data,
        newPassword: String
    ) throws -> DualAccessEnvelopeV2 {
        guard envelope.formatVersion == DualAccessEnvelopeV2.formatVersion else {
            throw DualAccessEnvelopeError.invalidEnvelopeVersion
        }
        guard envelope.accessSlots.count == DualAccessEnvelopeV2.fixedSlotCount else {
            throw DualAccessEnvelopeError.invalidSlotCount
        }

        let visibleSlot = try makeSlot(
            role: .visible,
            masterKey: masterKey,
            password: newPassword,
            vaultID: envelope.vaultID
        )
        var slots = envelope.accessSlots
        slots[0] = visibleSlot
        let updated = DualAccessEnvelopeV2(
            vaultID: envelope.vaultID,
            createdAt: envelope.createdAt,
            accessSlots: slots
        )

        let check = try unlock(envelope: updated, password: newPassword)
        guard check.role == .visible, check.masterKey == masterKey else {
            throw DualAccessEnvelopeError.invalidPayload
        }
        return updated
    }

    private func makeSlot(
        role: VaultAccessRole,
        masterKey: Data,
        password: String,
        vaultID: UUID
    ) throws -> VaultAccessSlot {
        let parameters = try makeParameters()
        let payload = try encodePayload(
            role: role,
            masterKey: masterKey,
            vaultID: vaultID
        )
        let wrappedPayload = try keyEngine.wrapPayload(
            payload,
            password: password,
            parameters: parameters
        )
        return VaultAccessSlot(kdf: parameters, wrappedPayload: wrappedPayload)
    }

    private func encodePayload(
        role: VaultAccessRole,
        masterKey: Data,
        vaultID: UUID
    ) throws -> Data {
        guard masterKey.count == 32 else {
            throw DualAccessEnvelopeError.invalidPayload
        }

        let vaultIDBytes = Data(vaultID.uuidString.lowercased().utf8)
        guard vaultIDBytes.count == Self.vaultIDStringByteCount else {
            throw DualAccessEnvelopeError.invalidPayload
        }

        var payload = Data([Self.payloadVersion, role.rawValue])
        payload.append(vaultIDBytes)
        payload.append(masterKey)
        guard payload.count == Self.payloadByteCount else {
            throw DualAccessEnvelopeError.invalidPayload
        }
        return payload
    }

    private func decodePayload(
        _ payload: Data,
        expectedVaultID: UUID
    ) throws -> UnlockedVaultAccess {
        guard payload.count == Self.payloadByteCount else {
            throw DualAccessEnvelopeError.invalidPayload
        }

        let bytes = [UInt8](payload)
        guard bytes[0] == Self.payloadVersion,
              let role = VaultAccessRole(rawValue: bytes[1]) else {
            throw DualAccessEnvelopeError.invalidPayload
        }

        let vaultStart = 2
        let vaultEnd = vaultStart + Self.vaultIDStringByteCount
        let vaultBytes = Data(bytes[vaultStart..<vaultEnd])
        guard let vaultString = String(data: vaultBytes, encoding: .utf8),
              let embeddedVaultID = UUID(uuidString: vaultString),
              embeddedVaultID == expectedVaultID else {
            throw DualAccessEnvelopeError.invalidPayload
        }

        let masterKey = Data(bytes[vaultEnd...])
        guard masterKey.count == 32 else {
            throw DualAccessEnvelopeError.invalidPayload
        }
        return UnlockedVaultAccess(role: role, masterKey: masterKey)
    }
}
