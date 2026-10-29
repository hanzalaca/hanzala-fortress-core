import Foundation
import CryptoKit

public enum V2RecoveryAnchorError: Error, Equatable, Sendable {
    case invalidRecoveryKeyOrCorruptedAnchor
    case invalidMasterKeyLength
    case anchorAlreadyExists
    case malformedPayload
}

public struct V2RecoveredAccess: Sendable {
    public let access: UnlockedVaultAccess
    public let accessID: UUID

    public init(access: UnlockedVaultAccess, accessID: UUID) {
        self.access = access
        self.accessID = accessID
    }
}

/// Derives a deterministic, role-neutral opaque recovery anchor from one
/// 256-bit recovery secret and the public vault identity.
///
/// A recovery attempt therefore never enumerates the shared object pool. The
/// caller can derive exactly one candidate filename from the supplied secret.
/// Different vault IDs produce different anchors even if a recovery secret were
/// accidentally reused across vaults.
public struct V2RecoveryNamespaceLocator: Sendable {
    private static let anchorLabel = Data("hanzala/v2/recovery-anchor".utf8)
    private let keyDeriver: DomainKeyDeriver

    public init(keyDeriver: DomainKeyDeriver = DomainKeyDeriver()) {
        self.keyDeriver = keyDeriver
    }

    public func objectName(recoveryKeyMaterial: Data, vaultID: UUID) throws -> String {
        let namespaceKey: Data
        do {
            namespaceKey = try keyDeriver.derive(
                masterKey: recoveryKeyMaterial,
                purpose: .recoveryNamespaceV2
            )
        } catch {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }

        var message = Self.anchorLabel
        message.append(0)
        message.append(contentsOf: vaultID.uuidString.lowercased().utf8)
        let code = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: namespaceKey)
        )
        return Data(code).map { String(format: "%02x", $0) }.joined()
    }
}

struct V2GeneratedRecoveryCredential: Sendable {
    let displayKey: String
    let keyMaterial: Data
}

/// Stores one recovery capability as an ordinary HZOBJ003 pool object.
///
/// The recovery secret itself is never written to disk. It derives both the
/// opaque anchor name and the AEAD key used by the common v2 pool-object codec.
/// The encrypted payload binds the recovered master key to vault ID, access ID,
/// and encrypted access role. No public recovery/visible/concealed marker is
/// added to the vault envelope or object filename.
public final class V2RecoveryAnchorStore {
    public static let paddedPlaintextByteCount = 4 * 1024

    private let recoveryKeyEngine: RecoveryKeyEngine
    private let locator: V2RecoveryNamespaceLocator
    private let objectStore: V2PoolObjectStore
    private let physicalCapacityGuard: V2PhysicalCapacityGuard
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        recoveryKeyEngine: RecoveryKeyEngine = RecoveryKeyEngine(),
        locator: V2RecoveryNamespaceLocator = V2RecoveryNamespaceLocator(),
        objectStore: V2PoolObjectStore = V2PoolObjectStore(),
        physicalCapacityGuard: V2PhysicalCapacityGuard = V2PhysicalCapacityGuard()
    ) {
        self.recoveryKeyEngine = recoveryKeyEngine
        self.locator = locator
        self.objectStore = objectStore
        self.physicalCapacityGuard = physicalCapacityGuard
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    func generateCredential() -> V2GeneratedRecoveryCredential {
        let generated = recoveryKeyEngine.generateRecoveryKeyMaterial()
        return V2GeneratedRecoveryCredential(
            displayKey: generated.displayKey,
            keyMaterial: generated.keyMaterial
        )
    }

    func objectName(for credential: V2GeneratedRecoveryCredential, vaultID: UUID) throws -> String {
        try locator.objectName(
            recoveryKeyMaterial: credential.keyMaterial,
            vaultID: vaultID
        )
    }

    @discardableResult
    func createAnchor(
        credential: V2GeneratedRecoveryCredential,
        access: UnlockedVaultAccess,
        accessID: UUID,
        vaultID: UUID,
        budget: V2StorageBudget,
        in root: URL
    ) throws -> String {
        guard access.masterKey.count == 32,
              credential.keyMaterial.count == 32 else {
            throw V2RecoveryAnchorError.invalidMasterKeyLength
        }

        let objectName = try objectName(for: credential, vaultID: vaultID)
        let payload = V2RecoveryAnchorPayload(
            vaultID: vaultID,
            accessID: accessID,
            access: access
        )
        let encoded: Data
        do {
            encoded = try encoder.encode(payload)
        } catch {
            throw V2RecoveryAnchorError.malformedPayload
        }

        let physicalBytes = try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
            paddedPlaintextByteCount: Self.paddedPlaintextByteCount
        )
        try physicalCapacityGuard.validateWrite(
            physicalWriteByteCount: physicalBytes,
            budget: budget,
            at: root
        )

        do {
            _ = try objectStore.createObject(
                named: objectName,
                kind: .recovery,
                content: encoded,
                masterKey: credential.keyMaterial,
                in: root,
                paddedPlaintextByteCount: Self.paddedPlaintextByteCount
            )
        } catch V2PoolObjectStoreError.objectAlreadyExists {
            throw V2RecoveryAnchorError.anchorAlreadyExists
        }
        return objectName
    }

    /// Recovers exactly one access capability from the supplied HZRK secret.
    /// Missing anchors, malformed keys, wrong-key authentication, wrong kind,
    /// malformed payload, and vault-ID mismatch intentionally collapse to one
    /// user-visible failure so probing does not reveal why a candidate failed.
    public func recover(
        recoveryKey: String,
        vaultID: UUID,
        in root: URL
    ) throws -> V2RecoveredAccess {
        do {
            let keyMaterial = try recoveryKeyEngine.keyMaterial(from: recoveryKey)
            let objectName = try locator.objectName(
                recoveryKeyMaterial: keyMaterial,
                vaultID: vaultID
            )
            let object = try objectStore.readObject(
                named: objectName,
                masterKey: keyMaterial,
                in: root
            )
            return try decodeRecoveredAccess(
                object,
                expectedVaultID: vaultID
            )
        } catch V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        } catch {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }
    }

    /// Internal descriptor-bound recovery used only while a retained root
    /// capability spans the full v2 unlock transaction. The supplied object
    /// reader never enumerates the shared pool and resolves exactly one derived
    /// recovery anchor relative to that retained root descriptor.
    func recover(
        recoveryKey: String,
        vaultID: UUID,
        using retainedRoot: V2RetainedVaultRoot,
        objectReader: V2RetainedRootObjectReader
    ) throws -> V2RecoveredAccess {
        do {
            let keyMaterial = try recoveryKeyEngine.keyMaterial(from: recoveryKey)
            let objectName = try locator.objectName(
                recoveryKeyMaterial: keyMaterial,
                vaultID: vaultID
            )
            let object = try objectReader.readObject(
                named: objectName,
                masterKey: keyMaterial,
                using: retainedRoot
            )
            return try decodeRecoveredAccess(
                object,
                expectedVaultID: vaultID
            )
        } catch V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        } catch {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }
    }

    private func decodeRecoveredAccess(
        _ object: V2PoolObject,
        expectedVaultID: UUID
    ) throws -> V2RecoveredAccess {
        guard object.kind == .recovery else {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }

        let payload: V2RecoveryAnchorPayload
        do {
            payload = try decoder.decode(V2RecoveryAnchorPayload.self, from: object.content)
        } catch {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }
        guard payload.formatVersion == V2RecoveryAnchorPayload.formatVersion,
              payload.vaultID == expectedVaultID,
              payload.masterKey.count == 32,
              let role = VaultAccessRole(rawValue: payload.roleRawValue) else {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }

        return V2RecoveredAccess(
            access: UnlockedVaultAccess(
                role: role,
                masterKey: payload.masterKey
            ),
            accessID: payload.accessID
        )
    }
}
