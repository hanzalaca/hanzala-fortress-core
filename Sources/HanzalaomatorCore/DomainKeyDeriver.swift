import Foundation
import CryptoKit

public enum DomainKeyError: Error, Equatable {
    case invalidMasterKeyLength
}

public enum DomainKeyPurpose: String, Sendable {
    case indexV1 = "hanzala/index/v1"
    case objectV1 = "hanzala/object/v1"
    case namespaceV2 = "hanzala/namespace/v2"
    case recoveryNamespaceV2 = "hanzala/recovery-namespace/v2"
    case poolObjectV2 = "hanzala/pool-object/v2"
}

public struct DomainKeyDeriver: Sendable {
    public init() {}

    public func derive(masterKey: Data, purpose: DomainKeyPurpose) throws -> Data {
        guard masterKey.count == 32 else {
            throw DomainKeyError.invalidMasterKeyLength
        }

        let inputKey = SymmetricKey(data: masterKey)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: Data(),
            info: Data(purpose.rawValue.utf8),
            outputByteCount: 32
        )

        return derived.withUnsafeBytes { Data($0) }
    }
}
