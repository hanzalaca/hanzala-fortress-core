import Foundation
import Sodium

public enum VaultKeyError: Error, Equatable {
    case randomGenerationFailed
    case unsupportedKDF
    case invalidKDFParameters
    case keyDerivationFailed
    case masterKeyWrappingFailed
    case invalidPasswordOrCorruptedHeader
}

public final class PasswordKeyEngine {
    private let sodium = Sodium()

    public init() {}

    public func makeDefaultParameters() throws -> KDFParameters {
        try makeParameters(
            operationsLimit: sodium.pwHash.OpsLimitModerate,
            memoryLimit: sodium.pwHash.MemLimitModerate
        )
    }

    func makeParameters(operationsLimit: Int, memoryLimit: Int) throws -> KDFParameters {
        guard operationsLimit > 0, memoryLimit > 0,
              operationsLimit <= sodium.pwHash.OpsLimitSensitive,
              memoryLimit <= sodium.pwHash.MemLimitSensitive else {
            throw VaultKeyError.invalidKDFParameters
        }
        guard let salt = sodium.randomBytes.buf(length: sodium.pwHash.SaltBytes) else {
            throw VaultKeyError.randomGenerationFailed
        }
        return KDFParameters(
            algorithm: "argon2id13",
            salt: Data(salt),
            operationsLimit: UInt64(operationsLimit),
            memoryLimit: UInt64(memoryLimit)
        )
    }

    public func generateMasterKey() -> Data {
        Data(sodium.secretStream.xchacha20poly1305.key())
    }

    /// Authenticates and encrypts arbitrary fixed-format payload data with a
    /// key derived from the supplied password and Argon2id parameters.
    ///
    /// The older master-key API remains as a compatibility wrapper so existing
    /// v1 vault behavior and callers do not change.
    public func wrapPayload(_ payload: Data, password: String, parameters: KDFParameters) throws -> Data {
        let wrappingKey = try deriveWrappingKey(password: password, parameters: parameters)
        let nonce = sodium.secretBox.nonce()
        guard let authenticatedCipherText = sodium.secretBox.seal(
            message: [UInt8](payload),
            secretKey: [UInt8](wrappingKey),
            nonce: nonce
        ) else {
            throw VaultKeyError.masterKeyWrappingFailed
        }
        return Data(nonce + authenticatedCipherText)
    }

    public func unwrapPayload(_ wrappedPayload: Data, password: String, parameters: KDFParameters) throws -> Data {
        let wrappingKey = try deriveWrappingKey(password: password, parameters: parameters)
        guard let payload = sodium.secretBox.open(
            nonceAndAuthenticatedCipherText: [UInt8](wrappedPayload),
            secretKey: [UInt8](wrappingKey)
        ) else {
            throw VaultKeyError.invalidPasswordOrCorruptedHeader
        }
        return Data(payload)
    }

    public func wrapMasterKey(_ masterKey: Data, password: String, parameters: KDFParameters) throws -> Data {
        try wrapPayload(masterKey, password: password, parameters: parameters)
    }

    public func unwrapMasterKey(_ wrappedMasterKey: Data, password: String, parameters: KDFParameters) throws -> Data {
        try unwrapPayload(wrappedMasterKey, password: password, parameters: parameters)
    }

    private func deriveWrappingKey(password: String, parameters: KDFParameters) throws -> Data {
        guard parameters.algorithm == "argon2id13",
              parameters.operationsLimit > 0,
              parameters.memoryLimit > 0,
              parameters.operationsLimit <= UInt64(sodium.pwHash.OpsLimitSensitive),
              parameters.memoryLimit <= UInt64(sodium.pwHash.MemLimitSensitive),
              parameters.salt.count == sodium.pwHash.SaltBytes else {
            throw VaultKeyError.invalidKDFParameters
        }

        guard let key = sodium.pwHash.hash(
            outputLength: sodium.secretBox.KeyBytes,
            passwd: [UInt8](password.utf8),
            salt: [UInt8](parameters.salt),
            opsLimit: Int(parameters.operationsLimit),
            memLimit: Int(parameters.memoryLimit),
            alg: .Argon2ID13
        ) else {
            throw VaultKeyError.keyDerivationFailed
        }
        return Data(key)
    }
}
