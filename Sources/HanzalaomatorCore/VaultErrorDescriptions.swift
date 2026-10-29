import Foundation

extension VaultStoreError: CustomStringConvertible, LocalizedError {
    public var description: String {
        switch self {
        case .rootAlreadyContainsVault: return "Vault folder already contains a Hanzalaomator vault."
        case .missingHeader: return "Vault reopen failed: vault.hanzala is missing."
        case .invalidHeader: return "Vault reopen failed: vault.hanzala could not be decoded."
        case .missingIndex: return "Vault reopen failed: index.hanzala is missing."
        case .missingObjectsDirectory: return "Vault reopen failed: objects directory is missing or is not a directory."
        }
    }

    public var errorDescription: String? { description }
}

extension VaultKeyError: CustomStringConvertible, LocalizedError {
    public var description: String {
        switch self {
        case .randomGenerationFailed: return "Vault key error: secure random generation failed."
        case .unsupportedKDF: return "Vault reopen failed: unsupported password KDF."
        case .invalidKDFParameters: return "Vault reopen failed: invalid password KDF parameters in vault.hanzala."
        case .keyDerivationFailed: return "Vault reopen failed: password key derivation failed."
        case .masterKeyWrappingFailed: return "Vault key error: master-key wrapping failed."
        case .invalidPasswordOrCorruptedHeader: return "Vault reopen failed: password is incorrect or vault.hanzala is corrupted."
        }
    }

    public var errorDescription: String? { description }
}

extension EncryptedIndexError: CustomStringConvertible, LocalizedError {
    public var description: String {
        switch self {
        case .invalidKeyLength: return "Vault reopen failed: derived index key has an invalid length."
        case .encryptionFailed: return "Encrypted index write failed."
        case .authenticationFailed: return "Vault reopen failed: index.hanzala authentication failed. The index may be corrupted or not belong to this vault key."
        case .malformedIndex: return "Vault reopen failed: index.hanzala is malformed."
        case .unsupportedVersion: return "Vault reopen failed: index.hanzala uses an unsupported format version."
        }
    }

    public var errorDescription: String? { description }
}

extension VaultObjectStoreError: CustomStringConvertible, LocalizedError {
    public var description: String {
        switch self {
        case .missingIndex: return "Vault object error: index.hanzala is missing."
        case .missingObject: return "Vault object error: an encrypted .hzo object referenced by the index is missing."
        case .entryNotFound: return "Vault object error: selected entry is not present in the encrypted index."
        case .invalidSourceFile: return "Vault import error: selected source is not a regular file."
        }
    }

    public var errorDescription: String? { description }
}

extension StreamCryptoError: CustomStringConvertible, LocalizedError {
    public var description: String {
        switch self {
        case .invalidKeyLength: return "Encrypted object error: invalid key length."
        case .malformedHeader: return "Encrypted object error: malformed stream header."
        case .unsupportedVersion: return "Encrypted object error: unsupported stream version."
        case .malformedFrame: return "Encrypted object error: malformed ciphertext frame."
        case .authenticationFailed: return "Encrypted object error: authentication failed; ciphertext may be damaged or belong to another key."
        case .missingFinalFrame: return "Encrypted object error: ciphertext is truncated; final authenticated frame is missing."
        case .trailingDataAfterFinalFrame: return "Encrypted object error: unexpected data exists after the final authenticated frame."
        }
    }

    public var errorDescription: String? { description }
}
