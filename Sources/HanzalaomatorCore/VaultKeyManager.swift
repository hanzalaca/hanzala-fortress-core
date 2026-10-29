import Foundation

public final class VaultKeyManager {
    private let keyEngine: PasswordKeyEngine
    private let recoveryKeyEngine: RecoveryKeyEngine

    public init(
        keyEngine: PasswordKeyEngine = PasswordKeyEngine(),
        recoveryKeyEngine: RecoveryKeyEngine? = nil
    ) {
        self.keyEngine = keyEngine
        self.recoveryKeyEngine = recoveryKeyEngine ?? RecoveryKeyEngine(keyEngine: keyEngine)
    }

    public func createHeader(password: String, vaultID: UUID = UUID(), createdAt: Date = Date()) throws -> (header: VaultHeader, masterKey: Data) {
        let parameters = try keyEngine.makeDefaultParameters()
        let masterKey = keyEngine.generateMasterKey()
        let wrapped = try keyEngine.wrapMasterKey(masterKey, password: password, parameters: parameters)
        let header = VaultHeader(
            formatVersion: 1,
            vaultID: vaultID,
            createdAt: createdAt,
            kdf: parameters,
            wrappedMasterKey: wrapped
        )
        return (header, masterKey)
    }

    public func createHeaderWithRecovery(
        password: String,
        vaultID: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> (header: VaultHeader, masterKey: Data, recoveryKey: String) {
        let passwordParameters = try keyEngine.makeDefaultParameters()
        let recoveryParameters = try keyEngine.makeDefaultParameters()
        let masterKey = keyEngine.generateMasterKey()
        let recoveryKey = recoveryKeyEngine.generateRecoveryKey()

        let passwordWrapped = try keyEngine.wrapMasterKey(
            masterKey,
            password: password,
            parameters: passwordParameters
        )
        let recoveryWrapped = try keyEngine.wrapMasterKey(
            masterKey,
            password: recoveryKey,
            parameters: recoveryParameters
        )

        let header = VaultHeader(
            formatVersion: 1,
            vaultID: vaultID,
            createdAt: createdAt,
            kdf: passwordParameters,
            wrappedMasterKey: passwordWrapped,
            recovery: RecoveryKeyEnvelope(
                formatVersion: 1,
                kdf: recoveryParameters,
                wrappedMasterKey: recoveryWrapped
            )
        )

        return (header, masterKey, recoveryKey)
    }

    public func unlock(header: VaultHeader, password: String) throws -> Data {
        guard header.formatVersion == 1 else {
            throw VaultKeyError.invalidKDFParameters
        }
        return try keyEngine.unwrapMasterKey(
            header.wrappedMasterKey,
            password: password,
            parameters: header.kdf
        )
    }

    public func unlockWithRecovery(header: VaultHeader, recoveryKey: String) throws -> Data {
        guard header.formatVersion == 1 else {
            throw VaultKeyError.invalidKDFParameters
        }
        guard let recovery = header.recovery else {
            throw RecoveryKeyError.unavailable
        }
        guard recovery.formatVersion == 1 else {
            throw RecoveryKeyError.unavailable
        }

        let normalized = try recoveryKeyEngine.normalize(recoveryKey)
        return try keyEngine.unwrapMasterKey(
            recovery.wrappedMasterKey,
            password: normalized,
            parameters: recovery.kdf
        )
    }

    public func rewrapPassword(
        header: VaultHeader,
        masterKey: Data,
        newPassword: String
    ) throws -> VaultHeader {
        let newParameters = try keyEngine.makeDefaultParameters()
        let newWrapped = try keyEngine.wrapMasterKey(
            masterKey,
            password: newPassword,
            parameters: newParameters
        )

        return VaultHeader(
            formatVersion: header.formatVersion,
            vaultID: header.vaultID,
            createdAt: header.createdAt,
            kdf: newParameters,
            wrappedMasterKey: newWrapped,
            recovery: header.recovery
        )
    }

    public func rotateRecoveryKey(
        header: VaultHeader,
        masterKey: Data
    ) throws -> (header: VaultHeader, recoveryKey: String) {
        let recoveryKey = recoveryKeyEngine.generateRecoveryKey()
        let recoveryParameters = try keyEngine.makeDefaultParameters()
        let recoveryWrapped = try keyEngine.wrapMasterKey(
            masterKey,
            password: recoveryKey,
            parameters: recoveryParameters
        )

        let updatedHeader = VaultHeader(
            formatVersion: header.formatVersion,
            vaultID: header.vaultID,
            createdAt: header.createdAt,
            kdf: header.kdf,
            wrappedMasterKey: header.wrappedMasterKey,
            recovery: RecoveryKeyEnvelope(
                formatVersion: 1,
                kdf: recoveryParameters,
                wrappedMasterKey: recoveryWrapped
            )
        )

        return (updatedHeader, recoveryKey)
    }
}
