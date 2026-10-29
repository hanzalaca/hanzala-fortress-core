import Foundation

public struct RecoveryKeyEnvelope: Codable, Sendable {
    public let formatVersion: UInt32
    public let kdf: KDFParameters
    public let wrappedMasterKey: Data

    public init(formatVersion: UInt32 = 1, kdf: KDFParameters, wrappedMasterKey: Data) {
        self.formatVersion = formatVersion
        self.kdf = kdf
        self.wrappedMasterKey = wrappedMasterKey
    }
}

public struct VaultHeader: Codable, Sendable {
    public let formatVersion: UInt32
    public let vaultID: UUID
    public let createdAt: Date
    public let kdf: KDFParameters
    public let wrappedMasterKey: Data
    public let recovery: RecoveryKeyEnvelope?

    public init(
        formatVersion: UInt32 = 1,
        vaultID: UUID,
        createdAt: Date,
        kdf: KDFParameters,
        wrappedMasterKey: Data,
        recovery: RecoveryKeyEnvelope? = nil
    ) {
        self.formatVersion = formatVersion
        self.vaultID = vaultID
        self.createdAt = createdAt
        self.kdf = kdf
        self.wrappedMasterKey = wrappedMasterKey
        self.recovery = recovery
    }
}

public struct KDFParameters: Codable, Sendable {
    public let algorithm: String
    public let salt: Data
    public let operationsLimit: UInt64
    public let memoryLimit: UInt64

    public init(algorithm: String = "argon2id", salt: Data, operationsLimit: UInt64, memoryLimit: UInt64) {
        self.algorithm = algorithm
        self.salt = salt
        self.operationsLimit = operationsLimit
        self.memoryLimit = memoryLimit
    }
}

public struct VaultEntry: Codable, Identifiable, Sendable {
    public let id: UUID
    public let opaqueObjectName: String
    public let originalName: String
    public let byteCount: UInt64
    public let createdAt: Date

    public init(id: UUID = UUID(), opaqueObjectName: String, originalName: String, byteCount: UInt64, createdAt: Date = Date()) {
        self.id = id
        self.opaqueObjectName = opaqueObjectName
        self.originalName = originalName
        self.byteCount = byteCount
        self.createdAt = createdAt
    }
}
