import Foundation
import Sodium

public struct VaultIndex: Codable, Sendable {
    public let formatVersion: UInt32
    public var entries: [VaultEntry]

    public init(formatVersion: UInt32 = 1, entries: [VaultEntry] = []) {
        self.formatVersion = formatVersion
        self.entries = entries
    }
}

public enum EncryptedIndexError: Error, Equatable {
    case invalidKeyLength
    case encryptionFailed
    case authenticationFailed
    case malformedIndex
    case unsupportedVersion
}

public final class EncryptedIndexStore {
    private let sodium = Sodium()
    private let keyDeriver: DomainKeyDeriver
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(keyDeriver: DomainKeyDeriver = DomainKeyDeriver()) {
        self.keyDeriver = keyDeriver
        encoder = JSONEncoder()
        decoder = JSONDecoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func write(_ index: VaultIndex, to url: URL, masterKey: Data) throws {
        let indexKey: Data
        do {
            indexKey = try keyDeriver.derive(masterKey: masterKey, purpose: .indexV1)
        } catch {
            throw EncryptedIndexError.invalidKeyLength
        }

        let plaintext = try encoder.encode(index)
        let nonce = sodium.secretBox.nonce()
        guard let ciphertext = sodium.secretBox.seal(
            message: [UInt8](plaintext),
            secretKey: [UInt8](indexKey),
            nonce: nonce
        ) else {
            throw EncryptedIndexError.encryptionFailed
        }

        var envelope = Data("HZIDX01".utf8)
        envelope.append(contentsOf: nonce)
        envelope.append(contentsOf: ciphertext)
        try SecureFileWriter.atomicallyWrite(envelope, to: url)
    }

    public func read(from url: URL, masterKey: Data) throws -> VaultIndex {
        let indexKey: Data
        do {
            indexKey = try keyDeriver.derive(masterKey: masterKey, purpose: .indexV1)
        } catch {
            throw EncryptedIndexError.invalidKeyLength
        }

        let envelope = try Data(contentsOf: url)
        let magic = Data("HZIDX01".utf8)
        let minimumLength = magic.count + sodium.secretBox.NonceBytes + sodium.secretBox.MacBytes
        guard envelope.count >= minimumLength, envelope.prefix(magic.count) == magic else {
            throw EncryptedIndexError.malformedIndex
        }

        let protected = envelope.dropFirst(magic.count)
        guard let plaintext = sodium.secretBox.open(
            nonceAndAuthenticatedCipherText: [UInt8](protected),
            secretKey: [UInt8](indexKey)
        ) else {
            throw EncryptedIndexError.authenticationFailed
        }

        let index: VaultIndex
        do {
            index = try decoder.decode(VaultIndex.self, from: Data(plaintext))
        } catch {
            throw EncryptedIndexError.malformedIndex
        }
        guard index.formatVersion == 1 else {
            throw EncryptedIndexError.unsupportedVersion
        }
        return index
    }
}
