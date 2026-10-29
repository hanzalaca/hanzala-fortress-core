import Foundation
import Sodium

public enum V2PoolObjectKind: UInt8, Equatable, Sendable {
    case metadata = 1
    case data = 2
    case padding = 3
    case manifest = 4
    case recovery = 5
}

public struct V2PoolObject: Equatable, Sendable {
    public let kind: V2PoolObjectKind
    public let content: Data

    public init(kind: V2PoolObjectKind, content: Data) {
        self.kind = kind
        self.content = content
    }
}

public enum V2PoolObjectCodecError: Error, Equatable, Sendable {
    case invalidMasterKeyLength
    case invalidObjectNameBinding
    case invalidPaddingTarget
    case payloadTooLarge
    case randomGenerationFailed
    case encryptionFailed
    case malformedEnvelope
    case authenticationFailed
    case unsupportedPayloadVersion
    case invalidPayloadKind
    case invalidLogicalLength
}

/// Common authenticated envelope for every v2 object-pool role.
///
/// Public bytes contain only one generic v2 object magic followed by an
/// XChaCha20-Poly1305 nonce+ciphertext. Object role and logical length are inside
/// the authenticated ciphertext so an observer cannot distinguish metadata,
/// ordinary data, chunk manifests, recovery anchors, or padding from a cleartext
/// type field.
///
/// The public opaque filename is mandatory AEAD associated data. Moving a valid
/// ciphertext to a different opaque name therefore fails authentication even
/// when both names belong to the same access master key. This prevents same-key
/// ciphertext swapping from silently rebinding one logical object to another.
public final class V2PoolObjectCodec {
    public static let maximumPlaintextByteCount = 16 * 1024 * 1024
    public static let encryptedPayloadHeaderByteCount = 10 // version + kind + UInt64 length

    /// XChaCha20-Poly1305-IETF uses a 24-byte nonce and a 16-byte authentication
    /// tag. The v2 public envelope adds the fixed 8-byte generic magic. Exposing
    /// this bound lets storage reject oversized filesystem objects before loading
    /// them into memory.
    public static let maximumEnvelopeByteCount = 8 + 24 + 16 + maximumPlaintextByteCount

    /// HZOBJ003 is the first v2 pool-object revision whose AEAD authentication is
    /// cryptographically bound to the object's opaque filename. Earlier HZOBJ002
    /// foundation objects are intentionally not accepted as this revision.
    private static let magic = Data("HZOBJ003".utf8)
    private static let payloadVersion: UInt8 = 1
    private static let bindingSeparator: UInt8 = 0

    private let sodium = Sodium()
    private let keyDeriver: DomainKeyDeriver

    public init(keyDeriver: DomainKeyDeriver = DomainKeyDeriver()) {
        self.keyDeriver = keyDeriver
    }

    /// Seals one pool object and binds the ciphertext to `objectName` through
    /// AEAD associated data. When `paddedPlaintextByteCount` is supplied, random
    /// padding is added *inside* the authenticated ciphertext until the encrypted
    /// payload reaches that plaintext size. The target includes the encrypted
    /// payload header and content.
    public func seal(
        kind: V2PoolObjectKind,
        content: Data,
        masterKey: Data,
        objectName: String,
        paddedPlaintextByteCount: Int? = nil
    ) throws -> Data {
        let objectKey = try deriveObjectKey(masterKey: masterKey)
        let associatedData = try Self.associatedData(for: objectName)

        let (minimumPlaintextByteCount, overflow) = Self.encryptedPayloadHeaderByteCount.addingReportingOverflow(content.count)
        guard !overflow,
              minimumPlaintextByteCount <= Self.maximumPlaintextByteCount else {
            throw V2PoolObjectCodecError.payloadTooLarge
        }

        let targetPlaintextByteCount = paddedPlaintextByteCount ?? minimumPlaintextByteCount
        guard targetPlaintextByteCount >= minimumPlaintextByteCount else {
            throw V2PoolObjectCodecError.invalidPaddingTarget
        }
        guard targetPlaintextByteCount <= Self.maximumPlaintextByteCount else {
            throw V2PoolObjectCodecError.payloadTooLarge
        }

        var payload = Data()
        payload.reserveCapacity(targetPlaintextByteCount)
        payload.append(Self.payloadVersion)
        payload.append(kind.rawValue)
        payload.append(Self.encodeUInt64(UInt64(content.count)))
        payload.append(content)

        let paddingByteCount = targetPlaintextByteCount - payload.count
        if paddingByteCount > 0 {
            guard let padding = sodium.randomBytes.buf(length: paddingByteCount) else {
                throw V2PoolObjectCodecError.randomGenerationFailed
            }
            payload.append(contentsOf: padding)
        }

        guard let protected: [UInt8] = sodium.aead.xchacha20poly1305ietf.encrypt(
            message: [UInt8](payload),
            secretKey: [UInt8](objectKey),
            additionalData: [UInt8](associatedData)
        ) else {
            throw V2PoolObjectCodecError.encryptionFailed
        }

        var envelope = Self.magic
        envelope.append(contentsOf: protected)
        return envelope
    }

    public func open(
        _ envelope: Data,
        masterKey: Data,
        objectName: String
    ) throws -> V2PoolObject {
        let aead = sodium.aead.xchacha20poly1305ietf
        let minimumEnvelopeByteCount = Self.magic.count + aead.NonceBytes + aead.ABytes + Self.encryptedPayloadHeaderByteCount
        let maximumEnvelopeByteCount = Self.magic.count + aead.NonceBytes + aead.ABytes + Self.maximumPlaintextByteCount
        guard envelope.count >= minimumEnvelopeByteCount,
              envelope.count <= maximumEnvelopeByteCount,
              envelope.prefix(Self.magic.count) == Self.magic else {
            if envelope.count > maximumEnvelopeByteCount {
                throw V2PoolObjectCodecError.payloadTooLarge
            }
            throw V2PoolObjectCodecError.malformedEnvelope
        }

        let objectKey = try deriveObjectKey(masterKey: masterKey)
        let associatedData = try Self.associatedData(for: objectName)
        let protected = envelope.dropFirst(Self.magic.count)
        guard let plaintextBytes = aead.decrypt(
            nonceAndAuthenticatedCipherText: [UInt8](protected),
            secretKey: [UInt8](objectKey),
            additionalData: [UInt8](associatedData)
        ) else {
            throw V2PoolObjectCodecError.authenticationFailed
        }

        let plaintext = Data(plaintextBytes)
        guard plaintext.count >= Self.encryptedPayloadHeaderByteCount else {
            throw V2PoolObjectCodecError.malformedEnvelope
        }

        guard plaintext[plaintext.startIndex] == Self.payloadVersion else {
            throw V2PoolObjectCodecError.unsupportedPayloadVersion
        }

        let kindIndex = plaintext.index(after: plaintext.startIndex)
        guard let kind = V2PoolObjectKind(rawValue: plaintext[kindIndex]) else {
            throw V2PoolObjectCodecError.invalidPayloadKind
        }

        let lengthStart = plaintext.index(kindIndex, offsetBy: 1)
        let lengthEnd = plaintext.index(lengthStart, offsetBy: 8)
        guard let logicalLength = Self.decodeUInt64(Data(plaintext[lengthStart..<lengthEnd])) else {
            throw V2PoolObjectCodecError.invalidLogicalLength
        }

        let contentStart = lengthEnd
        let availableContentBytes = plaintext.distance(from: contentStart, to: plaintext.endIndex)
        guard logicalLength <= UInt64(availableContentBytes),
              logicalLength <= UInt64(Int.max) else {
            throw V2PoolObjectCodecError.invalidLogicalLength
        }

        let contentEnd = plaintext.index(contentStart, offsetBy: Int(logicalLength))
        return V2PoolObject(
            kind: kind,
            content: Data(plaintext[contentStart..<contentEnd])
        )
    }

    private static func associatedData(for objectName: String) throws -> Data {
        guard V2OpaqueObjectName.isValid(objectName) else {
            throw V2PoolObjectCodecError.invalidObjectNameBinding
        }
        var data = Self.magic
        data.append(Self.bindingSeparator)
        data.append(contentsOf: objectName.utf8)
        return data
    }

    private func deriveObjectKey(masterKey: Data) throws -> Data {
        do {
            return try keyDeriver.derive(masterKey: masterKey, purpose: .poolObjectV2)
        } catch {
            throw V2PoolObjectCodecError.invalidMasterKeyLength
        }
    }

    private static func encodeUInt64(_ value: UInt64) -> Data {
        var bigEndian = value.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }

    private static func decodeUInt64(_ data: Data) -> UInt64? {
        guard data.count == 8 else { return nil }
        return data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return nil }
            return baseAddress.loadUnaligned(as: UInt64.self).bigEndian
        }
    }
}
