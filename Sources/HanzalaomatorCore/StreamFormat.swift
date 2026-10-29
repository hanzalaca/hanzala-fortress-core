import Foundation

/// Versioned envelope used for encrypted file objects.
///
/// File layout (all integers big-endian):
/// magic[8] | version[4] | secretstreamHeaderLength[4] | secretstreamHeader | frames...
/// frame := ciphertextLength[4] | ciphertext
///
/// The libsodium secretstream header is public and safe to store beside ciphertext.
/// A FINAL authenticated frame is mandatory; truncation is therefore rejected.
public enum StreamFormat {
    public static let magic = Data([0x48, 0x5A, 0x53, 0x54, 0x52, 0x4D, 0x30, 0x31]) // HZSTRM01
    public static let version: UInt32 = 1
    public static let defaultPlaintextChunkSize = 1024 * 1024

    public static func encodeUInt32(_ value: UInt32) -> Data {
        var big = value.bigEndian
        return withUnsafeBytes(of: &big) { Data($0) }
    }

    public static func decodeUInt32(_ data: Data) -> UInt32? {
        guard data.count == 4 else { return nil }
        return data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return nil }
            return base.loadUnaligned(as: UInt32.self).bigEndian
        }
    }
}

public enum StreamCryptoError: Error, Equatable {
    case invalidKeyLength
    case malformedHeader
    case unsupportedVersion
    case malformedFrame
    case authenticationFailed
    case missingFinalFrame
    case trailingDataAfterFinalFrame
}
