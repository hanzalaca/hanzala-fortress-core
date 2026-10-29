import Foundation

public enum RecoveryKeyError: Error, Equatable {
    case invalidFormat
    case unavailable
}

public final class RecoveryKeyEngine {
    private let keyEngine: PasswordKeyEngine

    public init(keyEngine: PasswordKeyEngine = PasswordKeyEngine()) {
        self.keyEngine = keyEngine
    }

    /// Generates a 256-bit recovery secret in a human-copyable HZRK format.
    /// The recovery secret itself is never intended to be stored in the vault.
    public func generateRecoveryKey() -> String {
        generateRecoveryKeyMaterial().displayKey
    }

    /// Accepts the displayed recovery key with or without separators/whitespace
    /// and returns one canonical representation for key derivation.
    public func normalize(_ input: String) throws -> String {
        let upper = input.uppercased()
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "-"))
        let compact = upper.components(separatedBy: separators).joined()

        guard compact.hasPrefix("HZRK") else {
            throw RecoveryKeyError.invalidFormat
        }

        let body = String(compact.dropFirst(4))
        guard body.count == 64,
              body.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789ABCDEF").inverted) == nil else {
            throw RecoveryKeyError.invalidFormat
        }

        return format(hexBody: body)
    }

    /// Internal v2 storage primitive. Recovery anchors operate on the original
    /// 256-bit random secret, not the human-readable HZRK punctuation/string.
    /// Keeping this internal avoids making raw recovery-key bytes part of the
    /// public application API while still allowing domain-separated v2 use.
    func keyMaterial(from input: String) throws -> Data {
        let normalized = try normalize(input)
        let compact = normalized.replacingOccurrences(of: "-", with: "")
        let body = String(compact.dropFirst(4))

        var bytes = Data()
        bytes.reserveCapacity(32)
        var index = body.startIndex
        while index < body.endIndex {
            let end = body.index(index, offsetBy: 2)
            guard let byte = UInt8(body[index..<end], radix: 16) else {
                throw RecoveryKeyError.invalidFormat
            }
            bytes.append(byte)
            index = end
        }
        guard bytes.count == 32 else {
            throw RecoveryKeyError.invalidFormat
        }
        return bytes
    }

    /// Generates one display key and its exact 32-byte secret in a single random
    /// operation so callers never regenerate or transform entropy implicitly.
    func generateRecoveryKeyMaterial() -> (displayKey: String, keyMaterial: Data) {
        let randomBytes = keyEngine.generateMasterKey()
        let hex = randomBytes.map { String(format: "%02X", $0) }.joined()
        return (format(hexBody: hex), randomBytes)
    }

    private func format(hexBody: String) -> String {
        var chunks: [String] = []
        var index = hexBody.startIndex

        while index < hexBody.endIndex {
            let end = hexBody.index(index, offsetBy: 4)
            chunks.append(String(hexBody[index..<end]))
            index = end
        }

        return "HZRK-" + chunks.joined(separator: "-")
    }
}
