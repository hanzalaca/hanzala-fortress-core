import Foundation

public enum SecureFileWriterError: Error {
    case destinationExists
}

/// Crash-conscious file replacement helper.
///
/// The caller writes the complete new encrypted representation to a temporary
/// file in the same directory. Only after the write succeeds is the temporary
/// file moved into its final location. This avoids exposing a partially-written
/// ciphertext file as a valid vault object.
public enum SecureFileWriter {
    public static func atomicallyWrite(_ data: Data, to destination: URL) throws {
        let fm = FileManager.default
        let directory = destination.deletingLastPathComponent()
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)

        let temporary = directory.appendingPathComponent(".hanzala-\(UUID().uuidString).tmp")
        defer { try? fm.removeItem(at: temporary) }

        try data.write(to: temporary, options: [.atomic])

        if fm.fileExists(atPath: destination.path) {
            _ = try fm.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try fm.moveItem(at: temporary, to: destination)
        }
    }
}
