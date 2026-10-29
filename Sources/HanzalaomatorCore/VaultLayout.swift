import Foundation

public enum VaultLayout {
    public static let headerName = "vault.hanzala"
    public static let encryptedIndexName = "index.hanzala"
    public static let objectsDirectoryName = "objects"
    public static let journalDirectoryName = ".journal"

    public static func headerURL(in root: URL) -> URL {
        root.appendingPathComponent(headerName, isDirectory: false)
    }

    public static func indexURL(in root: URL) -> URL {
        root.appendingPathComponent(encryptedIndexName, isDirectory: false)
    }

    public static func objectsURL(in root: URL) -> URL {
        root.appendingPathComponent(objectsDirectoryName, isDirectory: true)
    }

    public static func objectURL(named opaqueName: String, in root: URL) -> URL {
        objectsURL(in: root).appendingPathComponent(opaqueName, isDirectory: false)
    }

    public static func journalURL(in root: URL) -> URL {
        root.appendingPathComponent(journalDirectoryName, isDirectory: true)
    }

    public static func journalRecordURL(transactionID: UUID, in root: URL) -> URL {
        journalURL(in: root)
            .appendingPathComponent("import-\(transactionID.uuidString).json", isDirectory: false)
    }
}
