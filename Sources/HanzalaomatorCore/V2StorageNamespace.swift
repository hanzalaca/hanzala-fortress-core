import Foundation
import CryptoKit

/// Public v2 layout deliberately reuses the generic v1 header/object names.
/// The layout itself does not contain a visible/hidden role distinction.
public enum V2StorageLayout {
    public static let accessEnvelopeName = VaultLayout.headerName
    public static let poolDirectoryName = VaultLayout.objectsDirectoryName

    public static func accessEnvelopeURL(in root: URL) -> URL {
        root.appendingPathComponent(accessEnvelopeName, isDirectory: false)
    }

    public static func poolURL(in root: URL) -> URL {
        root.appendingPathComponent(poolDirectoryName, isDirectory: true)
    }

    public static func objectURL(named opaqueName: String, in root: URL) -> URL {
        poolURL(in: root).appendingPathComponent(opaqueName, isDirectory: false)
    }
}

public enum V2StorageNamespaceError: Error, Equatable, Sendable {
    case invalidMasterKeyLength
}

/// Derives deterministic opaque anchors inside the shared v2 object pool.
///
/// A caller that successfully unlocks one access slot can locate that slot's
/// encrypted metadata without any public filename containing a role name. A
/// different master key derives a different opaque anchor. This does not claim
/// that unreferenced pool objects, file sizes, or timestamps are deniable; those
/// metadata surfaces are handled by later storage-policy work.
public struct V2StorageNamespaceLocator: Sendable {
    private static let indexAnchorLabel = Data("hanzala/v2/index-anchor".utf8)

    private let keyDeriver: DomainKeyDeriver

    public init(keyDeriver: DomainKeyDeriver = DomainKeyDeriver()) {
        self.keyDeriver = keyDeriver
    }

    public func indexObjectName(masterKey: Data) throws -> String {
        let namespaceKey: Data
        do {
            namespaceKey = try keyDeriver.derive(
                masterKey: masterKey,
                purpose: .namespaceV2
            )
        } catch {
            throw V2StorageNamespaceError.invalidMasterKeyLength
        }

        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: Self.indexAnchorLabel,
            using: SymmetricKey(data: namespaceKey)
        )
        return Data(authenticationCode).map { String(format: "%02x", $0) }.joined()
    }

    public func indexURL(masterKey: Data, in root: URL) throws -> URL {
        let name = try indexObjectName(masterKey: masterKey)
        return V2StorageLayout.objectURL(named: name, in: root)
    }
}
