import Foundation

/// Read-only authenticated metadata resolver for one retained v2 vault root.
///
/// This mirrors `V2AccessMetadataStore.read` without reopening the public vault
/// pathname. It derives exactly one metadata anchor from the already-selected
/// access master key and validates the decoded authenticated metadata model.
final class V2RetainedRootMetadataReader {
    private let locator: V2StorageNamespaceLocator
    private let objectReader: V2RetainedRootObjectReader
    private let decoder: JSONDecoder

    init(
        locator: V2StorageNamespaceLocator = V2StorageNamespaceLocator(),
        objectReader: V2RetainedRootObjectReader = V2RetainedRootObjectReader()
    ) {
        self.locator = locator
        self.objectReader = objectReader
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    func read(
        masterKey: Data,
        using retainedRoot: V2RetainedVaultRoot
    ) throws -> V2AccessMetadata {
        let anchorName = try locator.indexObjectName(masterKey: masterKey)
        let object: V2PoolObject
        do {
            object = try objectReader.readObject(
                named: anchorName,
                masterKey: masterKey,
                using: retainedRoot
            )
        } catch V2PoolObjectStoreError.objectNotFound {
            throw V2AccessMetadataStoreError.metadataNotFound
        }

        guard object.kind == .metadata else {
            throw V2AccessMetadataStoreError.unexpectedObjectKind
        }

        let metadata: V2AccessMetadata
        do {
            metadata = try decoder.decode(V2AccessMetadata.self, from: object.content)
        } catch {
            throw V2AccessMetadataStoreError.malformedMetadata
        }
        try metadata.validate()
        return metadata
    }
}
