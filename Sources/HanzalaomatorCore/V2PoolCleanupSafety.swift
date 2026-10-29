import Foundation
import Sodium

public enum V2OpaqueObjectNameError: Error, Equatable, Sendable {
    case randomGenerationFailed
    case invalidName
}

/// Opaque v2 pool object names are 32 random bytes encoded as lowercase hex.
/// The format carries no object role, timestamp, sequence number, or original
/// filename information.
public enum V2OpaqueObjectName {
    public static let byteCount = 32
    public static let encodedLength = byteCount * 2

    public static func generate() throws -> String {
        let sodium = Sodium()
        guard let bytes = sodium.randomBytes.buf(length: byteCount) else {
            throw V2OpaqueObjectNameError.randomGenerationFailed
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func isValid(_ name: String) -> Bool {
        guard name.utf8.count == encodedLength else { return false }
        return name.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
    }

    public static func validatedURL(named name: String, in root: URL) throws -> URL {
        guard isValid(name) else {
            throw V2OpaqueObjectNameError.invalidName
        }
        return V2StorageLayout.objectURL(named: name, in: root)
    }
}

public enum V2PoolCleanupDecision: Equatable, Sendable {
    /// The current authenticated access metadata does not claim this object.
    /// It may belong to another access path and must be preserved.
    case preserveUnknown

    /// The object is authenticated as owned by the current access path and is
    /// still live according to that access path's encrypted metadata.
    case preserveLiveOwned

    /// Deletion is permitted only when the current access path both owns and has
    /// explicitly tombstoned the object in authenticated encrypted metadata.
    case deleteOwnedTombstone
}

/// Fail-closed cleanup policy for a shared v2 object pool.
///
/// The ordinary/decoy access path must never treat "not in my index" as garbage,
/// because those objects may belong to a concealed access path. Unknown objects
/// are therefore preserved unconditionally.
public struct V2PoolCleanupPolicy: Sendable {
    public init() {}

    public func decision(
        for candidateName: String,
        authenticatedOwnedObjectNames: Set<String>,
        authenticatedTombstonedObjectNames: Set<String>
    ) -> V2PoolCleanupDecision {
        guard authenticatedOwnedObjectNames.contains(candidateName) else {
            return .preserveUnknown
        }
        guard authenticatedTombstonedObjectNames.contains(candidateName) else {
            return .preserveLiveOwned
        }
        return .deleteOwnedTombstone
    }

    /// Returns only candidates that are safe for the currently unlocked access
    /// path to delete. Invalid opaque names and unknown objects are preserved.
    public func deletableObjectNames(
        from candidates: [String],
        authenticatedOwnedObjectNames: Set<String>,
        authenticatedTombstonedObjectNames: Set<String>
    ) -> [String] {
        candidates.filter { name in
            guard V2OpaqueObjectName.isValid(name) else { return false }
            return decision(
                for: name,
                authenticatedOwnedObjectNames: authenticatedOwnedObjectNames,
                authenticatedTombstonedObjectNames: authenticatedTombstonedObjectNames
            ) == .deleteOwnedTombstone
        }
    }
}
