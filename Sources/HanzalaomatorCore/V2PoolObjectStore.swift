import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum V2PoolObjectStoreError: Error, Equatable, Sendable {
    case invalidOpaqueName
    case poolPathIsNotDirectory
    case poolPathIsSymbolicLink
    case objectNotFound
    case objectAlreadyExists
    case objectIsNotRegularFile
    case objectTooLarge
    case objectKindMismatch
    case objectLengthMismatch
    case nameGenerationExhausted
    case stagingWriteFailed
    case stagingSyncFailed
    case commitFailed
    case objectReadFailed
    case objectDeleteFailed
}

public struct V2StoredPoolObjectReference: Equatable, Sendable {
    public let opaqueName: String
    public let logicalByteCount: UInt64
    public let sealedByteCount: UInt64

    public init(opaqueName: String, logicalByteCount: UInt64, sealedByteCount: UInt64) {
        self.opaqueName = opaqueName
        self.logicalByteCount = logicalByteCount
        self.sealedByteCount = sealedByteCount
    }
}

/// Immutable object writer/reader for the shared v2 pool.
///
/// New objects are written through the durable same-directory committer and are
/// AEAD-bound to their exact opaque filename. On Darwin, new-object publication,
/// reads, and authenticated deletion all operate relative to retained no-follow
/// root/pool descriptors instead of reopening the public `objects` pathname after
/// validation.
///
/// Authenticated deletion on Darwin keeps the same root/pool/object descriptors
/// alive through authentication, verifies that the public pool name still resolves
/// to the retained pool inode and that the opaque object name still resolves to the
/// authenticated object inode, then unlinks relative to that retained pool
/// descriptor and synchronizes the same directory capability.
///
/// POSIX does not provide a macOS equivalent of Linux `AT_EMPTY_PATH` unlink-by-fd,
/// so a hostile process with concurrent namespace mutation can still race the final
/// identity check and `unlinkat`. That narrow residual is documented rather than
/// overstated as solved.
public final class V2PoolObjectStore {
    public static let maximumNameGenerationAttempts = 16

    private let fileManager: FileManager
    private let codec: V2PoolObjectCodec
    private let durableCommitter: V2DurableFileCommitter
    private let nameGenerator: () throws -> String

    /// Internal deterministic seam used only by core tests to replace an object's
    /// pathname after the no-follow descriptor has already been opened.
    var objectOpenedHook: ((String) -> Void)?

    /// Internal deterministic seam used only by core tests after the exact object
    /// has authenticated but before the current namespace identity is rechecked.
    var authenticatedDeleteReadyHook: ((String) -> Void)?

    public init(
        fileManager: FileManager = .default,
        codec: V2PoolObjectCodec = V2PoolObjectCodec(),
        durableCommitter: V2DurableFileCommitter? = nil,
        nameGenerator: @escaping () throws -> String = { try V2OpaqueObjectName.generate() }
    ) {
        self.fileManager = fileManager
        self.codec = codec
        self.durableCommitter = durableCommitter ?? V2DurableFileCommitter(fileManager: fileManager)
        self.nameGenerator = nameGenerator
        self.objectOpenedHook = nil
        self.authenticatedDeleteReadyHook = nil
    }

    public func createObject(
        kind: V2PoolObjectKind,
        content: Data,
        masterKey: Data,
        in root: URL,
        paddedPlaintextByteCount: Int? = nil
    ) throws -> V2StoredPoolObjectReference {
        let pool = V2StorageLayout.poolURL(in: root)
        try ensurePoolDirectory(pool)
        for _ in 0..<Self.maximumNameGenerationAttempts {
            let opaqueName = try nameGenerator()
            guard V2OpaqueObjectName.isValid(opaqueName) else {
                throw V2PoolObjectStoreError.invalidOpaqueName
            }
            let destination = V2StorageLayout.objectURL(named: opaqueName, in: root)
            if fileManager.fileExists(atPath: destination.path) { continue }
            let sealed = try codec.seal(
                kind: kind,
                content: content,
                masterKey: masterKey,
                objectName: opaqueName,
                paddedPlaintextByteCount: paddedPlaintextByteCount
            )
            do {
                return try commitSealedObject(
                    sealed,
                    logicalByteCount: UInt64(content.count),
                    named: opaqueName,
                    in: root
                )
            } catch V2PoolObjectStoreError.objectAlreadyExists {
                continue
            }
        }
        throw V2PoolObjectStoreError.nameGenerationExhausted
    }

    public func createObject(
        named opaqueName: String,
        kind: V2PoolObjectKind,
        content: Data,
        masterKey: Data,
        in root: URL,
        paddedPlaintextByteCount: Int
    ) throws -> V2StoredPoolObjectReference {
        guard V2OpaqueObjectName.isValid(opaqueName) else {
            throw V2PoolObjectStoreError.invalidOpaqueName
        }
        let sealed = try codec.seal(
            kind: kind,
            content: content,
            masterKey: masterKey,
            objectName: opaqueName,
            paddedPlaintextByteCount: paddedPlaintextByteCount
        )
        try ensurePoolDirectory(V2StorageLayout.poolURL(in: root))
        return try commitSealedObject(
            sealed,
            logicalByteCount: UInt64(content.count),
            named: opaqueName,
            in: root
        )
    }

    public func readObject(
        named opaqueName: String,
        masterKey: Data,
        in root: URL
    ) throws -> V2PoolObject {
        guard V2OpaqueObjectName.isValid(opaqueName) else {
            throw V2PoolObjectStoreError.invalidOpaqueName
        }

        let sealed: Data
        #if canImport(Darwin)
        sealed = try readSealedObjectDescriptorRelative(named: opaqueName, in: root)
        #else
        let pool = V2StorageLayout.poolURL(in: root)
        guard fileManager.fileExists(atPath: pool.path) else {
            throw V2PoolObjectStoreError.objectNotFound
        }
        try validateExistingPoolDirectory(pool)
        let url = V2StorageLayout.objectURL(named: opaqueName, in: root)
        guard fileManager.fileExists(atPath: url.path) else {
            throw V2PoolObjectStoreError.objectNotFound
        }
        try validateExistingObjectFile(url)
        do { sealed = try Data(contentsOf: url, options: [.mappedIfSafe]) }
        catch { throw V2PoolObjectStoreError.objectReadFailed }
        #endif

        return try codec.open(sealed, masterKey: masterKey, objectName: opaqueName)
    }

    public func containsObject(named opaqueName: String, in root: URL) -> Bool {
        guard V2OpaqueObjectName.isValid(opaqueName) else { return false }
        let pool = V2StorageLayout.poolURL(in: root)
        guard isSafeExistingPoolDirectory(pool) else { return false }
        let url = V2StorageLayout.objectURL(named: opaqueName, in: root)
        guard fileManager.fileExists(atPath: url.path),
              (try? validateExistingObjectFile(url)) != nil else { return false }
        return true
    }

    /// Authenticates the exact object under the supplied access key before unlink.
    /// On Darwin the authentication read, namespace identity check, `unlinkat`, and
    /// directory synchronization all stay on retained no-follow descriptors.
    ///
    /// If the object name or the public `objects` directory is rebound after the
    /// authenticated descriptors were opened, deletion fails closed rather than
    /// deleting the newly substituted namespace entry.
    func deleteAuthenticatedObject(
        named opaqueName: String,
        masterKey: Data,
        expectedKind: V2PoolObjectKind,
        expectedLogicalByteCount: UInt64? = nil,
        in root: URL
    ) throws {
        #if canImport(Darwin)
        try deleteAuthenticatedObjectDescriptorRelative(
            named: opaqueName,
            masterKey: masterKey,
            expectedKind: expectedKind,
            expectedLogicalByteCount: expectedLogicalByteCount,
            in: root
        )
        #else
        let object = try readObject(named: opaqueName, masterKey: masterKey, in: root)
        guard object.kind == expectedKind else {
            throw V2PoolObjectStoreError.objectKindMismatch
        }
        if let expectedLogicalByteCount,
           UInt64(object.content.count) != expectedLogicalByteCount {
            throw V2PoolObjectStoreError.objectLengthMismatch
        }

        let pool = V2StorageLayout.poolURL(in: root)
        try validateExistingPoolDirectory(pool)
        let url = V2StorageLayout.objectURL(named: opaqueName, in: root)
        guard fileManager.fileExists(atPath: url.path) else {
            throw V2PoolObjectStoreError.objectNotFound
        }
        try validateExistingObjectFile(url)

        do {
            try durableCommitter.removeExisting(at: url)
        } catch V2DurableFileCommitError.destinationMissing {
            throw V2PoolObjectStoreError.objectNotFound
        } catch {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
        #endif
    }

    /// Recovery-only absence confirmation. The name must come from authenticated
    /// pending-removal metadata. A dangling symlink still counts as a filesystem
    /// entry and therefore fails closed instead of being mistaken for absence.
    func confirmAuthenticatedObjectAbsenceDurably(
        named opaqueName: String,
        in root: URL
    ) throws {
        guard V2OpaqueObjectName.isValid(opaqueName) else {
            throw V2PoolObjectStoreError.invalidOpaqueName
        }

        #if canImport(Darwin)
        try confirmAuthenticatedObjectAbsenceDescriptorRelative(
            named: opaqueName,
            in: root
        )
        #else
        let pool = V2StorageLayout.poolURL(in: root)
        try validateExistingPoolDirectory(pool)
        let url = V2StorageLayout.objectURL(named: opaqueName, in: root)
        guard !pathEntryExists(at: url) else {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
        do {
            try durableCommitter.confirmAbsentDurably(at: url)
        } catch {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
        #endif
    }

    private func commitSealedObject(
        _ sealed: Data,
        logicalByteCount: UInt64,
        named opaqueName: String,
        in root: URL
    ) throws -> V2StoredPoolObjectReference {
        do {
            #if canImport(Darwin)
            let rootDescriptor = root.path.withCString {
                Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
            }
            guard rootDescriptor >= 0 else {
                throw V2PoolObjectStoreError.poolPathIsNotDirectory
            }
            defer { Darwin.close(rootDescriptor) }

            let poolName = V2StorageLayout.poolDirectoryName
            let poolDescriptor = poolName.withCString {
                Darwin.openat(
                    rootDescriptor,
                    $0,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
                )
            }
            guard poolDescriptor >= 0 else {
                if entryIsSymbolicLink(directoryDescriptor: rootDescriptor, name: poolName) {
                    throw V2PoolObjectStoreError.poolPathIsSymbolicLink
                }
                throw V2PoolObjectStoreError.poolPathIsNotDirectory
            }
            defer { Darwin.close(poolDescriptor) }

            var openedPoolInformation = stat()
            guard Darwin.fstat(poolDescriptor, &openedPoolInformation) == 0,
                  (openedPoolInformation.st_mode & S_IFMT) == S_IFDIR else {
                throw V2PoolObjectStoreError.poolPathIsNotDirectory
            }

            try durableCommitter.writeNew(
                sealed,
                named: opaqueName,
                inDirectoryDescriptor: poolDescriptor,
                directoryURL: V2StorageLayout.poolURL(in: root),
                stagingPrefix: ".hanzala-v2-stage-",
                beforeNamespaceCommit: { [weak self] in
                    guard let self else { return false }
                    return (try? self.poolNameStillRefersToOpenedDirectory(
                        rootDescriptor: rootDescriptor,
                        openedPoolInformation: openedPoolInformation
                    )) == true
                }
            )
            #else
            let destination = V2StorageLayout.objectURL(named: opaqueName, in: root)
            try durableCommitter.writeNew(
                sealed,
                to: destination,
                stagingPrefix: ".hanzala-v2-stage-"
            )
            #endif
        } catch V2DurableFileCommitError.destinationAlreadyExists {
            throw V2PoolObjectStoreError.objectAlreadyExists
        } catch V2DurableFileCommitError.stagingSyncFailed {
            throw V2PoolObjectStoreError.stagingSyncFailed
        } catch V2DurableFileCommitError.stagingCreateFailed {
            throw V2PoolObjectStoreError.stagingWriteFailed
        } catch V2DurableFileCommitError.stagingWriteFailed {
            throw V2PoolObjectStoreError.stagingWriteFailed
        } catch let error as V2PoolObjectStoreError {
            throw error
        } catch {
            throw V2PoolObjectStoreError.commitFailed
        }
        return V2StoredPoolObjectReference(
            opaqueName: opaqueName,
            logicalByteCount: logicalByteCount,
            sealedByteCount: UInt64(sealed.count)
        )
    }

    #if canImport(Darwin)
    private func readSealedObjectDescriptorRelative(
        named opaqueName: String,
        in root: URL
    ) throws -> Data {
        let rootDescriptor = root.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard rootDescriptor >= 0 else {
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
        defer { Darwin.close(rootDescriptor) }

        let poolName = V2StorageLayout.poolDirectoryName
        let poolDescriptor = poolName.withCString {
            Darwin.openat(
                rootDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
            )
        }
        guard poolDescriptor >= 0 else {
            let failure = errno
            if failure == ENOENT {
                throw V2PoolObjectStoreError.objectNotFound
            }
            if entryIsSymbolicLink(directoryDescriptor: rootDescriptor, name: poolName) {
                throw V2PoolObjectStoreError.poolPathIsSymbolicLink
            }
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
        defer { Darwin.close(poolDescriptor) }

        let objectDescriptor = opaqueName.withCString {
            Darwin.openat(
                poolDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard objectDescriptor >= 0 else {
            let failure = errno
            if failure == ENOENT {
                throw V2PoolObjectStoreError.objectNotFound
            }
            if failure == ELOOP || entryIsSymbolicLink(
                directoryDescriptor: poolDescriptor,
                name: opaqueName
            ) {
                throw V2PoolObjectStoreError.objectIsNotRegularFile
            }
            throw V2PoolObjectStoreError.objectReadFailed
        }

        let handle = FileHandle(fileDescriptor: objectDescriptor, closeOnDealloc: true)
        defer { try? handle.close() }

        var information = stat()
        guard Darwin.fstat(objectDescriptor, &information) == 0 else {
            throw V2PoolObjectStoreError.objectReadFailed
        }
        let sealed = try readValidatedSealedBytes(
            from: handle,
            descriptor: objectDescriptor,
            information: information,
            opaqueName: opaqueName,
            invokeOpenHook: true
        )
        return sealed
    }

    private func deleteAuthenticatedObjectDescriptorRelative(
        named opaqueName: String,
        masterKey: Data,
        expectedKind: V2PoolObjectKind,
        expectedLogicalByteCount: UInt64?,
        in root: URL
    ) throws {
        guard V2OpaqueObjectName.isValid(opaqueName) else {
            throw V2PoolObjectStoreError.invalidOpaqueName
        }

        let rootDescriptor = root.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard rootDescriptor >= 0 else {
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
        defer { Darwin.close(rootDescriptor) }

        let poolName = V2StorageLayout.poolDirectoryName
        let poolDescriptor = poolName.withCString {
            Darwin.openat(
                rootDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
            )
        }
        guard poolDescriptor >= 0 else {
            let failure = errno
            if failure == ENOENT {
                throw V2PoolObjectStoreError.objectNotFound
            }
            if entryIsSymbolicLink(directoryDescriptor: rootDescriptor, name: poolName) {
                throw V2PoolObjectStoreError.poolPathIsSymbolicLink
            }
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
        defer { Darwin.close(poolDescriptor) }

        var openedPoolInformation = stat()
        guard Darwin.fstat(poolDescriptor, &openedPoolInformation) == 0,
              (openedPoolInformation.st_mode & S_IFMT) == S_IFDIR else {
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }

        let objectDescriptor = opaqueName.withCString {
            Darwin.openat(
                poolDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard objectDescriptor >= 0 else {
            let failure = errno
            if failure == ENOENT {
                throw V2PoolObjectStoreError.objectNotFound
            }
            if failure == ELOOP || entryIsSymbolicLink(
                directoryDescriptor: poolDescriptor,
                name: opaqueName
            ) {
                throw V2PoolObjectStoreError.objectIsNotRegularFile
            }
            throw V2PoolObjectStoreError.objectReadFailed
        }

        let handle = FileHandle(fileDescriptor: objectDescriptor, closeOnDealloc: true)
        defer { try? handle.close() }

        var openedObjectInformation = stat()
        guard Darwin.fstat(objectDescriptor, &openedObjectInformation) == 0 else {
            throw V2PoolObjectStoreError.objectReadFailed
        }
        let sealed = try readValidatedSealedBytes(
            from: handle,
            descriptor: objectDescriptor,
            information: openedObjectInformation,
            opaqueName: opaqueName,
            invokeOpenHook: false
        )
        let object = try codec.open(
            sealed,
            masterKey: masterKey,
            objectName: opaqueName
        )
        guard object.kind == expectedKind else {
            throw V2PoolObjectStoreError.objectKindMismatch
        }
        if let expectedLogicalByteCount,
           UInt64(object.content.count) != expectedLogicalByteCount {
            throw V2PoolObjectStoreError.objectLengthMismatch
        }

        authenticatedDeleteReadyHook?(opaqueName)

        guard try poolNameStillRefersToOpenedDirectory(
            rootDescriptor: rootDescriptor,
            openedPoolInformation: openedPoolInformation
        ) else {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
        guard try objectNameStillRefersToOpenedObject(
            poolDescriptor: poolDescriptor,
            opaqueName: opaqueName,
            openedObjectInformation: openedObjectInformation
        ) else {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }

        let poolURL = V2StorageLayout.poolURL(in: root)
        do {
            try durableCommitter.removeExisting(
                named: opaqueName,
                inDirectoryDescriptor: poolDescriptor,
                directoryURL: poolURL
            )
        } catch V2DurableFileCommitError.destinationMissing {
            throw V2PoolObjectStoreError.objectNotFound
        } catch {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
    }

    private func confirmAuthenticatedObjectAbsenceDescriptorRelative(
        named opaqueName: String,
        in root: URL
    ) throws {
        let rootDescriptor = root.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard rootDescriptor >= 0 else {
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
        defer { Darwin.close(rootDescriptor) }

        let poolName = V2StorageLayout.poolDirectoryName
        let poolDescriptor = poolName.withCString {
            Darwin.openat(
                rootDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
            )
        }
        guard poolDescriptor >= 0 else {
            if errno == ENOENT {
                throw V2PoolObjectStoreError.objectDeleteFailed
            }
            if entryIsSymbolicLink(directoryDescriptor: rootDescriptor, name: poolName) {
                throw V2PoolObjectStoreError.poolPathIsSymbolicLink
            }
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
        defer { Darwin.close(poolDescriptor) }

        var openedPoolInformation = stat()
        guard Darwin.fstat(poolDescriptor, &openedPoolInformation) == 0,
              (openedPoolInformation.st_mode & S_IFMT) == S_IFDIR,
              try poolNameStillRefersToOpenedDirectory(
                rootDescriptor: rootDescriptor,
                openedPoolInformation: openedPoolInformation
              ) else {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }

        var current = stat()
        let result = opaqueName.withCString {
            Darwin.fstatat(
                poolDescriptor,
                $0,
                &current,
                AT_SYMLINK_NOFOLLOW
            )
        }
        if result == 0 {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
        guard errno == ENOENT else {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }

        do {
            try durableCommitter.confirmAbsentDurably(
                named: opaqueName,
                inDirectoryDescriptor: poolDescriptor,
                directoryURL: V2StorageLayout.poolURL(in: root)
            )
        } catch {
            throw V2PoolObjectStoreError.objectDeleteFailed
        }
    }

    private func readValidatedSealedBytes(
        from handle: FileHandle,
        descriptor: Int32,
        information: stat,
        opaqueName: String,
        invokeOpenHook: Bool
    ) throws -> Data {
        guard (information.st_mode & S_IFMT) == S_IFREG else {
            throw V2PoolObjectStoreError.objectIsNotRegularFile
        }
        guard information.st_size >= 0 else {
            throw V2PoolObjectStoreError.objectTooLarge
        }
        let expectedByteCount = UInt64(information.st_size)
        guard expectedByteCount <= UInt64(V2PoolObjectCodec.maximumEnvelopeByteCount),
              expectedByteCount <= UInt64(Int.max) else {
            throw V2PoolObjectStoreError.objectTooLarge
        }

        if invokeOpenHook {
            objectOpenedHook?(opaqueName)
        }

        var sealed = Data()
        sealed.reserveCapacity(Int(expectedByteCount))
        while sealed.count < Int(expectedByteCount) {
            let remaining = Int(expectedByteCount) - sealed.count
            let request = min(1024 * 1024, remaining)
            let bytes: Data
            do {
                bytes = try handle.read(upToCount: request) ?? Data()
            } catch {
                throw V2PoolObjectStoreError.objectReadFailed
            }
            guard !bytes.isEmpty else {
                throw V2PoolObjectStoreError.objectReadFailed
            }
            sealed.append(bytes)
        }

        let extra: Data
        do {
            extra = try handle.read(upToCount: 1) ?? Data()
        } catch {
            throw V2PoolObjectStoreError.objectReadFailed
        }
        guard extra.isEmpty else {
            throw V2PoolObjectStoreError.objectTooLarge
        }

        var afterRead = stat()
        guard Darwin.fstat(descriptor, &afterRead) == 0,
              afterRead.st_dev == information.st_dev,
              afterRead.st_ino == information.st_ino,
              afterRead.st_size == information.st_size else {
            throw V2PoolObjectStoreError.objectReadFailed
        }
        return sealed
    }

    private func poolNameStillRefersToOpenedDirectory(
        rootDescriptor: Int32,
        openedPoolInformation: stat
    ) throws -> Bool {
        var current = stat()
        let poolName = V2StorageLayout.poolDirectoryName
        let result = poolName.withCString {
            Darwin.fstatat(
                rootDescriptor,
                $0,
                &current,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard result == 0 else {
            return false
        }
        guard (current.st_mode & S_IFMT) == S_IFDIR else {
            return false
        }
        return current.st_dev == openedPoolInformation.st_dev
            && current.st_ino == openedPoolInformation.st_ino
    }

    private func objectNameStillRefersToOpenedObject(
        poolDescriptor: Int32,
        opaqueName: String,
        openedObjectInformation: stat
    ) throws -> Bool {
        var current = stat()
        let result = opaqueName.withCString {
            Darwin.fstatat(
                poolDescriptor,
                $0,
                &current,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard result == 0 else {
            if errno == ENOENT {
                throw V2PoolObjectStoreError.objectNotFound
            }
            return false
        }
        guard (current.st_mode & S_IFMT) == S_IFREG else {
            return false
        }
        return current.st_dev == openedObjectInformation.st_dev
            && current.st_ino == openedObjectInformation.st_ino
    }

    private func entryIsSymbolicLink(
        directoryDescriptor: Int32,
        name: String
    ) -> Bool {
        var information = stat()
        let result = name.withCString {
            Darwin.fstatat(
                directoryDescriptor,
                $0,
                &information,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard result == 0 else { return false }
        return (information.st_mode & S_IFMT) == S_IFLNK
    }
    #endif

    private func pathEntryExists(at url: URL) -> Bool {
        #if canImport(Darwin)
        var info = stat()
        return url.path.withCString { lstat($0, &info) } == 0
        #else
        return fileManager.fileExists(atPath: url.path)
        #endif
    }

    private func validateExistingObjectFile(_ url: URL) throws {
        let values: URLResourceValues
        do {
            values = try url.resourceValues(forKeys: [
                .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey
            ])
        } catch { throw V2PoolObjectStoreError.objectReadFailed }
        guard values.isSymbolicLink != true, values.isRegularFile == true else {
            throw V2PoolObjectStoreError.objectIsNotRegularFile
        }
        guard let fileSize = values.fileSize,
              fileSize >= 0,
              fileSize <= V2PoolObjectCodec.maximumEnvelopeByteCount else {
            throw V2PoolObjectStoreError.objectTooLarge
        }
    }

    private func ensurePoolDirectory(_ pool: URL) throws {
        if fileManager.fileExists(atPath: pool.path) {
            try validateExistingPoolDirectory(pool)
            return
        }
        do { try fileManager.createDirectory(at: pool, withIntermediateDirectories: true) }
        catch { throw V2PoolObjectStoreError.commitFailed }
        try validateExistingPoolDirectory(pool)
    }

    private func validateExistingPoolDirectory(_ pool: URL) throws {
        let values: URLResourceValues
        do { values = try pool.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]) }
        catch { throw V2PoolObjectStoreError.poolPathIsNotDirectory }
        guard values.isSymbolicLink != true else {
            throw V2PoolObjectStoreError.poolPathIsSymbolicLink
        }
        guard values.isDirectory == true else {
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }
    }

    private func isSafeExistingPoolDirectory(_ pool: URL) -> Bool {
        guard fileManager.fileExists(atPath: pool.path),
              let values = try? pool.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
              values.isSymbolicLink != true,
              values.isDirectory == true else { return false }
        return true
    }
}
