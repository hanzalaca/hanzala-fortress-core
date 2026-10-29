import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Read-only HZOBJ003 resolver that stays relative to a caller-owned retained
/// vault-root capability for the full unlock transaction.
///
/// This intentionally does not expose enumeration or mutation. Callers must
/// already know the exact role-neutral opaque object name derived from an
/// authenticated password/recovery path.
final class V2RetainedRootObjectReader {
    private let codec: V2PoolObjectCodec
    private let fileManager: FileManager

    init(
        codec: V2PoolObjectCodec = V2PoolObjectCodec(),
        fileManager: FileManager = .default
    ) {
        self.codec = codec
        self.fileManager = fileManager
    }

    func readObject(
        named opaqueName: String,
        masterKey: Data,
        using retainedRoot: V2RetainedVaultRoot
    ) throws -> V2PoolObject {
        guard V2OpaqueObjectName.isValid(opaqueName) else {
            throw V2PoolObjectStoreError.invalidOpaqueName
        }

        #if canImport(Darwin)
        let sealed = try readSealedObject(
            named: opaqueName,
            rootDescriptor: retainedRoot.descriptor
        )
        #else
        let fallbackStore = V2PoolObjectStore(
            fileManager: fileManager,
            codec: codec
        )
        return try fallbackStore.readObject(
            named: opaqueName,
            masterKey: masterKey,
            in: retainedRoot.url
        )
        #endif

        #if canImport(Darwin)
        return try codec.open(
            sealed,
            masterKey: masterKey,
            objectName: opaqueName
        )
        #endif
    }

    #if canImport(Darwin)
    private func readSealedObject(
        named opaqueName: String,
        rootDescriptor: Int32
    ) throws -> Data {
        var rootInformation = stat()
        guard Darwin.fstat(rootDescriptor, &rootInformation) == 0,
              (rootInformation.st_mode & S_IFMT) == S_IFDIR else {
            throw V2PoolObjectStoreError.poolPathIsNotDirectory
        }

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
            if entryIsSymbolicLink(
                directoryDescriptor: rootDescriptor,
                name: poolName
            ) {
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
        defer { Darwin.close(objectDescriptor) }

        var before = stat()
        guard Darwin.fstat(objectDescriptor, &before) == 0 else {
            throw V2PoolObjectStoreError.objectReadFailed
        }
        guard (before.st_mode & S_IFMT) == S_IFREG else {
            throw V2PoolObjectStoreError.objectIsNotRegularFile
        }
        guard before.st_size >= 0 else {
            throw V2PoolObjectStoreError.objectTooLarge
        }

        let expectedByteCount = UInt64(before.st_size)
        guard expectedByteCount <= UInt64(V2PoolObjectCodec.maximumEnvelopeByteCount),
              expectedByteCount <= UInt64(Int.max) else {
            throw V2PoolObjectStoreError.objectTooLarge
        }

        let expected = Int(expectedByteCount)
        var data = Data(count: expected)
        var total = 0
        let completed = data.withUnsafeMutableBytes { rawBuffer -> Bool in
            if expected == 0 { return true }
            guard let base = rawBuffer.baseAddress else { return false }
            while total < expected {
                let result = Darwin.read(
                    objectDescriptor,
                    base.advanced(by: total),
                    expected - total
                )
                if result > 0 {
                    total += result
                    continue
                }
                if result < 0, errno == EINTR {
                    continue
                }
                return false
            }
            return true
        }
        guard completed, total == expected else {
            throw V2PoolObjectStoreError.objectReadFailed
        }

        var trailing: UInt8 = 0
        let extra = Darwin.read(objectDescriptor, &trailing, 1)
        guard extra == 0 else {
            if extra < 0, errno == EINTR {
                throw V2PoolObjectStoreError.objectReadFailed
            }
            throw V2PoolObjectStoreError.objectTooLarge
        }

        var after = stat()
        guard Darwin.fstat(objectDescriptor, &after) == 0,
              after.st_dev == before.st_dev,
              after.st_ino == before.st_ino,
              after.st_size == before.st_size else {
            throw V2PoolObjectStoreError.objectReadFailed
        }
        return data
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
}
