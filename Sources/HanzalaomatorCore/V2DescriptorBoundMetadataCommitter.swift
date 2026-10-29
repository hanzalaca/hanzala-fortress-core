import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum V2DescriptorBoundMetadataCommitError: Error, Equatable, Sendable {
    case invalidAnchorName
    case rootUnavailable
    case poolUnavailable
    case anchorUnavailable
    case anchorIsNotRegularFile
    case anchorTooLarge
    case anchorReadFailed
    case staleAnchor
    case stagingCreateFailed
    case stagingWriteFailed
    case stagingSyncFailed
    case namespaceChanged
    case commitFailed
    case namespaceSyncFailed
}

/// Darwin-only metadata replacement primitive that keeps the vault root, shared
/// `objects` directory, and authenticated metadata anchor open as retained
/// no-follow descriptors from the stale-generation check through publication.
///
/// The final replacement remains a pathname operation relative to the retained
/// pool descriptor. macOS has no compare-and-swap rename keyed by the destination
/// inode, so a hostile process can still race the final `fstatat` -> `renameat`
/// interval. That narrow residual is documented rather than treated as solved.
final class V2DescriptorBoundMetadataCommitter {
    typealias CurrentValidator = (Data) throws -> Void
    typealias BeforeStaging = () throws -> Void

    private let durableCommitter: V2DurableFileCommitter

    /// Deterministic test seam invoked after root/pool/anchor descriptors are open.
    var descriptorsOpenedHook: (() -> Void)?

    /// Deterministic test seam invoked after staging is durable but before the
    /// retained namespace identities are rechecked and the final rename occurs.
    var beforeNamespaceCommitHook: (() -> Void)?

    init(durableCommitter: V2DurableFileCommitter = V2DurableFileCommitter()) {
        self.durableCommitter = durableCommitter
    }

    #if canImport(Darwin)
    func replaceExisting(
        _ data: Data,
        named anchorName: String,
        in root: URL,
        validateCurrent: CurrentValidator,
        beforeStaging: BeforeStaging = {}
    ) throws {
        guard V2OpaqueObjectName.isValid(anchorName) else {
            throw V2DescriptorBoundMetadataCommitError.invalidAnchorName
        }

        let rootDescriptor = root.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard rootDescriptor >= 0 else {
            throw V2DescriptorBoundMetadataCommitError.rootUnavailable
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
            throw V2DescriptorBoundMetadataCommitError.poolUnavailable
        }
        defer { Darwin.close(poolDescriptor) }

        var openedPoolInformation = stat()
        guard Darwin.fstat(poolDescriptor, &openedPoolInformation) == 0,
              (openedPoolInformation.st_mode & S_IFMT) == S_IFDIR else {
            throw V2DescriptorBoundMetadataCommitError.poolUnavailable
        }

        let anchorDescriptor = anchorName.withCString {
            Darwin.openat(
                poolDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard anchorDescriptor >= 0 else {
            throw V2DescriptorBoundMetadataCommitError.anchorUnavailable
        }
        defer { Darwin.close(anchorDescriptor) }

        var openedAnchorInformation = stat()
        guard Darwin.fstat(anchorDescriptor, &openedAnchorInformation) == 0 else {
            throw V2DescriptorBoundMetadataCommitError.anchorUnavailable
        }
        guard (openedAnchorInformation.st_mode & S_IFMT) == S_IFREG else {
            throw V2DescriptorBoundMetadataCommitError.anchorIsNotRegularFile
        }
        guard openedAnchorInformation.st_size >= 0,
              openedAnchorInformation.st_size <= off_t(V2PoolObjectCodec.maximumEnvelopeByteCount) else {
            throw V2DescriptorBoundMetadataCommitError.anchorTooLarge
        }

        descriptorsOpenedHook?()

        let currentBytes = try readExactly(
            descriptor: anchorDescriptor,
            byteCount: Int(openedAnchorInformation.st_size)
        )
        try validateCurrent(currentBytes)
        try beforeStaging()

        let destinationURL = V2StorageLayout.objectURL(named: anchorName, in: root)
        let stagingPrefix = ".hanzala-v2-metadata-stage-"
        var stagingName: String?
        var stagingDescriptor: Int32 = -1
        for _ in 0..<16 {
            let candidate = "\(stagingPrefix)\(UUID().uuidString).tmp"
            let descriptor = candidate.withCString {
                Darwin.openat(
                    poolDescriptor,
                    $0,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    mode_t(S_IRUSR | S_IWUSR)
                )
            }
            if descriptor >= 0 {
                stagingName = candidate
                stagingDescriptor = descriptor
                break
            }
            if errno != EEXIST {
                throw V2DescriptorBoundMetadataCommitError.stagingCreateFailed
            }
        }
        guard let stagingName, stagingDescriptor >= 0 else {
            throw V2DescriptorBoundMetadataCommitError.stagingCreateFailed
        }

        var stagingInformation = stat()
        guard Darwin.fstat(stagingDescriptor, &stagingInformation) == 0,
              (stagingInformation.st_mode & S_IFMT) == S_IFREG else {
            Darwin.close(stagingDescriptor)
            throw V2DescriptorBoundMetadataCommitError.stagingCreateFailed
        }

        var namespaceCommitted = false
        var preserveStagingForSimulatedCrash = false
        defer {
            Darwin.close(stagingDescriptor)
            if !namespaceCommitted && !preserveStagingForSimulatedCrash {
                removeIfSameInode(
                    named: stagingName,
                    expected: stagingInformation,
                    directoryDescriptor: poolDescriptor
                )
            }
        }

        do {
            try durableCommitter.injectDescriptorCommitCrashPoint(
                .afterStagingCreate,
                destination: destinationURL
            )
        } catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        try writeExactly(data, descriptor: stagingDescriptor)
        do {
            try durableCommitter.injectDescriptorCommitCrashPoint(
                .afterStagingWrite,
                destination: destinationURL
            )
        } catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        guard Darwin.fsync(stagingDescriptor) == 0 else {
            throw V2DescriptorBoundMetadataCommitError.stagingSyncFailed
        }
        if Darwin.fcntl(stagingDescriptor, F_FULLFSYNC) == -1 {
            let failure = errno
            guard failure == EINVAL || failure == ENOTSUP else {
                throw V2DescriptorBoundMetadataCommitError.stagingSyncFailed
            }
        }

        do {
            try durableCommitter.injectDescriptorCommitCrashPoint(
                .afterStagingSync,
                destination: destinationURL
            )
        } catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        var syncedStagingInformation = stat()
        guard Darwin.fstat(stagingDescriptor, &syncedStagingInformation) == 0,
              sameInode(stagingInformation, syncedStagingInformation),
              syncedStagingInformation.st_size == off_t(data.count) else {
            throw V2DescriptorBoundMetadataCommitError.stagingSyncFailed
        }
        stagingInformation = syncedStagingInformation

        beforeNamespaceCommitHook?()

        guard descriptorEntry(
            named: poolName,
            directoryDescriptor: rootDescriptor,
            stillRefersTo: openedPoolInformation,
            expectedType: S_IFDIR
        ), descriptorEntry(
            named: anchorName,
            directoryDescriptor: poolDescriptor,
            stillRefersTo: openedAnchorInformation,
            expectedType: S_IFREG
        ), descriptorEntry(
            named: stagingName,
            directoryDescriptor: poolDescriptor,
            stillRefersTo: stagingInformation,
            expectedType: S_IFREG
        ) else {
            throw V2DescriptorBoundMetadataCommitError.namespaceChanged
        }

        let renameResult = stagingName.withCString { stagingPointer in
            anchorName.withCString { anchorPointer in
                Darwin.renameat(
                    poolDescriptor,
                    stagingPointer,
                    poolDescriptor,
                    anchorPointer
                )
            }
        }
        guard renameResult == 0 else {
            throw V2DescriptorBoundMetadataCommitError.commitFailed
        }
        namespaceCommitted = true

        do {
            try durableCommitter.injectDescriptorCommitCrashPoint(
                .afterNamespaceCommit,
                destination: destinationURL
            )
        } catch let crash as V2DurableCommitSimulatedCrash {
            throw crash
        }

        guard descriptorEntry(
            named: anchorName,
            directoryDescriptor: poolDescriptor,
            stillRefersTo: stagingInformation,
            expectedType: S_IFREG
        ) else {
            throw V2DescriptorBoundMetadataCommitError.commitFailed
        }

        guard Darwin.fsync(poolDescriptor) == 0 else {
            // The rename has already happened. The caller treats this as an
            // ambiguous committed state and relies on authenticated recovery.
            throw V2DescriptorBoundMetadataCommitError.namespaceSyncFailed
        }
    }

    private func readExactly(descriptor: Int32, byteCount: Int) throws -> Data {
        var data = Data(count: byteCount)
        do {
            try data.withUnsafeMutableBytes { rawBuffer in
                guard byteCount > 0 else { return }
                guard let base = rawBuffer.baseAddress else {
                    throw V2DescriptorBoundMetadataCommitError.anchorReadFailed
                }
                var offset = 0
                while offset < byteCount {
                    let count = Darwin.pread(
                        descriptor,
                        base.advanced(by: offset),
                        byteCount - offset,
                        off_t(offset)
                    )
                    guard count > 0 else {
                        throw V2DescriptorBoundMetadataCommitError.anchorReadFailed
                    }
                    offset += count
                }
            }
        } catch let error as V2DescriptorBoundMetadataCommitError {
            throw error
        } catch {
            throw V2DescriptorBoundMetadataCommitError.anchorReadFailed
        }

        var afterRead = stat()
        guard Darwin.fstat(descriptor, &afterRead) == 0,
              afterRead.st_size == off_t(byteCount) else {
            throw V2DescriptorBoundMetadataCommitError.anchorReadFailed
        }
        return data
    }

    private func writeExactly(_ data: Data, descriptor: Int32) throws {
        do {
            try data.withUnsafeBytes { rawBuffer in
                guard !data.isEmpty else { return }
                guard let base = rawBuffer.baseAddress else {
                    throw V2DescriptorBoundMetadataCommitError.stagingWriteFailed
                }
                var offset = 0
                while offset < data.count {
                    let count = Darwin.write(
                        descriptor,
                        base.advanced(by: offset),
                        data.count - offset
                    )
                    guard count > 0 else {
                        throw V2DescriptorBoundMetadataCommitError.stagingWriteFailed
                    }
                    offset += count
                }
            }
        } catch let error as V2DescriptorBoundMetadataCommitError {
            throw error
        } catch {
            throw V2DescriptorBoundMetadataCommitError.stagingWriteFailed
        }
    }

    private func descriptorEntry(
        named name: String,
        directoryDescriptor: Int32,
        stillRefersTo expected: stat,
        expectedType: mode_t
    ) -> Bool {
        var current = stat()
        let result = name.withCString {
            Darwin.fstatat(
                directoryDescriptor,
                $0,
                &current,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard result == 0,
              (current.st_mode & S_IFMT) == expectedType else {
            return false
        }
        return sameInode(current, expected)
    }

    private func removeIfSameInode(
        named name: String,
        expected: stat,
        directoryDescriptor: Int32
    ) {
        guard descriptorEntry(
            named: name,
            directoryDescriptor: directoryDescriptor,
            stillRefersTo: expected,
            expectedType: S_IFREG
        ) else { return }
        _ = name.withCString {
            Darwin.unlinkat(directoryDescriptor, $0, 0)
        }
    }

    private func sameInode(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }
    #endif
}
