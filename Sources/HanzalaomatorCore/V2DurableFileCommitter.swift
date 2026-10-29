import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum V2DurableFileCommitError: Error, Equatable, Sendable {
    case stagingCreateFailed
    case stagingWriteFailed
    case stagingSyncFailed
    case destinationAlreadyExists
    case destinationMissing
    case destinationStillExists
    case namespaceSyncFailed
    case commitFailed
}

/// Internal deterministic cut points used only by fault-injection tests.
/// Production initializers never install a fault injector.
enum V2DurableCommitCrashPoint: Equatable, Sendable {
    case afterStagingCreate
    case afterStagingWrite
    case afterStagingSync
    case afterNamespaceCommit
    case afterNamespaceDelete
}

enum V2DurableCommitSimulatedCrash: Error, Equatable, Sendable {
    case powerLoss(V2DurableCommitCrashPoint)
}

/// Role-neutral staged writer/deleter used by v2 ciphertext and envelope commits.
///
/// New/replacement durability is deliberately conservative: same-directory
/// staging, file sync, atomic namespace mutation, then best-effort parent sync.
/// Deletion is stricter: the exact namespace entry is unlinked and the parent
/// directory must synchronize before the deletion is reported as durable.
///
/// Darwin callers that already hold an authenticated directory capability can use
/// descriptor-relative creation, deletion, and absence confirmation. These
/// variants keep namespace mutation and synchronization on the retained directory
/// descriptor so replacing the directory pathname does not silently retarget the
/// operation.
///
/// This hardens crash recovery but does not claim perfect transactional behavior
/// across every filesystem, storage controller, external device, or hostile host.
public final class V2DurableFileCommitter {
    typealias FileSynchronizer = (FileHandle) throws -> Void
    typealias DirectorySynchronizer = (URL) throws -> Void
    typealias DirectoryDescriptorSynchronizer = (Int32, URL) throws -> Void
    typealias FaultInjector = (V2DurableCommitCrashPoint, URL) throws -> Void

    private static let maximumDescriptorStagingNameAttempts = 16

    private let fileManager: FileManager
    private let synchronizeFile: FileSynchronizer
    private let synchronizeDirectory: DirectorySynchronizer
    private let synchronizeDirectoryDescriptor: DirectoryDescriptorSynchronizer
    private let faultInjector: FaultInjector?

    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
        self.synchronizeFile = Self.defaultSynchronizeFile
        self.synchronizeDirectory = Self.defaultSynchronizeDirectory
        self.synchronizeDirectoryDescriptor = Self.defaultSynchronizeDirectoryDescriptor
        self.faultInjector = nil
    }

    init(
        fileManager: FileManager,
        synchronizeFile: @escaping FileSynchronizer,
        synchronizeDirectory: @escaping DirectorySynchronizer = V2DurableFileCommitter.defaultSynchronizeDirectory,
        synchronizeDirectoryDescriptor: DirectoryDescriptorSynchronizer? = nil,
        faultInjector: FaultInjector? = nil
    ) {
        self.fileManager = fileManager
        self.synchronizeFile = synchronizeFile
        self.synchronizeDirectory = synchronizeDirectory
        // The internal initializer is used by deterministic tests. If a test only
        // overrides the historical URL-based synchronizer, preserve that seam for
        // descriptor-relative calls as well. Production uses the public initializer
        // above and therefore fsyncs the retained directory descriptor directly.
        self.synchronizeDirectoryDescriptor = synchronizeDirectoryDescriptor ?? { _, url in
            try synchronizeDirectory(url)
        }
        self.faultInjector = faultInjector
    }

    public func writeNew(
        _ data: Data,
        to destination: URL,
        stagingPrefix: String
    ) throws {
        guard !fileManager.fileExists(atPath: destination.path) else {
            throw V2DurableFileCommitError.destinationAlreadyExists
        }
        let staging = try writeSynchronizedStagingFile(data, beside: destination, stagingPrefix: stagingPrefix)
        var preserveStagingForSimulatedCrash = false
        defer { if !preserveStagingForSimulatedCrash { try? fileManager.removeItem(at: staging) } }

        do { try fileManager.moveItem(at: staging, to: destination) }
        catch {
            if fileManager.fileExists(atPath: destination.path) {
                throw V2DurableFileCommitError.destinationAlreadyExists
            }
            throw V2DurableFileCommitError.commitFailed
        }
        do { try inject(.afterNamespaceCommit, destination: destination) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }
        try? synchronizeDirectory(destination.deletingLastPathComponent())
    }

    public func replaceExisting(
        _ data: Data,
        at destination: URL,
        stagingPrefix: String
    ) throws {
        guard fileManager.fileExists(atPath: destination.path) else {
            throw V2DurableFileCommitError.destinationMissing
        }
        let staging = try writeSynchronizedStagingFile(data, beside: destination, stagingPrefix: stagingPrefix)
        var preserveStagingForSimulatedCrash = false
        defer { if !preserveStagingForSimulatedCrash { try? fileManager.removeItem(at: staging) } }

        do { _ = try fileManager.replaceItemAt(destination, withItemAt: staging) }
        catch { throw V2DurableFileCommitError.commitFailed }
        do { try inject(.afterNamespaceCommit, destination: destination) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }
        try? synchronizeDirectory(destination.deletingLastPathComponent())
    }

    /// Unlinks one existing exact path and requires a parent-directory sync before
    /// reporting success. A failure after unlink is intentionally ambiguous: the
    /// caller must keep its authenticated tombstone and retry/confirm on reopen.
    public func removeExisting(at destination: URL) throws {
        guard fileManager.fileExists(atPath: destination.path) else {
            throw V2DurableFileCommitError.destinationMissing
        }
        do { try fileManager.removeItem(at: destination) }
        catch {
            if fileManager.fileExists(atPath: destination.path) {
                throw V2DurableFileCommitError.commitFailed
            }
        }
        try inject(.afterNamespaceDelete, destination: destination)
        do { try synchronizeDirectory(destination.deletingLastPathComponent()) }
        catch { throw V2DurableFileCommitError.namespaceSyncFailed }
    }

    /// Used by recovery when an authenticated tombstone refers to an object that
    /// is already absent. The absence is not finalized in metadata until the
    /// containing directory namespace can be synchronized in the current boot.
    public func confirmAbsentDurably(at destination: URL) throws {
        guard !fileManager.fileExists(atPath: destination.path) else {
            throw V2DurableFileCommitError.destinationStillExists
        }
        do { try synchronizeDirectory(destination.deletingLastPathComponent()) }
        catch { throw V2DurableFileCommitError.namespaceSyncFailed }
    }

    #if canImport(Darwin)
    /// Creates one new file entirely relative to a retained directory capability.
    /// `beforeNamespaceCommit` is called after the staging bytes have synchronized
    /// but before publication, allowing the owner to revalidate any higher-level
    /// directory binding (for example root/`objects` identity).
    ///
    /// Staging cleanup is inode-checked: if a hostile process replaces the random
    /// staging pathname, this method will not unlink the substituted entry.
    func writeNew(
        _ data: Data,
        named destinationName: String,
        inDirectoryDescriptor directoryDescriptor: Int32,
        directoryURL: URL,
        stagingPrefix: String,
        beforeNamespaceCommit: () -> Bool = { true }
    ) throws {
        guard Self.isSinglePathComponent(destinationName),
              Self.isSafeStagingPrefix(stagingPrefix) else {
            throw V2DurableFileCommitError.commitFailed
        }

        try requireDescriptorEntryAbsent(
            named: destinationName,
            inDirectoryDescriptor: directoryDescriptor
        )

        let destinationURL = directoryURL.appendingPathComponent(
            destinationName,
            isDirectory: false
        )

        var stagingName: String?
        var stagingDescriptor: Int32 = -1
        for _ in 0..<Self.maximumDescriptorStagingNameAttempts {
            let candidate = "\(stagingPrefix)\(UUID().uuidString).tmp"
            let descriptor = candidate.withCString {
                Darwin.openat(
                    directoryDescriptor,
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
                throw V2DurableFileCommitError.stagingCreateFailed
            }
        }
        guard let stagingName, stagingDescriptor >= 0 else {
            throw V2DurableFileCommitError.stagingCreateFailed
        }

        var stagingInformation = stat()
        guard Darwin.fstat(stagingDescriptor, &stagingInformation) == 0,
              (stagingInformation.st_mode & S_IFMT) == S_IFREG else {
            Darwin.close(stagingDescriptor)
            throw V2DurableFileCommitError.stagingCreateFailed
        }

        let handle = FileHandle(
            fileDescriptor: stagingDescriptor,
            closeOnDealloc: true
        )
        var preserveStagingForSimulatedCrash = false
        var namespaceCommitted = false
        defer {
            try? handle.close()
            if !preserveStagingForSimulatedCrash && !namespaceCommitted {
                Self.removeStagingIfSameInode(
                    named: stagingName,
                    expected: stagingInformation,
                    inDirectoryDescriptor: directoryDescriptor
                )
            }
        }

        do { try inject(.afterStagingCreate, destination: destinationURL) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        do { try handle.write(contentsOf: data) }
        catch { throw V2DurableFileCommitError.stagingWriteFailed }

        do { try inject(.afterStagingWrite, destination: destinationURL) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        do { try synchronizeFile(handle) }
        catch { throw V2DurableFileCommitError.stagingSyncFailed }

        do { try inject(.afterStagingSync, destination: destinationURL) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        var afterSyncInformation = stat()
        guard Darwin.fstat(stagingDescriptor, &afterSyncInformation) == 0,
              Self.sameInode(stagingInformation, afterSyncInformation),
              afterSyncInformation.st_size == off_t(data.count) else {
            throw V2DurableFileCommitError.stagingSyncFailed
        }
        stagingInformation = afterSyncInformation

        guard beforeNamespaceCommit() else {
            throw V2DurableFileCommitError.commitFailed
        }
        guard Self.descriptorEntry(
            named: stagingName,
            inDirectoryDescriptor: directoryDescriptor,
            stillRefersTo: stagingInformation
        ) else {
            throw V2DurableFileCommitError.commitFailed
        }

        // Recheck before RENAME_EXCL so expected collisions are reported cleanly.
        try requireDescriptorEntryAbsent(
            named: destinationName,
            inDirectoryDescriptor: directoryDescriptor
        )

        let renameResult = stagingName.withCString { stagingPointer in
            destinationName.withCString { destinationPointer in
                Darwin.renameatx_np(
                    directoryDescriptor,
                    stagingPointer,
                    directoryDescriptor,
                    destinationPointer,
                    UInt32(RENAME_EXCL)
                )
            }
        }
        guard renameResult == 0 else {
            let failure = errno
            if failure == EEXIST || failure == ENOTEMPTY {
                throw V2DurableFileCommitError.destinationAlreadyExists
            }
            throw V2DurableFileCommitError.commitFailed
        }
        namespaceCommitted = true

        do { try inject(.afterNamespaceCommit, destination: destinationURL) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }

        guard Self.descriptorEntry(
            named: destinationName,
            inDirectoryDescriptor: directoryDescriptor,
            stillRefersTo: stagingInformation
        ) else {
            throw V2DurableFileCommitError.commitFailed
        }

        // Preserve the historical write-new contract: parent sync after publication
        // is best effort because callers recover ambiguous committed/missing states
        // from authenticated transaction metadata on reopen.
        try? synchronizeDirectoryDescriptor(directoryDescriptor, directoryURL)
    }

    /// Descriptor-relative counterpart of `removeExisting(at:)` for a directory
    /// capability that the caller has already opened and validated. The caller is
    /// responsible for proving that `name` still refers to the authenticated inode
    /// immediately before invoking this method.
    func removeExisting(
        named name: String,
        inDirectoryDescriptor directoryDescriptor: Int32,
        directoryURL: URL
    ) throws {
        var information = stat()
        let exists = name.withCString {
            Darwin.fstatat(
                directoryDescriptor,
                $0,
                &information,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard exists == 0 else {
            if errno == ENOENT {
                throw V2DurableFileCommitError.destinationMissing
            }
            throw V2DurableFileCommitError.commitFailed
        }

        let destination = directoryURL.appendingPathComponent(name, isDirectory: false)
        let result = name.withCString {
            Darwin.unlinkat(directoryDescriptor, $0, 0)
        }
        guard result == 0 else {
            if errno == ENOENT {
                throw V2DurableFileCommitError.destinationMissing
            }
            throw V2DurableFileCommitError.commitFailed
        }

        try inject(.afterNamespaceDelete, destination: destination)
        do {
            try synchronizeDirectoryDescriptor(directoryDescriptor, directoryURL)
        } catch {
            throw V2DurableFileCommitError.namespaceSyncFailed
        }
    }

    /// Confirms absence and synchronizes the exact retained directory capability.
    /// A symlink or any other namespace entry counts as present.
    func confirmAbsentDurably(
        named name: String,
        inDirectoryDescriptor directoryDescriptor: Int32,
        directoryURL: URL
    ) throws {
        var information = stat()
        let result = name.withCString {
            Darwin.fstatat(
                directoryDescriptor,
                $0,
                &information,
                AT_SYMLINK_NOFOLLOW
            )
        }
        if result == 0 {
            throw V2DurableFileCommitError.destinationStillExists
        }
        guard errno == ENOENT else {
            throw V2DurableFileCommitError.commitFailed
        }
        do {
            try synchronizeDirectoryDescriptor(directoryDescriptor, directoryURL)
        } catch {
            throw V2DurableFileCommitError.namespaceSyncFailed
        }
    }

    private func requireDescriptorEntryAbsent(
        named name: String,
        inDirectoryDescriptor directoryDescriptor: Int32
    ) throws {
        var information = stat()
        let result = name.withCString {
            Darwin.fstatat(
                directoryDescriptor,
                $0,
                &information,
                AT_SYMLINK_NOFOLLOW
            )
        }
        if result == 0 {
            throw V2DurableFileCommitError.destinationAlreadyExists
        }
        guard errno == ENOENT else {
            throw V2DurableFileCommitError.commitFailed
        }
    }

    private static func descriptorEntry(
        named name: String,
        inDirectoryDescriptor directoryDescriptor: Int32,
        stillRefersTo expected: stat
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
              (current.st_mode & S_IFMT) == S_IFREG else {
            return false
        }
        return sameInode(current, expected)
    }

    private static func removeStagingIfSameInode(
        named name: String,
        expected: stat,
        inDirectoryDescriptor directoryDescriptor: Int32
    ) {
        guard descriptorEntry(
            named: name,
            inDirectoryDescriptor: directoryDescriptor,
            stillRefersTo: expected
        ) else { return }
        _ = name.withCString {
            Darwin.unlinkat(directoryDescriptor, $0, 0)
        }
    }

    private static func sameInode(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }

    private static func isSinglePathComponent(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/")
    }

    private static func isSafeStagingPrefix(_ prefix: String) -> Bool {
        !prefix.isEmpty && !prefix.contains("/")
    }
    #endif

    private func writeSynchronizedStagingFile(
        _ data: Data,
        beside destination: URL,
        stagingPrefix: String
    ) throws -> URL {
        let parent = destination.deletingLastPathComponent()
        let staging = parent.appendingPathComponent("\(stagingPrefix)\(UUID().uuidString).tmp")
        guard fileManager.createFile(atPath: staging.path, contents: nil,
                                     attributes: [.posixPermissions: NSNumber(value: 0o600)]) else {
            throw V2DurableFileCommitError.stagingCreateFailed
        }
        var preserveStagingForSimulatedCrash = false
        defer { if !preserveStagingForSimulatedCrash { try? fileManager.removeItem(at: staging) } }

        do { try inject(.afterStagingCreate, destination: destination) }
        catch let crash as V2DurableCommitSimulatedCrash {
            preserveStagingForSimulatedCrash = true
            throw crash
        }
        let handle: FileHandle
        do { handle = try FileHandle(forWritingTo: staging) }
        catch { throw V2DurableFileCommitError.stagingCreateFailed }
        do { try handle.write(contentsOf: data) }
        catch { try? handle.close(); throw V2DurableFileCommitError.stagingWriteFailed }
        do { try inject(.afterStagingWrite, destination: destination) }
        catch let crash as V2DurableCommitSimulatedCrash {
            try? handle.close(); preserveStagingForSimulatedCrash = true; throw crash
        }
        do { try synchronizeFile(handle) }
        catch { try? handle.close(); throw V2DurableFileCommitError.stagingSyncFailed }
        do { try inject(.afterStagingSync, destination: destination) }
        catch let crash as V2DurableCommitSimulatedCrash {
            try? handle.close(); preserveStagingForSimulatedCrash = true; throw crash
        }
        do { try handle.close() }
        catch { throw V2DurableFileCommitError.stagingSyncFailed }
        preserveStagingForSimulatedCrash = true
        return staging
    }

    /// Keeps descriptor-specialized committers on the same deterministic crash
    /// matrix as the general durable writer. Production instances have no fault
    /// injector, so this is a no-op outside internal tests.
    func injectDescriptorCommitCrashPoint(
        _ point: V2DurableCommitCrashPoint,
        destination: URL
    ) throws {
        try inject(point, destination: destination)
    }

    private func inject(_ point: V2DurableCommitCrashPoint, destination: URL) throws {
        try faultInjector?(point, destination)
    }

    private static func defaultSynchronizeFile(_ handle: FileHandle) throws {
        try handle.synchronize()
        #if canImport(Darwin)
        if fcntl(handle.fileDescriptor, F_FULLFSYNC) == -1 {
            let failure = errno
            guard failure == EINVAL || failure == ENOTSUP else {
                throw V2DurableFileCommitError.stagingSyncFailed
            }
        }
        #endif
    }

    fileprivate static func defaultSynchronizeDirectory(_ directory: URL) throws {
        #if canImport(Darwin)
        let descriptor = directory.path.withCString { Darwin.open($0, O_RDONLY) }
        guard descriptor >= 0 else { throw V2DurableFileCommitError.namespaceSyncFailed }
        defer { Darwin.close(descriptor) }
        if Darwin.fsync(descriptor) == -1 {
            throw V2DurableFileCommitError.namespaceSyncFailed
        }
        #else
        _ = directory
        #endif
    }

    fileprivate static func defaultSynchronizeDirectoryDescriptor(
        _ descriptor: Int32,
        _ directory: URL
    ) throws {
        #if canImport(Darwin)
        _ = directory
        if Darwin.fsync(descriptor) == -1 {
            throw V2DurableFileCommitError.namespaceSyncFailed
        }
        #else
        _ = descriptor
        _ = directory
        #endif
    }
}
