import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum V2DescriptorBoundEnvelopeReadError: Error, Equatable, Sendable {
    case rootUnavailable
    case missingEnvelope
    case envelopeIsNotRegularFile
    case envelopeTooLarge
    case envelopeReadFailed
}

/// Reads the public v2 `vault.hanzala` envelope from one retained vault-root
/// directory capability instead of validating a pathname and reopening it.
///
/// The envelope is public metadata, but it selects password KDF parameters,
/// encrypted access slots, and the public vault identity. A hostile namespace
/// process therefore must not be able to swap the pathname between validation and
/// read and silently redirect the unlock path to another file.
///
/// On Darwin the root and envelope are opened with `O_NOFOLLOW`, the envelope is
/// bounded with `fstat` before allocation, and bytes are read only from the already
/// opened descriptor. A caller that needs more private reads can supply a
/// `V2RetainedVaultRoot` so the same root descriptor remains live for the entire
/// unlock transaction.
final class V2DescriptorBoundEnvelopeReader {
    struct RootIdentity: Equatable, Sendable {
        let device: UInt64
        let inode: UInt64
    }

    struct Snapshot: Sendable {
        let data: Data
        let rootIdentity: RootIdentity
    }

    private let fileManager: FileManager
    private let maximumByteCount: Int

    /// Deterministic test seam called only after the root and exact envelope have
    /// both been opened and statted. Production never installs this hook.
    var envelopeOpenedHook: (() -> Void)?

    init(
        fileManager: FileManager = .default,
        maximumByteCount: Int
    ) {
        self.fileManager = fileManager
        self.maximumByteCount = maximumByteCount
        self.envelopeOpenedHook = nil
    }

    func read(at root: URL) throws -> Snapshot {
        let retainedRoot: V2RetainedVaultRoot
        do {
            retainedRoot = try V2RetainedVaultRoot(at: root)
        } catch {
            throw V2DescriptorBoundEnvelopeReadError.rootUnavailable
        }
        return try read(using: retainedRoot)
    }

    /// Reads the envelope relative to a root descriptor owned by the caller.
    /// The descriptor remains valid after this method returns, allowing password
    /// or recovery resolution to continue against the same opened vault root.
    func read(using retainedRoot: V2RetainedVaultRoot) throws -> Snapshot {
        guard maximumByteCount >= 0 else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeTooLarge
        }

        #if canImport(Darwin)
        return try readDescriptorRelative(using: retainedRoot)
        #else
        return try readFoundationFallback(at: retainedRoot.url)
        #endif
    }

    func rootPathStillMatches(_ identity: RootIdentity, at root: URL) -> Bool {
        #if canImport(Darwin)
        var current = stat()
        let result = root.path.withCString { Darwin.lstat($0, &current) }
        guard result == 0,
              (current.st_mode & S_IFMT) == S_IFDIR else {
            return false
        }
        return UInt64(current.st_dev) == identity.device
            && UInt64(current.st_ino) == identity.inode
        #else
        guard let values = try? root.resourceValues(forKeys: [
            .isDirectoryKey,
            .isSymbolicLinkKey
        ]),
        values.isSymbolicLink != true,
        values.isDirectory == true else {
            return false
        }
        _ = identity
        return true
        #endif
    }

    #if canImport(Darwin)
    private func readDescriptorRelative(
        using retainedRoot: V2RetainedVaultRoot
    ) throws -> Snapshot {
        let rootDescriptor = retainedRoot.descriptor

        var rootInformation = stat()
        guard Darwin.fstat(rootDescriptor, &rootInformation) == 0,
              (rootInformation.st_mode & S_IFMT) == S_IFDIR,
              UInt64(rootInformation.st_dev) == retainedRoot.device,
              UInt64(rootInformation.st_ino) == retainedRoot.inode else {
            throw V2DescriptorBoundEnvelopeReadError.rootUnavailable
        }
        let rootIdentity = RootIdentity(
            device: retainedRoot.device,
            inode: retainedRoot.inode
        )

        let envelopeName = V2StorageLayout.accessEnvelopeName
        let envelopeDescriptor = envelopeName.withCString {
            Darwin.openat(
                rootDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard envelopeDescriptor >= 0 else {
            if errno == ENOENT {
                throw V2DescriptorBoundEnvelopeReadError.missingEnvelope
            }
            if errno == ELOOP {
                throw V2DescriptorBoundEnvelopeReadError.envelopeIsNotRegularFile
            }
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }
        defer { Darwin.close(envelopeDescriptor) }

        var before = stat()
        guard Darwin.fstat(envelopeDescriptor, &before) == 0 else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }
        guard (before.st_mode & S_IFMT) == S_IFREG else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeIsNotRegularFile
        }
        guard before.st_size >= 0,
              before.st_size <= off_t(maximumByteCount) else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeTooLarge
        }

        envelopeOpenedHook?()

        let expectedByteCount = Int(before.st_size)
        let data = try readExactly(
            descriptor: envelopeDescriptor,
            byteCount: expectedByteCount
        )

        var after = stat()
        guard Darwin.fstat(envelopeDescriptor, &after) == 0,
              sameContentSnapshot(before, after),
              after.st_size == off_t(expectedByteCount) else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }

        return Snapshot(data: data, rootIdentity: rootIdentity)
    }

    private func readExactly(descriptor: Int32, byteCount: Int) throws -> Data {
        if byteCount == 0 { return Data() }

        var data = Data(count: byteCount)
        var total = 0
        let succeeded = data.withUnsafeMutableBytes { rawBuffer -> Bool in
            guard let base = rawBuffer.baseAddress else { return false }
            while total < byteCount {
                let result = Darwin.read(
                    descriptor,
                    base.advanced(by: total),
                    byteCount - total
                )
                if result > 0 {
                    total += result
                    continue
                }
                if result == 0 { return false }
                if errno == EINTR { continue }
                return false
            }
            return true
        }
        guard succeeded, total == byteCount else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }
        return data
    }

    /// `ctime` is deliberately not a content-stability signal here. Renaming the
    /// already-open inode changes its status-change time on macOS even though the
    /// retained descriptor still addresses exactly the same bytes. Device/inode,
    /// size, and modification time detect the mutations relevant to this read
    /// without turning a harmless namespace rename into a false corruption result.
    private func sameContentSnapshot(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
    }
    #endif

    #if !canImport(Darwin)
    private func readFoundationFallback(at root: URL) throws -> Snapshot {
        let rootValues: URLResourceValues
        do {
            rootValues = try root.resourceValues(forKeys: [
                .isDirectoryKey,
                .isSymbolicLinkKey
            ])
        } catch {
            throw V2DescriptorBoundEnvelopeReadError.rootUnavailable
        }
        guard rootValues.isSymbolicLink != true,
              rootValues.isDirectory == true else {
            throw V2DescriptorBoundEnvelopeReadError.rootUnavailable
        }

        let url = V2StorageLayout.accessEnvelopeURL(in: root)
        guard fileManager.fileExists(atPath: url.path) else {
            throw V2DescriptorBoundEnvelopeReadError.missingEnvelope
        }
        let values: URLResourceValues
        do {
            values = try url.resourceValues(forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey,
                .fileSizeKey
            ])
        } catch {
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }
        guard values.isSymbolicLink != true,
              values.isRegularFile == true else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeIsNotRegularFile
        }
        guard let fileSize = values.fileSize,
              fileSize >= 0,
              fileSize <= maximumByteCount else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeTooLarge
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }
        guard data.count == fileSize else {
            throw V2DescriptorBoundEnvelopeReadError.envelopeReadFailed
        }
        return Snapshot(
            data: data,
            rootIdentity: RootIdentity(device: 0, inode: 0)
        )
    }
    #endif
}
