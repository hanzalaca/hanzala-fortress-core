import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum V2RetainedVaultRootError: Error, Equatable, Sendable {
    case unavailable
}

/// Retains one no-follow vault-root directory capability across a complete v2
/// unlock transaction.
///
/// The public pathname is used only once to acquire the directory descriptor.
/// Envelope, recovery-anchor, and metadata reads can then stay relative to the
/// same opened root even if another process temporarily rebinds the pathname.
/// Before an unlocked capability is published, callers must still require that
/// the public pathname resolves back to this retained root identity.
final class V2RetainedVaultRoot {
    let url: URL
    let device: UInt64
    let inode: UInt64

    #if canImport(Darwin)
    let descriptor: Int32
    #endif

    init(at url: URL) throws {
        self.url = url

        #if canImport(Darwin)
        let opened = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard opened >= 0 else {
            throw V2RetainedVaultRootError.unavailable
        }

        var information = stat()
        guard Darwin.fstat(opened, &information) == 0,
              (information.st_mode & S_IFMT) == S_IFDIR else {
            Darwin.close(opened)
            throw V2RetainedVaultRootError.unavailable
        }

        self.descriptor = opened
        self.device = UInt64(information.st_dev)
        self.inode = UInt64(information.st_ino)
        #else
        let values: URLResourceValues
        do {
            values = try url.resourceValues(forKeys: [
                .isDirectoryKey,
                .isSymbolicLinkKey
            ])
        } catch {
            throw V2RetainedVaultRootError.unavailable
        }
        guard values.isSymbolicLink != true,
              values.isDirectory == true else {
            throw V2RetainedVaultRootError.unavailable
        }
        self.device = 0
        self.inode = 0
        #endif
    }

    deinit {
        #if canImport(Darwin)
        Darwin.close(descriptor)
        #endif
    }

    func pathStillMatches() -> Bool {
        #if canImport(Darwin)
        var current = stat()
        let result = url.path.withCString { Darwin.lstat($0, &current) }
        guard result == 0,
              (current.st_mode & S_IFMT) == S_IFDIR else {
            return false
        }
        return UInt64(current.st_dev) == device
            && UInt64(current.st_ino) == inode
        #else
        guard let values = try? url.resourceValues(forKeys: [
            .isDirectoryKey,
            .isSymbolicLinkKey
        ]),
        values.isSymbolicLink != true,
        values.isDirectory == true else {
            return false
        }
        return true
        #endif
    }
}
