import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum V2SecureSourceFileError: Error, Equatable, Sendable {
    case sourceOpenFailed
    case sourceIsSymbolicLink
    case sourceNotRegularFile
    case sourceSizeUnavailable
    case sourceReadFailed
    case sourceSeekFailed
    case sourceChanged
}

/// Descriptor-bound reader for untrusted import source paths.
///
/// On Darwin the absolute source path is traversed one component at a time from
/// a root directory descriptor. Every ancestor is opened with
/// `openat(... O_NOFOLLOW | O_DIRECTORY)` and the final component is opened with
/// `openat(... O_NOFOLLOW)`. Once an ancestor is opened, later pathname replacement
/// of that ancestor cannot retarget subsequent traversal away from its retained
/// directory descriptor.
///
/// An app sandbox (iOS on a real device) may refuse to open the system folders
/// above the app's own container, so a caller can name a `trustedDirectory` it
/// owns. Traversal then starts from that directory, opened with `O_NOFOLLOW`,
/// and every component below it is still opened one at a time without
/// following links.
///
/// The final regular-file, size, identity, and mutation checks are performed with
/// `fstat` on the already-open file descriptor. All reads and rewinds remain bound
/// to that same descriptor.
final class V2SecureSourceFile {
    let byteCount: Int

    private let handle: FileHandle

    #if canImport(Darwin)
    typealias AncestorOpenedHook = (_ componentIndex: Int, _ component: String) throws -> Void

    private struct Snapshot: Equatable {
        let device: Int64
        let inode: UInt64
        let byteCount: Int64
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let changeSeconds: Int64
        let changeNanoseconds: Int64
    }

    private let snapshot: Snapshot
    #else
    private let sourceURL: URL
    private let initialModificationDate: Date?
    #endif

    #if canImport(Darwin)
    convenience init(url: URL, trustedDirectory: URL? = nil) throws {
        try self.init(url: url, trustedDirectory: trustedDirectory, ancestorOpenedHook: nil)
    }

    /// Internal deterministic hook is used only by tests to replace an ancestor
    /// after that exact directory has been opened. Production callers use the
    /// no-hook initializer above.
    init(
        url: URL,
        trustedDirectory: URL? = nil,
        ancestorOpenedHook: AncestorOpenedHook?
    ) throws {
        let descriptor = try Self.openDescriptorRelative(
            url: url,
            trustedDirectory: trustedDirectory,
            ancestorOpenedHook: ancestorOpenedHook
        )

        do {
            let captured = try Self.captureSnapshot(descriptor: descriptor)
            guard captured.byteCount >= 0,
                  UInt64(captured.byteCount) <= UInt64(Int.max) else {
                throw V2SecureSourceFileError.sourceSizeUnavailable
            }
            self.byteCount = Int(captured.byteCount)
            self.snapshot = captured
            self.handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }
    #else
    init(url: URL, trustedDirectory: URL? = nil) throws {
        let values: URLResourceValues
        do {
            values = try url.resourceValues(forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey,
                .fileSizeKey,
                .contentModificationDateKey
            ])
        } catch {
            throw V2SecureSourceFileError.sourceOpenFailed
        }
        guard values.isSymbolicLink != true else {
            throw V2SecureSourceFileError.sourceIsSymbolicLink
        }
        guard values.isRegularFile == true else {
            throw V2SecureSourceFileError.sourceNotRegularFile
        }
        guard let size = values.fileSize, size >= 0 else {
            throw V2SecureSourceFileError.sourceSizeUnavailable
        }
        do {
            self.handle = try FileHandle(forReadingFrom: url)
        } catch {
            throw V2SecureSourceFileError.sourceOpenFailed
        }
        self.byteCount = size
        self.sourceURL = url
        self.initialModificationDate = values.contentModificationDate
    }
    #endif

    func read(upToCount count: Int) throws -> Data {
        guard count >= 0 else {
            throw V2SecureSourceFileError.sourceReadFailed
        }
        do {
            return try handle.read(upToCount: count) ?? Data()
        } catch {
            throw V2SecureSourceFileError.sourceReadFailed
        }
    }

    /// Rewinds the same already-open descriptor. On Darwin no pathname lookup is
    /// performed, so a racing rename/replacement cannot redirect pass two of a
    /// streaming import to another file.
    func rewind() throws {
        #if canImport(Darwin)
        guard Darwin.lseek(handle.fileDescriptor, 0, SEEK_SET) != -1 else {
            throw V2SecureSourceFileError.sourceSeekFailed
        }
        try validateUnchanged()
        #else
        do {
            try handle.seek(toOffset: 0)
        } catch {
            throw V2SecureSourceFileError.sourceSeekFailed
        }
        try validateUnchanged()
        #endif
    }

    /// Validates that the opened file itself still has the same identity, size,
    /// modification timestamp, and change timestamp captured at open.
    func validateUnchanged() throws {
        #if canImport(Darwin)
        let current = try Self.captureSnapshot(descriptor: handle.fileDescriptor)
        guard current == snapshot else {
            throw V2SecureSourceFileError.sourceChanged
        }
        #else
        let values: URLResourceValues
        do {
            values = try sourceURL.resourceValues(forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey,
                .fileSizeKey,
                .contentModificationDateKey
            ])
        } catch {
            throw V2SecureSourceFileError.sourceChanged
        }
        guard values.isSymbolicLink != true,
              values.isRegularFile == true,
              values.fileSize == byteCount,
              values.contentModificationDate == initialModificationDate else {
            throw V2SecureSourceFileError.sourceChanged
        }
        #endif
    }

    #if canImport(Darwin)
    private static func openDescriptorRelative(
        url: URL,
        trustedDirectory: URL?,
        ancestorOpenedHook: AncestorOpenedHook?
    ) throws -> Int32 {
        var components = try securePathComponents(for: url)
        var startPath = "/"
        if let trustedDirectory {
            let trusted = try securePathComponents(for: trustedDirectory)
            guard components.count > trusted.count,
                  Array(components.prefix(trusted.count)) == trusted else {
                throw V2SecureSourceFileError.sourceOpenFailed
            }
            components.removeFirst(trusted.count)
            startPath = "/" + trusted.joined(separator: "/")
        }
        guard let finalComponent = components.last else {
            throw V2SecureSourceFileError.sourceNotRegularFile
        }

        var directoryDescriptor = Darwin.open(
            startPath,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
        )
        guard directoryDescriptor >= 0 else {
            throw V2SecureSourceFileError.sourceOpenFailed
        }
        defer { Darwin.close(directoryDescriptor) }

        if components.count > 1 {
            for (index, component) in components.dropLast().enumerated() {
                let nextDescriptor = component.withCString {
                    Darwin.openat(
                        directoryDescriptor,
                        $0,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
                    )
                }
                guard nextDescriptor >= 0 else {
                    // Ancestor failures intentionally collapse onto the existing
                    // generic source-open failure surface so callers learn no
                    // component-level path detail.
                    throw V2SecureSourceFileError.sourceOpenFailed
                }

                Darwin.close(directoryDescriptor)
                directoryDescriptor = nextDescriptor
                try ancestorOpenedHook?(index, component)
            }
        }

        let descriptor = finalComponent.withCString {
            Darwin.openat(
                directoryDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else {
            let failure = errno
            if failure == ELOOP {
                throw V2SecureSourceFileError.sourceIsSymbolicLink
            }
            throw V2SecureSourceFileError.sourceOpenFailed
        }
        return descriptor
    }

    private static func securePathComponents(for url: URL) throws -> [String] {
        guard url.isFileURL else {
            throw V2SecureSourceFileError.sourceOpenFailed
        }
        let path = url.path
        guard path.hasPrefix("/") else {
            throw V2SecureSourceFileError.sourceOpenFailed
        }

        var components = path.split(
            separator: "/",
            omittingEmptySubsequences: true
        ).map(String.init)

        guard !components.contains(where: {
            $0 == "." || $0 == ".." || $0.utf8.contains(0)
        }) else {
            throw V2SecureSourceFileError.sourceOpenFailed
        }

        // macOS and iOS expose these root-level compatibility aliases as
        // symlinks (iOS app containers are reported under /var/mobile). Use
        // fixed OS-known canonical prefixes rather than following the symlink at
        // runtime, so ordinary /tmp and /var paths remain usable while arbitrary
        // user-controlled ancestor symlinks stay forbidden.
        #if os(macOS) || os(iOS)
        if let first = components.first {
            switch first {
            case "tmp":
                components.replaceSubrange(0...0, with: ["private", "tmp"])
            case "var":
                components.replaceSubrange(0...0, with: ["private", "var"])
            case "etc":
                components.replaceSubrange(0...0, with: ["private", "etc"])
            default:
                break
            }
        }
        #endif

        return components
    }

    private static func captureSnapshot(descriptor: Int32) throws -> Snapshot {
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0 else {
            throw V2SecureSourceFileError.sourceOpenFailed
        }
        guard (information.st_mode & S_IFMT) == S_IFREG else {
            throw V2SecureSourceFileError.sourceNotRegularFile
        }
        guard information.st_size >= 0 else {
            throw V2SecureSourceFileError.sourceSizeUnavailable
        }

        return Snapshot(
            device: Int64(information.st_dev),
            inode: UInt64(information.st_ino),
            byteCount: Int64(information.st_size),
            modificationSeconds: Int64(information.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(information.st_mtimespec.tv_nsec),
            changeSeconds: Int64(information.st_ctimespec.tv_sec),
            changeNanoseconds: Int64(information.st_ctimespec.tv_nsec)
        )
    }
    #endif
}
