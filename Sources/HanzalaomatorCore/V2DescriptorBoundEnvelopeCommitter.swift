import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum V2DescriptorBoundEnvelopeCommitError: Error, Equatable, Sendable {
    case rootUnavailable
    case rootNamespaceChanged
    case destinationAlreadyExists
    case stagingWriteFailed
    case stagingSyncFailed
    case commitFailed
}

/// Publishes the public v2 `vault.hanzala` file relative to a retained vault-root
/// directory descriptor on Darwin.
///
/// Bootstrap captures a role-neutral root identity immediately after creating the
/// layout. The final public envelope can then be published only if the root opened
/// for the commit is still that same filesystem object. Staging/final namespace
/// mutations stay relative to the retained root descriptor.
///
/// There remains a narrow race between the final path identity check and return;
/// the actual envelope write itself remains descriptor-bound. This helper does not
/// claim a filesystem-wide transactional root.
final class V2DescriptorBoundEnvelopeCommitter {
    struct RootIdentity: Equatable, Sendable {
        #if canImport(Darwin)
        let device: UInt64
        let inode: UInt64
        #endif

        #if !canImport(Darwin)
        init() {}
        #endif
    }

    private let durableCommitter: V2DurableFileCommitter

    /// Deterministic test seam called after staging has synchronized, immediately
    /// before the retained/public root identity is checked for final publication.
    var beforeNamespaceCommitHook: (() -> Void)?

    init(durableCommitter: V2DurableFileCommitter = V2DurableFileCommitter()) {
        self.durableCommitter = durableCommitter
    }

    func captureRootIdentity(at root: URL) throws -> RootIdentity {
        #if canImport(Darwin)
        let descriptor = root.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard descriptor >= 0 else {
            throw V2DescriptorBoundEnvelopeCommitError.rootUnavailable
        }
        defer { Darwin.close(descriptor) }

        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              (information.st_mode & S_IFMT) == S_IFDIR else {
            throw V2DescriptorBoundEnvelopeCommitError.rootUnavailable
        }
        return RootIdentity(
            device: UInt64(information.st_dev),
            inode: UInt64(information.st_ino)
        )
        #else
        _ = root
        return RootIdentity()
        #endif
    }

    func rootPathStillMatches(_ identity: RootIdentity, at root: URL) -> Bool {
        #if canImport(Darwin)
        var current = stat()
        let result = root.path.withCString {
            Darwin.lstat($0, &current)
        }
        guard result == 0,
              (current.st_mode & S_IFMT) == S_IFDIR else {
            return false
        }
        return UInt64(current.st_dev) == identity.device
            && UInt64(current.st_ino) == identity.inode
        #else
        _ = identity
        _ = root
        return true
        #endif
    }

    func writeNew(
        _ data: Data,
        in root: URL,
        expectedRootIdentity: RootIdentity
    ) throws {
        #if canImport(Darwin)
        let rootDescriptor = root.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard rootDescriptor >= 0 else {
            throw V2DescriptorBoundEnvelopeCommitError.rootUnavailable
        }
        defer { Darwin.close(rootDescriptor) }

        var openedRootInformation = stat()
        guard Darwin.fstat(rootDescriptor, &openedRootInformation) == 0,
              (openedRootInformation.st_mode & S_IFMT) == S_IFDIR,
              UInt64(openedRootInformation.st_dev) == expectedRootIdentity.device,
              UInt64(openedRootInformation.st_ino) == expectedRootIdentity.inode else {
            throw V2DescriptorBoundEnvelopeCommitError.rootNamespaceChanged
        }

        let destinationName = V2StorageLayout.accessEnvelopeName
        var rootMismatchObserved = false
        do {
            try durableCommitter.writeNew(
                data,
                named: destinationName,
                inDirectoryDescriptor: rootDescriptor,
                directoryURL: root,
                stagingPrefix: ".hanzala-v2-envelope-stage-",
                beforeNamespaceCommit: { [weak self] in
                    self?.beforeNamespaceCommitHook?()
                    let matches = self?.rootPathStillMatches(
                        expectedRootIdentity,
                        at: root
                    ) == true
                    if !matches {
                        rootMismatchObserved = true
                    }
                    return matches
                }
            )
        } catch V2DurableFileCommitError.destinationAlreadyExists {
            throw V2DescriptorBoundEnvelopeCommitError.destinationAlreadyExists
        } catch V2DurableFileCommitError.stagingSyncFailed {
            throw V2DescriptorBoundEnvelopeCommitError.stagingSyncFailed
        } catch V2DurableFileCommitError.stagingCreateFailed {
            throw V2DescriptorBoundEnvelopeCommitError.stagingWriteFailed
        } catch V2DurableFileCommitError.stagingWriteFailed {
            throw V2DescriptorBoundEnvelopeCommitError.stagingWriteFailed
        } catch let crash as V2DurableCommitSimulatedCrash {
            throw crash
        } catch {
            if rootMismatchObserved {
                throw V2DescriptorBoundEnvelopeCommitError.rootNamespaceChanged
            }
            throw V2DescriptorBoundEnvelopeCommitError.commitFailed
        }

        guard rootPathStillMatches(expectedRootIdentity, at: root) else {
            // Publication happened in the retained original directory, but the
            // public path moved. Report an ambiguous failure rather than treating
            // an unrelated replacement directory as the created vault.
            throw V2DescriptorBoundEnvelopeCommitError.rootNamespaceChanged
        }
        #else
        _ = expectedRootIdentity
        let destination = V2StorageLayout.accessEnvelopeURL(in: root)
        do {
            try durableCommitter.writeNew(
                data,
                to: destination,
                stagingPrefix: ".hanzala-v2-envelope-stage-"
            )
        } catch V2DurableFileCommitError.destinationAlreadyExists {
            throw V2DescriptorBoundEnvelopeCommitError.destinationAlreadyExists
        } catch V2DurableFileCommitError.stagingSyncFailed {
            throw V2DescriptorBoundEnvelopeCommitError.stagingSyncFailed
        } catch V2DurableFileCommitError.stagingCreateFailed {
            throw V2DescriptorBoundEnvelopeCommitError.stagingWriteFailed
        } catch V2DurableFileCommitError.stagingWriteFailed {
            throw V2DescriptorBoundEnvelopeCommitError.stagingWriteFailed
        } catch {
            throw V2DescriptorBoundEnvelopeCommitError.commitFailed
        }
        #endif
    }
}
