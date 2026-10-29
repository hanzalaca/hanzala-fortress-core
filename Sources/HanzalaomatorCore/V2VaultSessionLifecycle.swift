import Foundation

public enum V2VaultSessionLifecycleError: Error, Equatable, Sendable {
    case alreadyUnlocked
    case locked
    case openCancelled
    case finderLeaseNotFound
    /// The new password was saved, but `lock()` ran before the change
    /// finished, so the vault stays locked. Open it with the new password.
    case lockedAfterPasswordChange
    case passwordChangeInProgress
}

public struct V2VaultSessionIdentity: Equatable, Sendable {
    public let root: URL
    public let vaultID: UUID
    public let accessID: UUID
    public let role: VaultAccessRole

    public init(root: URL, vaultID: UUID, accessID: UUID, role: VaultAccessRole) {
        self.root = root
        self.vaultID = vaultID
        self.accessID = accessID
        self.role = role
    }
}

public struct V2VaultLifecycleOpenResult: Equatable, Sendable {
    public let identity: V2VaultSessionIdentity
    public let recovery: V2VaultSessionRecoveryReport

    public init(identity: V2VaultSessionIdentity, recovery: V2VaultSessionRecoveryReport) {
        self.identity = identity
        self.recovery = recovery
    }
}

/// Memory-only application lifecycle boundary for exactly one unlocked v2 access
/// path at a time.
///
/// The controller deliberately keeps `V2VaultSession` (and therefore its master
/// key) private. Callers receive only non-secret identity/recovery information and
/// capability-style operations. Finder receives a `V2FinderReadOnlySession`, not
/// the underlying v2 session or master key.
///
/// Password and HZRK recovery opens enter the same `opening` state machine. A
/// successful credential selects exactly one authenticated access path, while
/// callers never receive the raw recovered key or a separate visible/concealed
/// mode selector.
///
/// `lock()` is fail-closed for Finder: every issued Finder lease is invalidated
/// before this method returns and the active v2 session reference is forgotten.
/// A concurrent password/KDF or recovery open that finishes after `lock()` is
/// discarded and never becomes the active session.
public final class V2VaultSessionLifecycle {
    public struct FinderLease {
        public let id: UUID
        public let root: URL
        public let session: V2FinderReadOnlySession

        fileprivate init(id: UUID, root: URL, session: V2FinderReadOnlySession) {
            self.id = id
            self.root = root
            self.session = session
        }
    }

    private enum State {
        case locked
        case opening(UUID)
        case unlocked(session: V2VaultSession, generation: UUID)
    }

    private let sessionStore: V2VaultSessionStore
    private let recoverySessionCoordinator: V2RecoverySessionCoordinator
    private let lockObject = NSLock()
    private var state: State = .locked
    private var finderLeases: [UUID: V2FinderReadOnlySession] = [:]
    private var isChangingPassword = false

    public init(
        sessionStore: V2VaultSessionStore = V2VaultSessionStore(),
        recoverySessionCoordinator: V2RecoverySessionCoordinator? = nil
    ) {
        self.sessionStore = sessionStore
        self.recoverySessionCoordinator = recoverySessionCoordinator
            ?? V2RecoverySessionCoordinator(sessionStore: sessionStore)
    }

    deinit {
        lock()
    }

    public var isUnlocked: Bool {
        lockObject.lock()
        defer { lockObject.unlock() }
        if case .unlocked = state { return true }
        return false
    }

    public var identity: V2VaultSessionIdentity? {
        lockObject.lock()
        defer { lockObject.unlock() }
        guard case .unlocked(let session, _) = state else { return nil }
        return Self.identity(for: session)
    }

    /// Opens exactly one password-selected v2 access path. There is no separate
    /// concealed-mode selector: the password selects the slot inside the generic
    /// v2 envelope.
    @discardableResult
    public func open(at root: URL, password: String) throws -> V2VaultLifecycleOpenResult {
        try performOpen {
            try sessionStore.openSession(at: root, password: password)
        }
    }

    /// Opens exactly one authenticated v2 access path from one HZRK recovery key.
    /// The lifecycle state and post-open capabilities are identical to a password
    /// open; the credential type does not create a second session implementation.
    @discardableResult
    public func openRecovery(
        at root: URL,
        recoveryKey: String
    ) throws -> V2VaultLifecycleOpenResult {
        try performOpen {
            try recoverySessionCoordinator.openSession(
                at: root,
                recoveryKey: recoveryKey
            )
        }
    }

    /// Changes the password of the open (visible) access path, whether it was
    /// opened with the old password or the Recovery Key. The Recovery Key and
    /// all files stay as they are.
    ///
    /// Finder capabilities are bound to the old envelope, so they are revoked
    /// here; callers mount Finder again. If `lock()` wins the race, or the
    /// change may have been published but could not be confirmed, the vault is
    /// locked and `lockedAfterPasswordChange` is thrown: the new password is
    /// the one to use. One change runs at a time per lifecycle.
    public func changePassword(to newPassword: String) throws {
        let snapshot: (session: V2VaultSession, generation: UUID)

        lockObject.lock()
        guard case .unlocked(let session, let generation) = state else {
            lockObject.unlock()
            throw V2VaultSessionLifecycleError.locked
        }
        guard !isChangingPassword else {
            lockObject.unlock()
            throw V2VaultSessionLifecycleError.passwordChangeInProgress
        }
        isChangingPassword = true
        snapshot = (session, generation)
        lockObject.unlock()
        defer {
            lockObject.lock()
            isChangingPassword = false
            lockObject.unlock()
        }

        let refreshed: V2VaultSession
        do {
            refreshed = try sessionStore.changeVisiblePassword(
                in: snapshot.session,
                to: newPassword
            )
        } catch V2VaultBootstrapStoreError.passwordChangeOutcomeUncertain {
            lock()
            throw V2VaultSessionLifecycleError.lockedAfterPasswordChange
        }

        lockObject.lock()
        guard case .unlocked(_, let currentGeneration) = state,
              currentGeneration == snapshot.generation else {
            lockObject.unlock()
            throw V2VaultSessionLifecycleError.lockedAfterPasswordChange
        }
        let finders = Array(finderLeases.values)
        finderLeases.removeAll()
        state = .unlocked(session: refreshed, generation: UUID())
        lockObject.unlock()

        for finder in finders {
            finder.invalidate()
        }
    }

    public func listEntries() throws -> [V2AccessEntry] {
        let session = try activeSession()
        return try sessionStore.listEntries(in: session)
    }

    /// The unlocked vault's fixed capacity, or nil for an ordinary vault.
    public func fixedCapacityStatus() throws -> V2FixedCapacityStatus? {
        let session = try activeSession()
        return try sessionStore.fixedCapacityStatus(in: session)
    }

    /// Makes the unlocked, still empty vault fixed-capacity, or resumes an
    /// interrupted fill. See `V2VaultSessionStore.prepareFixedCapacity`.
    public func prepareFixedCapacity(
        capacityBytes: UInt64,
        progress: ((Int, Int) -> Void)? = nil
    ) throws {
        let session = try activeSession()
        try sessionStore.prepareFixedCapacity(
            capacityBytes: capacityBytes,
            in: session,
            progress: progress
        )
    }

    @discardableResult
    public func importFile(
        at sourceURL: URL,
        originalName: String? = nil,
        trustedSourceDirectory: URL? = nil
    ) throws -> V2AccessEntry {
        let session = try activeSession()
        return try sessionStore.importFile(
            at: sourceURL,
            originalName: originalName,
            trustedSourceDirectory: trustedSourceDirectory,
            into: session
        )
    }

    public func readEntryRange(id entryID: UUID, offset: UInt64, length: Int) throws -> Data {
        let session = try activeSession()
        return try sessionStore.readEntryRange(
            id: entryID,
            offset: offset,
            length: length,
            in: session
        )
    }

    public func verifyEntryIntegrity(id entryID: UUID) throws {
        let session = try activeSession()
        try sessionStore.verifyEntryIntegrity(id: entryID, in: session)
    }

    @discardableResult
    public func removeEntry(id entryID: UUID) throws -> UUID {
        let session = try activeSession()
        return try sessionStore.removeEntry(id: entryID, from: session)
    }

    /// Issues a read-only Finder capability without exposing `V2VaultSession`.
    /// The returned session is tracked so `lock()` can revoke it even if the
    /// mount coordinator is delayed or macOS refuses to unmount immediately.
    public func makeFinderLease(
        maximumReadLength: Int = V2FinderReadOnlySession.defaultMaximumReadLength
    ) throws -> FinderLease {
        let snapshot: (session: V2VaultSession, generation: UUID)

        lockObject.lock()
        guard case .unlocked(let session, let generation) = state else {
            lockObject.unlock()
            throw V2VaultSessionLifecycleError.locked
        }
        snapshot = (session, generation)
        lockObject.unlock()

        let finderSession = V2FinderReadOnlySession(
            session: snapshot.session,
            sessionStore: sessionStore,
            maximumReadLength: maximumReadLength
        )
        let leaseID = UUID()

        lockObject.lock()
        guard case .unlocked(_, let currentGeneration) = state,
              currentGeneration == snapshot.generation else {
            lockObject.unlock()
            finderSession.invalidate()
            throw V2VaultSessionLifecycleError.locked
        }
        finderLeases[leaseID] = finderSession
        lockObject.unlock()

        return FinderLease(id: leaseID, root: snapshot.session.root, session: finderSession)
    }

    /// Releases one Finder capability. This is idempotent for callers that race
    /// normal close with global lock/unmount cleanup.
    public func releaseFinderLease(id leaseID: UUID) {
        lockObject.lock()
        let finder = finderLeases.removeValue(forKey: leaseID)
        lockObject.unlock()
        finder?.invalidate()
    }

    /// Revokes all Finder capabilities first, then drops the active/opening v2
    /// session state. The caller should stop its IPC server before or immediately
    /// after this call; stale Finder handles cannot produce further plaintext.
    public func lock() {
        lockObject.lock()
        let finders = Array(finderLeases.values)
        finderLeases.removeAll()
        state = .locked
        lockObject.unlock()

        for finder in finders {
            finder.invalidate()
        }
    }

    public func activeFinderLeaseCount() -> Int {
        lockObject.lock()
        defer { lockObject.unlock() }
        return finderLeases.count
    }

    private func performOpen(
        _ opener: () throws -> V2OpenedVaultSession
    ) throws -> V2VaultLifecycleOpenResult {
        let attemptID = UUID()

        lockObject.lock()
        guard case .locked = state else {
            lockObject.unlock()
            throw V2VaultSessionLifecycleError.alreadyUnlocked
        }
        state = .opening(attemptID)
        lockObject.unlock()

        do {
            let opened = try opener()

            lockObject.lock()
            guard case .opening(let currentAttemptID) = state,
                  currentAttemptID == attemptID else {
                lockObject.unlock()
                throw V2VaultSessionLifecycleError.openCancelled
            }
            let generation = UUID()
            state = .unlocked(session: opened.session, generation: generation)
            lockObject.unlock()

            return V2VaultLifecycleOpenResult(
                identity: Self.identity(for: opened.session),
                recovery: opened.recovery
            )
        } catch {
            lockObject.lock()
            if case .opening(let currentAttemptID) = state,
               currentAttemptID == attemptID {
                state = .locked
            }
            lockObject.unlock()
            throw error
        }
    }

    private func activeSession() throws -> V2VaultSession {
        lockObject.lock()
        defer { lockObject.unlock() }
        guard case .unlocked(let session, _) = state else {
            throw V2VaultSessionLifecycleError.locked
        }
        return session
    }

    private static func identity(for session: V2VaultSession) -> V2VaultSessionIdentity {
        V2VaultSessionIdentity(
            root: session.root,
            vaultID: session.vaultID,
            accessID: session.accessID,
            role: session.role
        )
    }
}
