import Foundation

/// Opens the same v2 session capability from an authenticated HZRK recovery
/// credential instead of a password.
///
/// Recovery-key resolution stays in `V2VaultBootstrapStore`: exactly one opaque
/// recovery anchor is derived and authenticated, then its recovered master key
/// must authenticate the normal metadata anchor and matching access ID. This
/// coordinator only converts that already-authenticated foundation into the
/// standard `V2VaultSession` capability and runs the same pending-transaction
/// recovery used by password-opened sessions.
///
/// The shared pool is never scanned and the returned session exposes no raw key.
/// Hidden/Decoy UI remains disabled; this is storage/session foundation only.
public final class V2RecoverySessionCoordinator {
    private let bootstrapStore: V2VaultBootstrapStore
    private let sessionStore: V2VaultSessionStore

    public init(
        bootstrapStore: V2VaultBootstrapStore = V2VaultBootstrapStore(),
        sessionStore: V2VaultSessionStore? = nil
    ) {
        self.bootstrapStore = bootstrapStore
        self.sessionStore = sessionStore ?? V2VaultSessionStore(
            bootstrapStore: bootstrapStore
        )
    }

    /// Returns a normal v2 session only after:
    /// 1. the supplied HZRK locates/authenticates exactly one recovery anchor;
    /// 2. the recovered master key authenticates its matching metadata anchor;
    /// 3. recovery-anchor and metadata access IDs agree;
    /// 4. the current public envelope is captured as the session binding;
    /// 5. authenticated pending imports/chunk imports/removals are recovered.
    ///
    /// Malformed/missing/wrong recovery credentials keep the generic recovery
    /// failure behavior defined by `V2VaultBootstrapStore.openRecoveryAccess`.
    public func openSession(
        at root: URL,
        recoveryKey: String
    ) throws -> V2OpenedVaultSession {
        let opened = try bootstrapStore.openRecoveryAccess(
            at: root,
            recoveryKey: recoveryKey
        )
        let binding = try canonicalEnvelopeData(opened.envelope)
        let session = V2VaultSession(
            root: root,
            vaultID: opened.envelope.vaultID,
            accessID: opened.metadata.accessID,
            role: opened.access.role,
            masterKey: opened.access.masterKey,
            envelopeBinding: binding
        )

        let recovery = try sessionStore.recover(session: session)
        // Re-enter the normal public session boundary once more after recovery.
        // This repeats envelope/access identity validation before publishing the
        // capability to the caller without exposing private store internals here.
        _ = try sessionStore.listEntries(in: session)
        return V2OpenedVaultSession(session: session, recovery: recovery)
    }

    private func canonicalEnvelopeData(_ envelope: DualAccessEnvelopeV2) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        do {
            return try encoder.encode(envelope)
        } catch {
            throw V2VaultSessionError.envelopeBindingFailed
        }
    }
}
