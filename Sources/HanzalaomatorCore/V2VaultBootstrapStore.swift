import Foundation

public enum V2VaultBootstrapStoreError: Error, Equatable, Sendable {
    case rootAlreadyContainsVaultLayout
    case invalidInitializationKeyCount
    case duplicateInitializationMasterKey
    case duplicateInitializationRecoveryKey
    case duplicateInitializationAnchor
    case missingEnvelope
    case envelopeIsNotRegularFile
    case envelopeTooLarge
    case invalidEnvelope
    case envelopeCommitFailed
    case invalidNewPassword
    case envelopeChangedDuringPasswordChange
    /// The new envelope may already be on disk, but reading it back failed.
    case passwordChangeOutcomeUncertain
}

public struct V2CreatedVaultFoundation: Sendable {
    public let root: URL
    public let envelope: DualAccessEnvelopeV2
    public let visibleMasterKey: Data
    public let concealedMasterKey: Data?
    public let visibleRecoveryKey: String?
    public let concealedRecoveryKey: String?

    public init(
        root: URL,
        envelope: DualAccessEnvelopeV2,
        visibleMasterKey: Data,
        concealedMasterKey: Data?,
        visibleRecoveryKey: String? = nil,
        concealedRecoveryKey: String? = nil
    ) {
        self.root = root
        self.envelope = envelope
        self.visibleMasterKey = visibleMasterKey
        self.concealedMasterKey = concealedMasterKey
        self.visibleRecoveryKey = visibleRecoveryKey
        self.concealedRecoveryKey = concealedRecoveryKey
    }
}

public struct V2OpenedVaultAccessFoundation: Sendable {
    public let root: URL
    public let envelope: DualAccessEnvelopeV2
    public let access: UnlockedVaultAccess
    public let metadata: V2AccessMetadata

    public init(
        root: URL,
        envelope: DualAccessEnvelopeV2,
        access: UnlockedVaultAccess,
        metadata: V2AccessMetadata
    ) {
        self.root = root
        self.envelope = envelope
        self.access = access
        self.metadata = metadata
    }
}

/// Creates and opens the complete *disabled* v2 bootstrap foundation.
///
/// Public storage symmetry is maintained for both password and recovery paths:
/// visible-only and dual-access creation both write two encrypted metadata
/// anchors plus two encrypted recovery anchors. In visible-only mode the second
/// password slot, metadata anchor, recovery secret, and recovery anchor are dummy
/// material whose secrets are discarded after bootstrap. The public envelope and
/// pool therefore do not gain an object-count marker for concealed access.
///
/// Bootstrap publishes the public envelope last and only after all four private
/// anchors have been authenticated. Existing password and HZRK opens retain one
/// no-follow root descriptor from the public envelope read through private-anchor
/// resolution, then require the public path to resolve to that same root before an
/// unlocked foundation is returned.
public final class V2VaultBootstrapStore {
    public static let maximumEnvelopeByteCount = 1024 * 1024

    private struct DecodedEnvelopeSnapshot {
        let envelope: DualAccessEnvelopeV2
        let rootIdentity: V2DescriptorBoundEnvelopeReader.RootIdentity
    }

    private let fileManager: FileManager
    private let envelopeEngine: DualAccessEnvelopeEngine
    private let metadataStore: V2AccessMetadataStore
    private let locator: V2StorageNamespaceLocator
    private let recoveryAnchorStore: V2RecoveryAnchorStore
    private let durableCommitter: V2DurableFileCommitter
    private let descriptorEnvelopeCommitter: V2DescriptorBoundEnvelopeCommitter
    private let descriptorEnvelopeReader: V2DescriptorBoundEnvelopeReader
    private let retainedRootObjectReader: V2RetainedRootObjectReader
    private let retainedRootMetadataReader: V2RetainedRootMetadataReader
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    #if canImport(Darwin)
    /// Internal deterministic seams used by namespace-race tests only.
    var envelopeBeforeNamespaceCommitHook: (() -> Void)? {
        get { descriptorEnvelopeCommitter.beforeNamespaceCommitHook }
        set { descriptorEnvelopeCommitter.beforeNamespaceCommitHook = newValue }
    }

    var envelopeReadOpenedHook: (() -> Void)? {
        get { descriptorEnvelopeReader.envelopeOpenedHook }
        set { descriptorEnvelopeReader.envelopeOpenedHook = newValue }
    }

    /// Fired after credential authentication but before any private anchor is
    /// resolved. Tests use this to model a hostile replace-and-restore window.
    var unlockBeforePrivateAnchorHook: (() -> Void)?

    /// Fired after all private anchors for the selected credential have been read
    /// but before the public root path is checked for session publication.
    var unlockAfterPrivateAnchorHook: (() -> Void)?
    #endif

    public init(
        fileManager: FileManager = .default,
        envelopeEngine: DualAccessEnvelopeEngine = DualAccessEnvelopeEngine(),
        metadataStore: V2AccessMetadataStore = V2AccessMetadataStore(),
        locator: V2StorageNamespaceLocator = V2StorageNamespaceLocator(),
        recoveryAnchorStore: V2RecoveryAnchorStore = V2RecoveryAnchorStore(),
        durableCommitter: V2DurableFileCommitter? = nil
    ) {
        let resolvedCommitter = durableCommitter ?? V2DurableFileCommitter(fileManager: fileManager)
        let retainedObjectReader = V2RetainedRootObjectReader(fileManager: fileManager)
        self.fileManager = fileManager
        self.envelopeEngine = envelopeEngine
        self.metadataStore = metadataStore
        self.locator = locator
        self.recoveryAnchorStore = recoveryAnchorStore
        self.durableCommitter = resolvedCommitter
        self.descriptorEnvelopeCommitter = V2DescriptorBoundEnvelopeCommitter(
            durableCommitter: resolvedCommitter
        )
        self.descriptorEnvelopeReader = V2DescriptorBoundEnvelopeReader(
            fileManager: fileManager,
            maximumByteCount: Self.maximumEnvelopeByteCount
        )
        self.retainedRootObjectReader = retainedObjectReader
        self.retainedRootMetadataReader = V2RetainedRootMetadataReader(
            locator: locator,
            objectReader: retainedObjectReader
        )
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        // Base64 output has a fixed character length for fixed-size Data, but
        // default JSON slash escaping can add a variable number of backslashes
        // depending on random ciphertext bytes. Never let that become a public
        // visible-only vs dual-access size signal.
        self.encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder.dateDecodingStrategy = .iso8601
    }

    public func createVisibleOnly(
        at root: URL,
        password: String,
        budget: V2StorageBudget,
        vaultID: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> V2CreatedVaultFoundation {
        let created = try envelopeEngine.createVisibleOnly(
            password: password,
            vaultID: vaultID,
            createdAt: createdAt
        )
        return try bootstrap(
            created,
            budgets: [budget, budget],
            at: root
        )
    }

    public func createDualAccess(
        at root: URL,
        visiblePassword: String,
        concealedPassword: String,
        visibleBudget: V2StorageBudget,
        concealedBudget: V2StorageBudget,
        vaultID: UUID = UUID(),
        createdAt: Date = Date()
    ) throws -> V2CreatedVaultFoundation {
        let created = try envelopeEngine.createDualAccess(
            visiblePassword: visiblePassword,
            concealedPassword: concealedPassword,
            vaultID: vaultID,
            createdAt: createdAt
        )
        return try bootstrap(
            created,
            budgets: [visibleBudget, concealedBudget],
            at: root
        )
    }

    /// Unlocks exactly one password slot and resolves its metadata anchor through
    /// the same retained root descriptor that supplied `vault.hanzala`.
    ///
    /// A hostile process may temporarily rebind the public root pathname, but it
    /// cannot redirect the private metadata read to that replacement. The path
    /// must resolve back to the retained root before this method publishes an
    /// unlocked foundation.
    public func openAccess(
        at root: URL,
        password: String
    ) throws -> V2OpenedVaultAccessFoundation {
        let retainedRoot = try makeRetainedRoot(at: root)
        let openedEnvelope = try readEnvelopeSnapshot(using: retainedRoot)
        let access = try envelopeEngine.unlock(
            envelope: openedEnvelope.envelope,
            password: password
        )

        #if canImport(Darwin)
        unlockBeforePrivateAnchorHook?()
        #endif
        let metadata = try retainedRootMetadataReader.read(
            masterKey: access.masterKey,
            using: retainedRoot
        )
        #if canImport(Darwin)
        unlockAfterPrivateAnchorHook?()
        #endif

        guard retainedRoot.pathStillMatches() else {
            throw V2VaultBootstrapStoreError.invalidEnvelope
        }

        return V2OpenedVaultAccessFoundation(
            root: root,
            envelope: openedEnvelope.envelope,
            access: access,
            metadata: metadata
        )
    }

    /// Recovers exactly one access path from one HZRK secret. Envelope, recovery
    /// anchor, and authenticated metadata are all resolved through one retained
    /// vault-root capability; the shared pool is never enumerated.
    public func openRecoveryAccess(
        at root: URL,
        recoveryKey: String
    ) throws -> V2OpenedVaultAccessFoundation {
        do {
            let retainedRoot = try V2RetainedVaultRoot(at: root)
            let openedEnvelope = try readEnvelopeSnapshot(using: retainedRoot)

            #if canImport(Darwin)
            unlockBeforePrivateAnchorHook?()
            #endif
            let recovered = try recoveryAnchorStore.recover(
                recoveryKey: recoveryKey,
                vaultID: openedEnvelope.envelope.vaultID,
                using: retainedRoot,
                objectReader: retainedRootObjectReader
            )
            let metadata = try retainedRootMetadataReader.read(
                masterKey: recovered.access.masterKey,
                using: retainedRoot
            )
            #if canImport(Darwin)
            unlockAfterPrivateAnchorHook?()
            #endif

            guard metadata.accessID == recovered.accessID,
                  retainedRoot.pathStillMatches() else {
                throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
            }

            return V2OpenedVaultAccessFoundation(
                root: root,
                envelope: openedEnvelope.envelope,
                access: recovered.access,
                metadata: metadata
            )
        } catch V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor {
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        } catch {
            // Root rebinding, envelope failures, and private-anchor failures all
            // stay on the same recovery surface; do not turn namespace races into
            // an HZRK existence oracle.
            throw V2RecoveryAnchorError.invalidRecoveryKeyOrCorruptedAnchor
        }
    }

    /// Rewrites only the visible password slot of the public envelope.
    ///
    /// The caller proves it holds an open session: `masterKey` must
    /// authenticate this vault's metadata anchor, and `expectedEnvelopeBinding`
    /// must equal the envelope on disk both before the new slot is derived and
    /// again just before it is published (compare-and-swap). Another change in
    /// between therefore fails instead of being silently overwritten.
    ///
    /// The replacement is staged, synchronized and swapped in atomically, so a
    /// crash leaves either the old or the new envelope, each fully valid. No
    /// file, metadata or recovery anchor is touched; the Recovery Key keeps
    /// working. Returns the published envelope.
    public func replaceVisiblePassword(
        at root: URL,
        masterKey: Data,
        expectedEnvelopeBinding: Data,
        newPassword: String
    ) throws -> DualAccessEnvelopeV2 {
        guard !newPassword.isEmpty else {
            throw V2VaultBootstrapStoreError.invalidNewPassword
        }

        let retainedRoot = try makeRetainedRoot(at: root)
        let current = try readEnvelopeSnapshot(using: retainedRoot)
        guard try canonicalData(current.envelope) == expectedEnvelopeBinding else {
            throw V2VaultBootstrapStoreError.envelopeChangedDuringPasswordChange
        }
        // The key must belong to this vault before its envelope is rewritten.
        _ = try retainedRootMetadataReader.read(
            masterKey: masterKey,
            using: retainedRoot
        )

        let updated = try envelopeEngine.replacingVisiblePassword(
            in: current.envelope,
            masterKey: masterKey,
            newPassword: newPassword
        )
        let data = try canonicalData(updated)
        guard data.count <= Self.maximumEnvelopeByteCount else {
            throw V2VaultBootstrapStoreError.envelopeTooLarge
        }

        // Key derivation took a while; check nothing moved in the meantime.
        let latest = try readEnvelopeSnapshot(using: retainedRoot)
        guard try canonicalData(latest.envelope) == expectedEnvelopeBinding,
              retainedRoot.pathStillMatches() else {
            throw V2VaultBootstrapStoreError.envelopeChangedDuringPasswordChange
        }

        do {
            try durableCommitter.replaceExisting(
                data,
                at: V2StorageLayout.accessEnvelopeURL(in: root),
                stagingPrefix: ".hanzala-v2-envelope-stage-"
            )
        } catch let crash as V2DurableCommitSimulatedCrash {
            throw crash
        } catch {
            // The swap can succeed and still report an error. Only an
            // envelope that still matches the old binding is "not changed".
            let stillOld = (try? canonicalData(readEnvelope(at: root))) == expectedEnvelopeBinding
            throw stillOld
                ? V2VaultBootstrapStoreError.envelopeCommitFailed
                : V2VaultBootstrapStoreError.passwordChangeOutcomeUncertain
        }

        // From here the new envelope may be published: never report a plain
        // failure, or the user would keep using a password that no longer works.
        let writtenMatches = (try? canonicalData(readEnvelope(at: root))) == data
        guard writtenMatches else {
            throw V2VaultBootstrapStoreError.passwordChangeOutcomeUncertain
        }
        return updated
    }

    public func readEnvelope(at root: URL) throws -> DualAccessEnvelopeV2 {
        try readEnvelopeSnapshot(at: root).envelope
    }

    /// Same encoding the session store uses for its envelope binding.
    private func canonicalData(_ envelope: DualAccessEnvelopeV2) throws -> Data {
        do {
            return try encoder.encode(envelope)
        } catch {
            throw V2VaultBootstrapStoreError.invalidEnvelope
        }
    }

    private func makeRetainedRoot(at root: URL) throws -> V2RetainedVaultRoot {
        do {
            return try V2RetainedVaultRoot(at: root)
        } catch {
            throw V2VaultBootstrapStoreError.envelopeIsNotRegularFile
        }
    }

    private func readEnvelopeSnapshot(at root: URL) throws -> DecodedEnvelopeSnapshot {
        let snapshot: V2DescriptorBoundEnvelopeReader.Snapshot
        do {
            snapshot = try descriptorEnvelopeReader.read(at: root)
        } catch V2DescriptorBoundEnvelopeReadError.missingEnvelope {
            throw V2VaultBootstrapStoreError.missingEnvelope
        } catch V2DescriptorBoundEnvelopeReadError.envelopeIsNotRegularFile {
            throw V2VaultBootstrapStoreError.envelopeIsNotRegularFile
        } catch V2DescriptorBoundEnvelopeReadError.envelopeTooLarge {
            throw V2VaultBootstrapStoreError.envelopeTooLarge
        } catch V2DescriptorBoundEnvelopeReadError.rootUnavailable {
            throw V2VaultBootstrapStoreError.envelopeIsNotRegularFile
        } catch {
            throw V2VaultBootstrapStoreError.invalidEnvelope
        }
        return try decodeEnvelopeSnapshot(snapshot)
    }

    private func readEnvelopeSnapshot(
        using retainedRoot: V2RetainedVaultRoot
    ) throws -> DecodedEnvelopeSnapshot {
        let snapshot: V2DescriptorBoundEnvelopeReader.Snapshot
        do {
            snapshot = try descriptorEnvelopeReader.read(using: retainedRoot)
        } catch V2DescriptorBoundEnvelopeReadError.missingEnvelope {
            throw V2VaultBootstrapStoreError.missingEnvelope
        } catch V2DescriptorBoundEnvelopeReadError.envelopeIsNotRegularFile {
            throw V2VaultBootstrapStoreError.envelopeIsNotRegularFile
        } catch V2DescriptorBoundEnvelopeReadError.envelopeTooLarge {
            throw V2VaultBootstrapStoreError.envelopeTooLarge
        } catch V2DescriptorBoundEnvelopeReadError.rootUnavailable {
            throw V2VaultBootstrapStoreError.envelopeIsNotRegularFile
        } catch {
            throw V2VaultBootstrapStoreError.invalidEnvelope
        }
        return try decodeEnvelopeSnapshot(snapshot)
    }

    private func decodeEnvelopeSnapshot(
        _ snapshot: V2DescriptorBoundEnvelopeReader.Snapshot
    ) throws -> DecodedEnvelopeSnapshot {
        let envelope: DualAccessEnvelopeV2
        do {
            envelope = try decoder.decode(DualAccessEnvelopeV2.self, from: snapshot.data)
        } catch {
            throw V2VaultBootstrapStoreError.invalidEnvelope
        }
        guard envelope.formatVersion == DualAccessEnvelopeV2.formatVersion,
              envelope.accessSlots.count == DualAccessEnvelopeV2.fixedSlotCount else {
            throw V2VaultBootstrapStoreError.invalidEnvelope
        }
        return DecodedEnvelopeSnapshot(
            envelope: envelope,
            rootIdentity: snapshot.rootIdentity
        )
    }

    private func bootstrap(
        _ created: CreatedDualAccessEnvelope,
        budgets: [V2StorageBudget],
        at root: URL
    ) throws -> V2CreatedVaultFoundation {
        let keys = created.storageInitializationMasterKeys
        guard keys.count == DualAccessEnvelopeV2.fixedSlotCount,
              budgets.count == DualAccessEnvelopeV2.fixedSlotCount else {
            throw V2VaultBootstrapStoreError.invalidInitializationKeyCount
        }
        guard Set(keys).count == keys.count else {
            throw V2VaultBootstrapStoreError.duplicateInitializationMasterKey
        }

        let recoveryCredentials = keys.map { _ in recoveryAnchorStore.generateCredential() }
        guard Set(recoveryCredentials.map(\.keyMaterial)).count == recoveryCredentials.count else {
            throw V2VaultBootstrapStoreError.duplicateInitializationRecoveryKey
        }

        let metadataAnchorNames = try keys.map {
            try locator.indexObjectName(masterKey: $0)
        }
        let recoveryAnchorNames = try recoveryCredentials.map {
            try recoveryAnchorStore.objectName(
                for: $0,
                vaultID: created.envelope.vaultID
            )
        }
        let allAnchorNames = metadataAnchorNames + recoveryAnchorNames
        guard Set(allAnchorNames).count == allAnchorNames.count else {
            throw V2VaultBootstrapStoreError.duplicateInitializationAnchor
        }

        let envelopeURL = V2StorageLayout.accessEnvelopeURL(in: root)
        let v1IndexURL = VaultLayout.indexURL(in: root)
        let poolURL = V2StorageLayout.poolURL(in: root)
        let journalURL = VaultLayout.journalURL(in: root)

        // Refuse all known v1/v2 layout components. Never reinterpret or remove a
        // pre-existing layout during creation.
        guard !fileManager.fileExists(atPath: envelopeURL.path),
              !fileManager.fileExists(atPath: v1IndexURL.path),
              !fileManager.fileExists(atPath: poolURL.path),
              !fileManager.fileExists(atPath: journalURL.path) else {
            throw V2VaultBootstrapStoreError.rootAlreadyContainsVaultLayout
        }

        let rootExisted = fileManager.fileExists(atPath: root.path)
        var createdPoolDirectory = false
        var committedAnchorNames: [String] = []
        var initializedMetadata: [V2AccessMetadata] = []
        var wroteEnvelope = false
        var rootIdentity: V2DescriptorBoundEnvelopeCommitter.RootIdentity?

        do {
            try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
            try fileManager.createDirectory(at: poolURL, withIntermediateDirectories: false)
            createdPoolDirectory = true
            rootIdentity = try descriptorEnvelopeCommitter.captureRootIdentity(at: root)

            for index in keys.indices {
                let metadata = try metadataStore.createInitialEmpty(
                    budget: budgets[index],
                    masterKey: keys[index],
                    in: root
                )
                initializedMetadata.append(metadata)
                committedAnchorNames.append(metadataAnchorNames[index])
            }

            for index in keys.indices {
                let role: VaultAccessRole = index == 0 ? .visible : .concealed
                let returnedName = try recoveryAnchorStore.createAnchor(
                    credential: recoveryCredentials[index],
                    access: UnlockedVaultAccess(
                        role: role,
                        masterKey: keys[index]
                    ),
                    accessID: initializedMetadata[index].accessID,
                    vaultID: created.envelope.vaultID,
                    budget: budgets[index],
                    in: root
                )
                guard returnedName == recoveryAnchorNames[index] else {
                    throw V2VaultBootstrapStoreError.duplicateInitializationAnchor
                }
                committedAnchorNames.append(returnedName)
            }

            // Authenticate every private anchor before publishing any public
            // envelope. This also proves that the current root path still reaches
            // the complete private foundation produced in this invocation.
            for index in keys.indices {
                let metadata = try metadataStore.read(
                    masterKey: keys[index],
                    in: root
                )
                guard metadata.accessID == initializedMetadata[index].accessID else {
                    throw V2VaultBootstrapStoreError.invalidEnvelope
                }

                let expectedRole: VaultAccessRole = index == 0 ? .visible : .concealed
                let recovered = try recoveryAnchorStore.recover(
                    recoveryKey: recoveryCredentials[index].displayKey,
                    vaultID: created.envelope.vaultID,
                    in: root
                )
                guard recovered.access.role == expectedRole,
                      recovered.access.masterKey == keys[index],
                      recovered.accessID == initializedMetadata[index].accessID else {
                    throw V2VaultBootstrapStoreError.invalidEnvelope
                }
            }

            guard let rootIdentity,
                  descriptorEnvelopeCommitter.rootPathStillMatches(rootIdentity, at: root) else {
                throw V2DescriptorBoundEnvelopeCommitError.rootNamespaceChanged
            }

            let envelopeData: Data
            do {
                envelopeData = try encoder.encode(created.envelope)
            } catch {
                throw V2VaultBootstrapStoreError.invalidEnvelope
            }
            try commitNewEnvelope(
                envelopeData,
                in: root,
                expectedRootIdentity: rootIdentity
            )
            wroteEnvelope = true

            _ = try readEnvelope(at: root)

            return V2CreatedVaultFoundation(
                root: root,
                envelope: created.envelope,
                visibleMasterKey: created.visibleMasterKey,
                concealedMasterKey: created.concealedMasterKey,
                visibleRecoveryKey: recoveryCredentials[0].displayKey,
                concealedRecoveryKey: created.concealedMasterKey == nil
                    ? nil
                    : recoveryCredentials[1].displayKey
            )
        } catch let crash as V2DurableCommitSimulatedCrash {
            // Fault-injection models process death: do not run cooperative
            // rollback that a real dead process could not perform.
            throw crash
        } catch {
            // If the root pathname no longer resolves to the root this bootstrap
            // created/accepted, never perform pathname-based cleanup against an
            // attacker-substituted directory. Leaving encrypted orphan state in
            // the displaced original is safer than deleting unrelated data.
            if let rootIdentity,
               !descriptorEnvelopeCommitter.rootPathStillMatches(rootIdentity, at: root) {
                throw V2VaultBootstrapStoreError.envelopeCommitFailed
            }

            if wroteEnvelope {
                try? fileManager.removeItem(at: envelopeURL)
            }
            // Remove only exact objects whose successful creation this invocation
            // recorded. Never recursively delete unknown pool contents.
            for name in committedAnchorNames {
                try? fileManager.removeItem(
                    at: V2StorageLayout.objectURL(named: name, in: root)
                )
            }
            if createdPoolDirectory,
               let contents = try? fileManager.contentsOfDirectory(atPath: poolURL.path),
               contents.isEmpty {
                try? fileManager.removeItem(at: poolURL)
            }
            if !rootExisted,
               let contents = try? fileManager.contentsOfDirectory(atPath: root.path),
               contents.isEmpty {
                try? fileManager.removeItem(at: root)
            }
            throw error
        }
    }

    private func commitNewEnvelope(
        _ data: Data,
        in root: URL,
        expectedRootIdentity: V2DescriptorBoundEnvelopeCommitter.RootIdentity
    ) throws {
        guard data.count <= Self.maximumEnvelopeByteCount else {
            throw V2VaultBootstrapStoreError.envelopeTooLarge
        }

        do {
            try descriptorEnvelopeCommitter.writeNew(
                data,
                in: root,
                expectedRootIdentity: expectedRootIdentity
            )
        } catch V2DescriptorBoundEnvelopeCommitError.destinationAlreadyExists {
            throw V2VaultBootstrapStoreError.rootAlreadyContainsVaultLayout
        } catch let crash as V2DurableCommitSimulatedCrash {
            throw crash
        } catch {
            throw V2VaultBootstrapStoreError.envelopeCommitFailed
        }
    }
}
