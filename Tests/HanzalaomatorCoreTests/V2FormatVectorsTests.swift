import XCTest
@testable import HanzalaomatorCore

/// Freezes the v2 on-disk format (Docs/V2-VAULT-FORMAT-SPEC.md).
///
/// The fixture vault and vectors were written by the independent Python
/// reference implementation in Scripts/vault_format_reference/. If any of
/// these tests fail, the Swift code no longer reads or writes the frozen
/// format: change the format only with a new version number and new vectors.
final class V2FormatVectorsTests: XCTestCase {
    private let fileManager = FileManager.default

    func testFixtureVaultOpensWithPassword() throws {
        let vectors = try loadVectors()
        let fixture = vectors.fixtureVault
        let root = try copyFixtureVault()
        defer { try? fileManager.removeItem(at: root) }

        XCTAssertEqual(try VaultFormatDetector().detect(at: root), .v2)

        let sessions = V2VaultSessionStore()
        let opened = try sessions.openSession(at: root, password: fixture.password)
        try assertFixtureContents(fixture, session: opened.session, sessions: sessions)

        XCTAssertThrowsError(
            try sessions.openSession(at: root, password: fixture.password + " ")
        )
        try assertUnchanged(root)
    }

    func testFixtureVaultOpensWithRecoveryKey() throws {
        let vectors = try loadVectors()
        let fixture = vectors.fixtureVault
        let root = try copyFixtureVault()
        defer { try? fileManager.removeItem(at: root) }

        let sessions = V2VaultSessionStore()
        let recovery = V2RecoverySessionCoordinator(sessionStore: sessions)
        let opened = try recovery.openSession(at: root, recoveryKey: fixture.recoveryKey)
        try assertFixtureContents(fixture, session: opened.session, sessions: sessions)

        let lowercase = try recovery.openSession(
            at: root,
            recoveryKey: fixture.recoveryKey.lowercased()
        )
        XCTAssertEqual(lowercase.session.accessID, opened.session.accessID)
        try assertUnchanged(root)
    }

    func testFixtureJSONIsByteExact() throws {
        let vectors = try loadVectors()
        let fixture = vectors.fixtureVault
        let root = try copyFixtureVault()
        defer { try? fileManager.removeItem(at: root) }

        let envelopeData = try Data(contentsOf: V2StorageLayout.accessEnvelopeURL(in: root))
        let envelopeDecoder = JSONDecoder()
        envelopeDecoder.dateDecodingStrategy = .iso8601
        let envelope = try envelopeDecoder.decode(DualAccessEnvelopeV2.self, from: envelopeData)
        XCTAssertEqual(envelope.formatVersion, 2)
        XCTAssertEqual(envelope.vaultID, try uuid(fixture.vaultID))
        XCTAssertEqual(envelope.accessSlots.count, 2)
        XCTAssertEqual(
            try encoder([.sortedKeys, .withoutEscapingSlashes], dates: true).encode(envelope),
            envelopeData
        )

        let masterKey = try hex(fixture.masterKeyHex)
        let codec = V2PoolObjectCodec()
        let metadataObject = try codec.open(
            try Data(contentsOf: V2StorageLayout.objectURL(named: fixture.metadataAnchorName, in: root)),
            masterKey: masterKey,
            objectName: fixture.metadataAnchorName
        )
        XCTAssertEqual(metadataObject.kind, .metadata)
        XCTAssertEqual(metadataObject.content, try hex(fixture.metadataJSONHex))
        let metadataDecoder = JSONDecoder()
        metadataDecoder.dateDecodingStrategy = .iso8601
        let metadata = try metadataDecoder.decode(V2AccessMetadata.self, from: metadataObject.content)
        XCTAssertNoThrow(try metadata.validate())
        XCTAssertEqual(metadata.accessID, try uuid(fixture.accessID))
        XCTAssertEqual(metadata.generation, fixture.metadataGeneration)
        XCTAssertNil(metadata.fixedCapacity)
        XCTAssertEqual(
            try encoder([.sortedKeys], dates: true).encode(metadata),
            metadataObject.content
        )

        let secret = try hex(vectors.recoveryKey.secretHex)
        let recoveryObject = try codec.open(
            try Data(contentsOf: V2StorageLayout.objectURL(named: fixture.recoveryAnchorName, in: root)),
            masterKey: secret,
            objectName: fixture.recoveryAnchorName
        )
        XCTAssertEqual(recoveryObject.kind, .recovery)
        XCTAssertEqual(recoveryObject.content, try hex(fixture.recoveryPayloadJSONHex))
        let payload = try JSONDecoder().decode(V2RecoveryAnchorPayload.self, from: recoveryObject.content)
        XCTAssertEqual(payload.formatVersion, V2RecoveryAnchorPayload.formatVersion)
        XCTAssertEqual(payload.vaultID, try uuid(fixture.vaultID))
        XCTAssertEqual(payload.accessID, try uuid(fixture.accessID))
        XCTAssertEqual(payload.roleRawValue, VaultAccessRole.visible.rawValue)
        XCTAssertEqual(payload.masterKey, masterKey)
        XCTAssertEqual(
            try encoder([.sortedKeys, .withoutEscapingSlashes], dates: false).encode(payload),
            recoveryObject.content
        )

        let pool = V2StorageLayout.poolURL(in: root)
        let names = try fileManager.contentsOfDirectory(atPath: pool.path)
        XCTAssertEqual(names.count, 7)
        for name in names {
            XCTAssertTrue(V2OpaqueObjectName.isValid(name))
            let bytes = try Data(contentsOf: pool.appendingPathComponent(name))
            XCTAssertEqual(bytes.prefix(8), Data("HZOBJ003".utf8))
            XCTAssertTrue(V2DataObjectPaddingPolicy.plaintextBuckets.contains(bytes.count - 48))
        }
    }

    func testPasswordKDFAndSlotUnwrapVectors() throws {
        let vectors = try loadVectors()
        let kdf = vectors.passwordKDF
        let slot = vectors.slotUnwrap
        let parameters = KDFParameters(
            algorithm: kdf.algorithm,
            salt: try hex(kdf.saltHex),
            operationsLimit: kdf.operationsLimit,
            memoryLimit: kdf.memoryLimit
        )

        let payload = try PasswordKeyEngine().unwrapPayload(
            try hex(slot.wrappedPayloadHex),
            password: kdf.password,
            parameters: parameters
        )
        XCTAssertEqual(payload, try hex(slot.payloadHex))
        XCTAssertEqual(payload.count, 70)
        XCTAssertEqual(payload.first, 2)
        XCTAssertEqual(payload.suffix(32), try hex(slot.masterKeyHex))

        let root = try copyFixtureVault()
        defer { try? fileManager.removeItem(at: root) }
        let envelope = try V2VaultBootstrapStore().readEnvelope(at: root)
        XCTAssertEqual(envelope.accessSlots[0].wrappedPayload, try hex(slot.wrappedPayloadHex))
        XCTAssertEqual(envelope.accessSlots[0].kdf.salt, try hex(kdf.saltHex))
        let access = try DualAccessEnvelopeEngine().unlock(envelope: envelope, password: kdf.password)
        XCTAssertEqual(access.role.rawValue, slot.role)
        XCTAssertEqual(access.masterKey, try hex(slot.masterKeyHex))
    }

    func testDomainKeyVectors() throws {
        let keys = try loadVectors().domainKeys
        let input = try hex(keys.inputKeyHex)
        let deriver = DomainKeyDeriver()
        let expected: [(DomainKeyPurpose, String)] = [
            (.namespaceV2, keys.namespaceV2Hex),
            (.recoveryNamespaceV2, keys.recoveryNamespaceV2Hex),
            (.poolObjectV2, keys.poolObjectV2Hex),
            (.indexV1, keys.indexV1Hex),
            (.objectV1, keys.objectV1Hex)
        ]
        for (purpose, value) in expected {
            XCTAssertEqual(try deriver.derive(masterKey: input, purpose: purpose), try hex(value), purpose.rawValue)
        }
    }

    func testDerivedObjectNameVectors() throws {
        let vectors = try loadVectors()

        let anchor = vectors.metadataAnchor
        XCTAssertEqual(
            try V2StorageNamespaceLocator().indexObjectName(masterKey: try hex(anchor.masterKeyHex)),
            anchor.name
        )

        let recovery = vectors.recoveryKey
        XCTAssertEqual(
            try V2RecoveryNamespaceLocator().objectName(
                recoveryKeyMaterial: try hex(recovery.secretHex),
                vaultID: try uuid(recovery.vaultID)
            ),
            recovery.anchorName
        )

        for cover in vectors.coverNames {
            let namer = try V2FixedCapacityPool().coverNamer(masterKey: try hex(cover.masterKeyHex))
            XCTAssertEqual(namer(cover.bucket, cover.index), cover.name)
        }
    }

    func testRecoveryKeyEncodingVectors() throws {
        let recovery = try loadVectors().recoveryKey
        let engine = RecoveryKeyEngine()
        XCTAssertEqual(try engine.normalize(recovery.displayKey), recovery.displayKey)
        XCTAssertEqual(try engine.keyMaterial(from: recovery.displayKey), try hex(recovery.secretHex))
        for input in recovery.acceptedInputs {
            XCTAssertEqual(try engine.normalize(input), recovery.displayKey)
            XCTAssertEqual(try engine.keyMaterial(from: input), try hex(recovery.secretHex))
        }
        for input in recovery.rejectedInputs {
            XCTAssertThrowsError(try engine.normalize(input))
        }
    }

    func testPoolObjectAndManifestVectors() throws {
        let vectors = try loadVectors()

        let object = vectors.poolObject
        let envelope = try hex(object.envelopeHex)
        XCTAssertEqual(envelope.count, object.paddedPlaintextByteCount + 48)
        let codec = V2PoolObjectCodec()
        let opened = try codec.open(
            envelope,
            masterKey: try hex(object.keyMaterialHex),
            objectName: object.objectName
        )
        XCTAssertEqual(opened.kind.rawValue, object.kind)
        XCTAssertEqual(opened.content, try hex(object.contentHex))
        XCTAssertThrowsError(
            try codec.open(envelope, masterKey: try hex(object.keyMaterialHex), objectName: object.otherObjectName)
        ) { error in
            XCTAssertEqual(error as? V2PoolObjectCodecError, .authenticationFailed)
        }

        let vector = vectors.manifestObject
        let manifest = try V2ChunkManifestCodec().open(
            try hex(vector.envelopeHex),
            masterKey: try hex(vector.keyMaterialHex),
            objectName: vector.objectName
        )
        XCTAssertEqual(manifest.formatVersion, 1)
        XCTAssertEqual(manifest.fileID, try uuid(vector.fileID))
        XCTAssertEqual(manifest.logicalByteCount, vector.logicalByteCount)
        XCTAssertEqual(manifest.sha256Digest, try hex(vector.sha256DigestHex))
        XCTAssertEqual(manifest.chunks.map(\.opaqueObjectName), vector.chunks.map(\.opaqueObjectName))
        XCTAssertEqual(manifest.chunks.map(\.logicalByteCount), vector.chunks.map(\.logicalByteCount))
        let content = try codec.open(
            try hex(vector.envelopeHex),
            masterKey: try hex(vector.keyMaterialHex),
            objectName: vector.objectName
        )
        XCTAssertEqual(content.kind, .manifest)
        XCTAssertEqual(content.content, try hex(vector.contentJSONHex))
        XCTAssertEqual(try V2ChunkManifestCodec().encodeContent(manifest), content.content)
    }

    func testPaddingAndFixedCapacityPlanVectors() throws {
        let vectors = try loadVectors()
        for target in vectors.dataPaddingTargets {
            XCTAssertEqual(
                try V2DataObjectPaddingPolicy.targetPlaintextByteCount(forContentByteCount: target.contentByteCount),
                target.plaintextByteCount
            )
        }
        for target in vectors.metadataPaddingTargets {
            XCTAssertEqual(
                try V2AccessMetadataPaddingPolicy.targetPlaintextByteCount(
                    forEncodedMetadataByteCount: target.encodedByteCount
                ),
                target.plaintextByteCount
            )
        }
        for expected in vectors.fixedCapacityPlans {
            let plan = try V2FixedCapacityPlan(capacityBytes: expected.capacityBytes)
            XCTAssertEqual(plan.slots.map(\.plaintextByteCount), expected.slots.map(\.plaintextByteCount))
            XCTAssertEqual(plan.slots.map(\.count), expected.slots.map(\.count))
        }
    }

    func testFrozenConstants() {
        XCTAssertEqual(VaultLayout.headerName, "vault.hanzala")
        XCTAssertEqual(VaultLayout.objectsDirectoryName, "objects")
        XCTAssertEqual(DualAccessEnvelopeV2.formatVersion, 2)
        XCTAssertEqual(DualAccessEnvelopeV2.fixedSlotCount, 2)
        XCTAssertEqual(V2VaultBootstrapStore.maximumEnvelopeByteCount, 1024 * 1024)
        XCTAssertEqual(VaultAccessRole.visible.rawValue, 1)
        XCTAssertEqual(VaultAccessRole.concealed.rawValue, 2)
        XCTAssertEqual(DomainKeyPurpose.indexV1.rawValue, "hanzala/index/v1")
        XCTAssertEqual(DomainKeyPurpose.objectV1.rawValue, "hanzala/object/v1")
        XCTAssertEqual(DomainKeyPurpose.namespaceV2.rawValue, "hanzala/namespace/v2")
        XCTAssertEqual(DomainKeyPurpose.recoveryNamespaceV2.rawValue, "hanzala/recovery-namespace/v2")
        XCTAssertEqual(DomainKeyPurpose.poolObjectV2.rawValue, "hanzala/pool-object/v2")
        XCTAssertEqual(V2PoolObjectKind.metadata.rawValue, 1)
        XCTAssertEqual(V2PoolObjectKind.data.rawValue, 2)
        XCTAssertEqual(V2PoolObjectKind.padding.rawValue, 3)
        XCTAssertEqual(V2PoolObjectKind.manifest.rawValue, 4)
        XCTAssertEqual(V2PoolObjectKind.recovery.rawValue, 5)
        XCTAssertEqual(V2PoolObjectCodec.maximumPlaintextByteCount, 16 * 1024 * 1024)
        XCTAssertEqual(V2PoolObjectCodec.encryptedPayloadHeaderByteCount, 10)
        XCTAssertEqual(V2PoolObjectCodec.maximumEnvelopeByteCount, 16 * 1024 * 1024 + 48)
        XCTAssertEqual(V2OpaqueObjectName.byteCount, 32)
        XCTAssertEqual(V2OpaqueObjectName.encodedLength, 64)
        XCTAssertEqual(
            V2DataObjectPaddingPolicy.plaintextBuckets,
            [4096, 16384, 65536, 262_144, 1_048_576, 4_194_304, 16_777_216]
        )
        XCTAssertEqual(V2AccessMetadataPaddingPolicy.plaintextBuckets, V2DataObjectPaddingPolicy.plaintextBuckets)
        XCTAssertEqual(V2DataObjectPaddingPolicy.maximumLogicalContentByteCount, 16_777_206)
        XCTAssertEqual(V2AccessMetadata.formatVersion, 1)
        XCTAssertEqual(V2RecoveryAnchorPayload.formatVersion, 1)
        XCTAssertEqual(V2RecoveryAnchorStore.paddedPlaintextByteCount, 4096)
        XCTAssertEqual(V2ChunkManifest.formatVersion, 1)
        XCTAssertEqual(V2ChunkManifest.maximumChunkCount, 16_384)
        XCTAssertEqual(V2ChunkManifest.chunkPaddedPlaintextByteCount, 4 * 1024 * 1024)
        XCTAssertEqual(V2ChunkManifest.maximumLogicalChunkByteCount, 4 * 1024 * 1024 - 10)
        XCTAssertEqual(V2FixedCapacityPlan.metadataPaddedPlaintextByteCount, 1024 * 1024)
        XCTAssertEqual(V2FixedCapacityPlan.minimumCapacityBytes, 64 * 1024 * 1024)
        XCTAssertEqual(V2FixedCapacityPlan.maximumCapacityBytes, 256 * 1024 * 1024 * 1024)
    }

    // MARK: - Fixture checks

    private func assertFixtureContents(
        _ fixture: Vectors.FixtureVault,
        session: V2VaultSession,
        sessions: V2VaultSessionStore
    ) throws {
        XCTAssertEqual(session.role.rawValue, fixture.role)
        XCTAssertEqual(session.vaultID, try uuid(fixture.vaultID))
        XCTAssertEqual(session.accessID, try uuid(fixture.accessID))

        let entries = try sessions.listEntries(in: session)
        XCTAssertEqual(entries.map(\.originalName), fixture.files.map(\.name))
        XCTAssertEqual(entries.count, fixture.files.count)
        for (entry, file) in zip(entries, fixture.files) {
            let content = try hex(file.contentHex)
            XCTAssertEqual(entry.id, try uuid(file.id))
            XCTAssertEqual(entry.opaqueObjectName, file.objectName)
            XCTAssertTrue(entry.auxiliaryObjectNames.isEmpty)
            XCTAssertEqual(entry.logicalByteCount, UInt64(file.byteCount))
            XCTAssertEqual(entry.createdAt, try XCTUnwrap(ISO8601DateFormatter().date(from: file.createdAt)))
            XCTAssertEqual(content.count, file.byteCount)
            XCTAssertEqual(try sessions.readEntry(id: entry.id, in: session).data, content)
            XCTAssertEqual(
                try sessions.readEntryRange(id: entry.id, offset: 1, length: 16, in: session),
                content.subdata(in: 1..<min(17, content.count))
            )
            XCTAssertNoThrow(try sessions.verifyEntryIntegrity(id: entry.id, in: session))
        }
    }

    /// Opening must never write: the copy still equals the committed fixture.
    private func assertUnchanged(_ root: URL) throws {
        let original = try fixtureDirectory().appendingPathComponent("vault", isDirectory: true)
        let expected = try fileManager.subpathsOfDirectory(atPath: original.path).sorted()
        XCTAssertEqual(try fileManager.subpathsOfDirectory(atPath: root.path).sorted(), expected)
        for path in expected {
            var isDirectory: ObjCBool = false
            _ = fileManager.fileExists(atPath: original.appendingPathComponent(path).path, isDirectory: &isDirectory)
            if isDirectory.boolValue { continue }
            XCTAssertEqual(
                try Data(contentsOf: root.appendingPathComponent(path)),
                try Data(contentsOf: original.appendingPathComponent(path)),
                path
            )
        }
    }

    // MARK: - Helpers

    private func fixtureDirectory() throws -> URL {
        let fixtures = try XCTUnwrap(Bundle.module.url(forResource: "Fixtures", withExtension: nil))
        return fixtures.appendingPathComponent("v2-format-vectors", isDirectory: true)
    }

    private func loadVectors() throws -> Vectors {
        let url = try fixtureDirectory().appendingPathComponent("vectors.json")
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }

    private func copyFixtureVault() throws -> URL {
        let source = try fixtureDirectory().appendingPathComponent("vault", isDirectory: true)
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-format-vectors-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.copyItem(at: source, to: root)
        return root
    }

    private func encoder(_ formatting: JSONEncoder.OutputFormatting, dates: Bool) -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = formatting
        if dates {
            encoder.dateEncodingStrategy = .iso8601
        }
        return encoder
    }

    private func hex(_ string: String) throws -> Data {
        let characters = Array(string.utf8)
        XCTAssertEqual(characters.count % 2, 0, "odd hex length")
        var bytes: [UInt8] = []
        bytes.reserveCapacity(characters.count / 2)
        var index = 0
        while index + 1 < characters.count {
            let pair = String(decoding: characters[index...index + 1], as: UTF8.self)
            bytes.append(try XCTUnwrap(UInt8(pair, radix: 16), "bad hex"))
            index += 2
        }
        return Data(bytes)
    }

    private func uuid(_ string: String) throws -> UUID {
        try XCTUnwrap(UUID(uuidString: string), "bad UUID \(string)")
    }
}

/// Mirrors Tests/HanzalaomatorCoreTests/Fixtures/v2-format-vectors/vectors.json.
private struct Vectors: Decodable {
    struct FixtureVault: Decodable {
        struct File: Decodable {
            let name: String
            let id: String
            let objectName: String
            let createdAt: String
            let byteCount: Int
            let contentHex: String
            let sha256Hex: String
        }

        let directory: String
        let password: String
        let recoveryKey: String
        let vaultID: String
        let accessID: String
        let role: UInt8
        let masterKeyHex: String
        let metadataAnchorName: String
        let recoveryAnchorName: String
        let metadataGeneration: UInt64
        let metadataJSONHex: String
        let recoveryPayloadJSONHex: String
        let files: [File]
    }

    struct PasswordKDF: Decodable {
        let password: String
        let algorithm: String
        let saltHex: String
        let operationsLimit: UInt64
        let memoryLimit: UInt64
        let keyHex: String
    }

    struct SlotUnwrap: Decodable {
        let wrappedPayloadHex: String
        let payloadHex: String
        let role: UInt8
        let vaultID: String
        let masterKeyHex: String
    }

    struct DomainKeys: Decodable {
        let inputKeyHex: String
        let namespaceV2Hex: String
        let recoveryNamespaceV2Hex: String
        let poolObjectV2Hex: String
        let indexV1Hex: String
        let objectV1Hex: String
    }

    struct RecoveryKey: Decodable {
        let displayKey: String
        let acceptedInputs: [String]
        let rejectedInputs: [String]
        let secretHex: String
        let vaultID: String
        let recoveryNamespaceKeyHex: String
        let anchorName: String
    }

    struct MetadataAnchor: Decodable {
        let masterKeyHex: String
        let name: String
    }

    struct PoolObject: Decodable {
        let keyMaterialHex: String
        let objectName: String
        let kind: UInt8
        let contentHex: String
        let paddedPlaintextByteCount: Int
        let envelopeHex: String
        let otherObjectName: String
    }

    struct ManifestObject: Decodable {
        struct Chunk: Decodable {
            let opaqueObjectName: String
            let logicalByteCount: UInt64
        }

        let keyMaterialHex: String
        let objectName: String
        let fileID: String
        let logicalByteCount: UInt64
        let chunks: [Chunk]
        let sha256DigestHex: String
        let contentJSONHex: String
        let envelopeHex: String
    }

    struct CoverName: Decodable {
        let masterKeyHex: String
        let bucket: Int
        let index: Int
        let name: String
    }

    struct DataPadding: Decodable {
        let contentByteCount: Int
        let plaintextByteCount: Int
    }

    struct MetadataPadding: Decodable {
        let encodedByteCount: Int
        let plaintextByteCount: Int
    }

    struct Plan: Decodable {
        struct Slots: Decodable {
            let plaintextByteCount: Int
            let count: Int
        }

        let capacityBytes: UInt64
        let slots: [Slots]
    }

    let fixtureVault: FixtureVault
    let passwordKDF: PasswordKDF
    let slotUnwrap: SlotUnwrap
    let domainKeys: DomainKeys
    let recoveryKey: RecoveryKey
    let metadataAnchor: MetadataAnchor
    let poolObject: PoolObject
    let manifestObject: ManifestObject
    let coverNames: [CoverName]
    let dataPaddingTargets: [DataPadding]
    let metadataPaddingTargets: [MetadataPadding]
    let fixedCapacityPlans: [Plan]
}
