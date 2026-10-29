import XCTest
@testable import HanzalaomatorCore

final class V2RecoveryAnchorStoreTests: XCTestCase {
    private let fileManager = FileManager.default

    func testRecoveryKeyMaterialRoundTripsCanonicalHZRKSecret() throws {
        let engine = RecoveryKeyEngine()
        let key = engine.generateRecoveryKey()
        let material = try engine.keyMaterial(from: key)

        XCTAssertEqual(material.count, 32)
        XCTAssertEqual(try engine.normalize(key), key)
        XCTAssertEqual(
            try engine.keyMaterial(from: key.lowercased()),
            material
        )
    }

    func testRecoveryAnchorRoundTripReturnsBoundAccessIdentity() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let store = V2RecoveryAnchorStore()
        let credential = store.generateCredential()
        let vaultID = UUID(uuidString: "91000000-0000-0000-0000-000000000001")!
        let accessID = UUID(uuidString: "91000000-0000-0000-0000-000000000002")!
        let masterKey = Data(repeating: 0x91, count: 32)
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)

        let name = try store.createAnchor(
            credential: credential,
            access: UnlockedVaultAccess(role: .visible, masterKey: masterKey),
            accessID: accessID,
            vaultID: vaultID,
            budget: budget,
            in: root
        )

        XCTAssertTrue(V2OpaqueObjectName.isValid(name))
        let recovered = try store.recover(
            recoveryKey: credential.displayKey,
            vaultID: vaultID,
            in: root
        )
        XCTAssertEqual(recovered.access.role, .visible)
        XCTAssertEqual(recovered.access.masterKey, masterKey)
        XCTAssertEqual(recovered.accessID, accessID)

        let file = V2StorageLayout.objectURL(named: name, in: root)
        let bytes = try Data(contentsOf: file)
        XCTAssertEqual(Data(bytes.prefix(8)), Data("HZOBJ003".utf8))
        XCTAssertEqual(
            bytes.count,
            Int(try V2PhysicalCapacityGuard.sealedEnvelopeByteCount(
                paddedPlaintextByteCount: V2RecoveryAnchorStore.paddedPlaintextByteCount
            ))
        )
    }

    func testRecoveryNamespaceIsDeterministicAndVaultBound() throws {
        let engine = RecoveryKeyEngine()
        let key = engine.generateRecoveryKey()
        let material = try engine.keyMaterial(from: key)
        let locator = V2RecoveryNamespaceLocator()
        let vaultA = UUID(uuidString: "92000000-0000-0000-0000-000000000001")!
        let vaultB = UUID(uuidString: "92000000-0000-0000-0000-000000000002")!

        let first = try locator.objectName(recoveryKeyMaterial: material, vaultID: vaultA)
        let repeated = try locator.objectName(recoveryKeyMaterial: material, vaultID: vaultA)
        let otherVault = try locator.objectName(recoveryKeyMaterial: material, vaultID: vaultB)

        XCTAssertEqual(first, repeated)
        XCTAssertNotEqual(first, otherVault)
        XCTAssertTrue(V2OpaqueObjectName.isValid(first))
        XCTAssertTrue(V2OpaqueObjectName.isValid(otherVault))
    }

    func testRecoveryCiphertextCannotBeReboundToAnotherVaultAnchorName() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }

        let store = V2RecoveryAnchorStore()
        let credential = store.generateCredential()
        let vaultA = UUID(uuidString: "93000000-0000-0000-0000-000000000001")!
        let vaultB = UUID(uuidString: "93000000-0000-0000-0000-000000000002")!
        let budget = try V2StorageBudget(totalBytes: 100_000, reserveBytes: 20_000)
        let sourceName = try store.createAnchor(
            credential: credential,
            access: UnlockedVaultAccess(
                role: .concealed,
                masterKey: Data(repeating: 0x93, count: 32)
            ),
            accessID: UUID(uuidString: "93000000-0000-0000-0000-000000000003")!,
            vaultID: vaultA,
            budget: budget,
            in: root
        )

        let destinationName = try V2RecoveryNamespaceLocator().objectName(
            recoveryKeyMaterial: credential.keyMaterial,
            vaultID: vaultB
        )
        let source = V2StorageLayout.objectURL(named: sourceName, in: root)
        let destination = V2StorageLayout.objectURL(named: destinationName, in: root)
        try Data(contentsOf: source).write(to: destination)

        XCTAssertThrowsError(
            try store.recover(
                recoveryKey: credential.displayKey,
                vaultID: vaultB,
                in: root
            )
        ) { error in
            XCTAssertEqual(
                error as? V2RecoveryAnchorError,
                .invalidRecoveryKeyOrCorruptedAnchor
            )
        }
    }

    func testMissingMalformedAndWrongRecoveryCandidatesShareFailure() throws {
        let root = try makeRoot()
        defer { try? fileManager.removeItem(at: root) }
        let store = V2RecoveryAnchorStore()
        let vaultID = UUID(uuidString: "94000000-0000-0000-0000-000000000001")!

        for candidate in [
            "not-a-recovery-key",
            RecoveryKeyEngine().generateRecoveryKey()
        ] {
            XCTAssertThrowsError(
                try store.recover(
                    recoveryKey: candidate,
                    vaultID: vaultID,
                    in: root
                )
            ) { error in
                XCTAssertEqual(
                    error as? V2RecoveryAnchorError,
                    .invalidRecoveryKeyOrCorruptedAnchor
                )
            }
        }
    }

    private func makeRoot() throws -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "hanzala-v2-recovery-anchor-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try fileManager.createDirectory(
            at: V2StorageLayout.poolURL(in: url),
            withIntermediateDirectories: false
        )
        return url
    }
}
