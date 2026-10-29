import XCTest
@testable import HanzalaomatorCore

final class RecoveryKeyTests: XCTestCase {
    func testRecoveryKeyFormatAndNormalization() throws {
        let engine = RecoveryKeyEngine()
        let key = engine.generateRecoveryKey()

        XCTAssertTrue(key.hasPrefix("HZRK-"))
        XCTAssertEqual(key.split(separator: "-").count, 17)
        XCTAssertEqual(try engine.normalize(key.lowercased()), key)
        XCTAssertEqual(try engine.normalize(key.replacingOccurrences(of: "-", with: " ")), key)
        XCTAssertThrowsError(try engine.normalize("HZRK-not-a-real-key")) { error in
            XCTAssertEqual(error as? RecoveryKeyError, .invalidFormat)
        }
    }

    func testRecoveryUnlockAndPasswordRewrapUseSameMasterKey() throws {
        let manager = VaultKeyManager()
        let created = try manager.createHeaderWithRecovery(password: "old-password")

        let passwordUnlocked = try manager.unlock(header: created.header, password: "old-password")
        let recoveryUnlocked = try manager.unlockWithRecovery(header: created.header, recoveryKey: created.recoveryKey)
        XCTAssertEqual(passwordUnlocked, created.masterKey)
        XCTAssertEqual(recoveryUnlocked, created.masterKey)

        let changedHeader = try manager.rewrapPassword(
            header: created.header,
            masterKey: created.masterKey,
            newPassword: "new-password"
        )

        XCTAssertThrowsError(try manager.unlock(header: changedHeader, password: "old-password"))
        XCTAssertEqual(try manager.unlock(header: changedHeader, password: "new-password"), created.masterKey)
        XCTAssertEqual(
            try manager.unlockWithRecovery(header: changedHeader, recoveryKey: created.recoveryKey),
            created.masterKey
        )
    }

    func testLegacyHeaderWithoutRecoveryStillDecodes() throws {
        struct LegacyHeader: Codable {
            let formatVersion: UInt32
            let vaultID: UUID
            let createdAt: Date
            let kdf: KDFParameters
            let wrappedMasterKey: Data
        }

        let engine = PasswordKeyEngine()
        let parameters = try engine.makeParameters(operationsLimit: 1, memoryLimit: 8 * 1024 * 1024)
        let masterKey = engine.generateMasterKey()
        let wrapped = try engine.wrapMasterKey(masterKey, password: "legacy-password", parameters: parameters)
        let legacy = LegacyHeader(
            formatVersion: 1,
            vaultID: UUID(),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            kdf: parameters,
            wrappedMasterKey: wrapped
        )

        let data = try JSONEncoder().encode(legacy)
        let decoded = try JSONDecoder().decode(VaultHeader.self, from: data)

        XCTAssertNil(decoded.recovery)
        XCTAssertEqual(try engine.unwrapMasterKey(decoded.wrappedMasterKey, password: "legacy-password", parameters: decoded.kdf), masterKey)
    }

    func testVaultPasswordChangeDoesNotRewriteEncryptedIndex() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("Hanzalaomator-RecoveryTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let store = VaultStore()
        let created = try store.createVaultWithRecovery(at: root, password: "old-password")
        let indexURL = VaultLayout.indexURL(in: root)
        let indexBefore = try Data(contentsOf: indexURL)

        let changed = try store.changePassword(for: created.vault, to: "new-password")
        let indexAfter = try Data(contentsOf: indexURL)

        XCTAssertEqual(indexAfter, indexBefore)
        XCTAssertEqual(changed.masterKey, created.vault.masterKey)
        XCTAssertThrowsError(try store.openVault(at: root, password: "old-password"))
        XCTAssertEqual(try store.openVault(at: root, password: "new-password").masterKey, created.vault.masterKey)
        XCTAssertEqual(try store.openVault(at: root, recoveryKey: created.recoveryKey).masterKey, created.vault.masterKey)
    }
}
