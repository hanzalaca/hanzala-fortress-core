import XCTest
@testable import HanzalaomatorCore

final class PasswordKeyEngineTests: XCTestCase {
    func testWrapAndUnwrapMasterKey() throws {
        let engine = PasswordKeyEngine()
        let params = try engine.makeParameters(operationsLimit: 2, memoryLimit: 64 * 1024 * 1024)
        let masterKey = engine.generateMasterKey()

        let wrapped = try engine.wrapMasterKey(masterKey, password: "correct horse battery staple", parameters: params)
        let unwrapped = try engine.unwrapMasterKey(wrapped, password: "correct horse battery staple", parameters: params)

        XCTAssertEqual(unwrapped, masterKey)
        XCTAssertNotEqual(wrapped, masterKey)
    }

    func testWrongPasswordIsRejected() throws {
        let engine = PasswordKeyEngine()
        let params = try engine.makeParameters(operationsLimit: 2, memoryLimit: 64 * 1024 * 1024)
        let masterKey = engine.generateMasterKey()
        let wrapped = try engine.wrapMasterKey(masterKey, password: "right-password", parameters: params)

        XCTAssertThrowsError(try engine.unwrapMasterKey(wrapped, password: "wrong-password", parameters: params)) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidPasswordOrCorruptedHeader)
        }
    }

    func testTamperedWrappedMasterKeyIsRejected() throws {
        let engine = PasswordKeyEngine()
        let params = try engine.makeParameters(operationsLimit: 2, memoryLimit: 64 * 1024 * 1024)
        let masterKey = engine.generateMasterKey()
        var wrapped = try engine.wrapMasterKey(masterKey, password: "test-password", parameters: params)
        wrapped[wrapped.index(before: wrapped.endIndex)] ^= 0x01

        XCTAssertThrowsError(try engine.unwrapMasterKey(wrapped, password: "test-password", parameters: params)) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidPasswordOrCorruptedHeader)
        }
    }

    func testVaultHeaderRoundTripAndUnlock() throws {
        let engine = PasswordKeyEngine()
        let params = try engine.makeParameters(operationsLimit: 2, memoryLimit: 64 * 1024 * 1024)
        let masterKey = engine.generateMasterKey()
        let wrapped = try engine.wrapMasterKey(masterKey, password: "vault-password", parameters: params)
        let header = VaultHeader(
            vaultID: UUID(),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            kdf: params,
            wrappedMasterKey: wrapped
        )

        let encoded = try JSONEncoder().encode(header)
        let decoded = try JSONDecoder().decode(VaultHeader.self, from: encoded)
        let unlocked = try engine.unwrapMasterKey(decoded.wrappedMasterKey, password: "vault-password", parameters: decoded.kdf)

        XCTAssertEqual(unlocked, masterKey)
        XCTAssertEqual(decoded.kdf.algorithm, "argon2id13")
        XCTAssertEqual(decoded.kdf.operationsLimit, 2)
        XCTAssertEqual(decoded.kdf.memoryLimit, 64 * 1024 * 1024)
    }

    func testMakeParametersRejectsExcessiveResourceLimits() {
        let engine = PasswordKeyEngine()

        XCTAssertThrowsError(
            try engine.makeParameters(
                operationsLimit: Int.max,
                memoryLimit: 64 * 1024 * 1024
            )
        ) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidKDFParameters)
        }

        XCTAssertThrowsError(
            try engine.makeParameters(
                operationsLimit: 2,
                memoryLimit: Int.max
            )
        ) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidKDFParameters)
        }
    }

    func testSerializedKDFParametersCannotRequestUnboundedResources() throws {
        let engine = PasswordKeyEngine()
        let safe = try engine.makeParameters(
            operationsLimit: 2,
            memoryLimit: 64 * 1024 * 1024
        )

        let excessiveOperations = KDFParameters(
            algorithm: "argon2id13",
            salt: safe.salt,
            operationsLimit: UInt64(Int.max),
            memoryLimit: safe.memoryLimit
        )
        XCTAssertThrowsError(
            try engine.wrapPayload(
                Data("payload".utf8),
                password: "password",
                parameters: excessiveOperations
            )
        ) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidKDFParameters)
        }

        let excessiveMemory = KDFParameters(
            algorithm: "argon2id13",
            salt: safe.salt,
            operationsLimit: safe.operationsLimit,
            memoryLimit: UInt64(Int.max)
        )
        XCTAssertThrowsError(
            try engine.wrapPayload(
                Data("payload".utf8),
                password: "password",
                parameters: excessiveMemory
            )
        ) { error in
            XCTAssertEqual(error as? VaultKeyError, .invalidKDFParameters)
        }
    }
}
