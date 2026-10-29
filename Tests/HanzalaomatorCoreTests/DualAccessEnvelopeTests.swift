import XCTest
@testable import HanzalaomatorCore

final class DualAccessEnvelopeTests: XCTestCase {
    private func makeEngine() -> DualAccessEnvelopeEngine {
        let keyEngine = PasswordKeyEngine()
        return DualAccessEnvelopeEngine(
            keyEngine: keyEngine,
            makeParameters: {
                try keyEngine.makeParameters(
                    operationsLimit: 2,
                    memoryLimit: 32 * 1024 * 1024
                )
            }
        )
    }

    func testDualAccessPasswordsUnlockIndependentMasterKeys() throws {
        let engine = makeEngine()
        let created = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password"
        )

        let visible = try engine.unlock(
            envelope: created.envelope,
            password: "ordinary-password"
        )
        let concealed = try engine.unlock(
            envelope: created.envelope,
            password: "source-protection-password"
        )

        XCTAssertEqual(visible.role, .visible)
        XCTAssertEqual(visible.masterKey, created.visibleMasterKey)
        XCTAssertEqual(concealed.role, .concealed)
        XCTAssertEqual(concealed.masterKey, created.concealedMasterKey)
        XCTAssertNotEqual(visible.masterKey, concealed.masterKey)
    }

    func testEveryV2EnvelopeHasSameFixedPublicSlotCount() throws {
        let engine = makeEngine()
        let visibleOnly = try engine.createVisibleOnly(password: "ordinary-password")
        let dual = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "different-password"
        )

        XCTAssertEqual(
            visibleOnly.envelope.accessSlots.count,
            DualAccessEnvelopeV2.fixedSlotCount
        )
        XCTAssertEqual(
            dual.envelope.accessSlots.count,
            DualAccessEnvelopeV2.fixedSlotCount
        )
        XCTAssertEqual(
            visibleOnly.envelope.accessSlots.map(\.wrappedPayload.count),
            dual.envelope.accessSlots.map(\.wrappedPayload.count)
        )
        XCTAssertNil(visibleOnly.concealedMasterKey)
        XCTAssertNotNil(dual.concealedMasterKey)
    }

    func testPublicEnvelopeDoesNotSerializeRoleOrEnabledState() throws {
        let engine = makeEngine()
        let created = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "different-password"
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(created.envelope)
        // Only field names and short text values are checked: random base64
        // ciphertext can contain any short word by chance.
        let words = Self.namesAndShortStrings(in: try JSONSerialization.jsonObject(with: encoded))
            .map { $0.lowercased() }
            .joined(separator: " ")

        XCTAssertFalse(words.contains("hidden"))
        XCTAssertFalse(words.contains("concealed"))
        XCTAssertFalse(words.contains("visible"))
        XCTAssertFalse(words.contains("role"))
        XCTAssertFalse(words.contains("enabled"))
        XCTAssertTrue(words.contains("accessslots"))
    }

    private static func namesAndShortStrings(in value: Any) -> [String] {
        switch value {
        case let dictionary as [String: Any]:
            return dictionary.flatMap { [$0.key] + namesAndShortStrings(in: $0.value) }
        case let array as [Any]:
            return array.flatMap { namesAndShortStrings(in: $0) }
        case let string as String where string.count <= 32:
            return [string]
        default:
            return []
        }
    }

    func testAccessSlotsUseIndependentKDFSalts() throws {
        let engine = makeEngine()
        let created = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "different-password"
        )

        XCTAssertEqual(created.envelope.accessSlots.count, 2)
        XCTAssertNotEqual(
            created.envelope.accessSlots[0].kdf.salt,
            created.envelope.accessSlots[1].kdf.salt
        )
    }

    func testSamePasswordForBothAccessPathsIsRejected() {
        let engine = makeEngine()

        XCTAssertThrowsError(
            try engine.createDualAccess(
                visiblePassword: "same-password",
                concealedPassword: "same-password"
            )
        ) { error in
            XCTAssertEqual(error as? HiddenVaultPolicyError, .passwordsMustDiffer)
        }
    }

    func testWrongPasswordIsIndistinguishableFromUnreadableEnvelope() throws {
        let engine = makeEngine()
        let created = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "different-password"
        )

        XCTAssertThrowsError(
            try engine.unlock(
                envelope: created.envelope,
                password: "not-a-valid-password"
            )
        ) { error in
            XCTAssertEqual(
                error as? DualAccessEnvelopeError,
                .invalidPasswordOrCorruptedEnvelope
            )
        }
    }

    func testPublicVaultIDTamperingInvalidatesBothPasswordPaths() throws {
        let engine = makeEngine()
        let originalVaultID = UUID(uuidString: "81000000-0000-0000-0000-000000000001")!
        let tamperedVaultID = UUID(uuidString: "81000000-0000-0000-0000-000000000002")!
        let created = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "source-protection-password",
            vaultID: originalVaultID
        )

        let tampered = DualAccessEnvelopeV2(
            vaultID: tamperedVaultID,
            createdAt: created.envelope.createdAt,
            accessSlots: created.envelope.accessSlots
        )

        for password in ["ordinary-password", "source-protection-password"] {
            XCTAssertThrowsError(
                try engine.unlock(envelope: tampered, password: password)
            ) { error in
                XCTAssertEqual(
                    error as? DualAccessEnvelopeError,
                    .invalidPasswordOrCorruptedEnvelope
                )
            }
        }

        let intactVisible = try engine.unlock(
            envelope: created.envelope,
            password: "ordinary-password"
        )
        XCTAssertEqual(intactVisible.masterKey, created.visibleMasterKey)
    }

    func testDamageToOtherSlotDoesNotBlockValidAccessPath() throws {
        let engine = makeEngine()
        let created = try engine.createDualAccess(
            visiblePassword: "ordinary-password",
            concealedPassword: "different-password"
        )

        var damagedPayload = created.envelope.accessSlots[1].wrappedPayload
        damagedPayload[damagedPayload.index(before: damagedPayload.endIndex)] ^= 0x01

        let damagedSlot = VaultAccessSlot(
            kdf: created.envelope.accessSlots[1].kdf,
            wrappedPayload: damagedPayload
        )
        let damagedEnvelope = DualAccessEnvelopeV2(
            vaultID: created.envelope.vaultID,
            createdAt: created.envelope.createdAt,
            accessSlots: [created.envelope.accessSlots[0], damagedSlot]
        )

        let visible = try engine.unlock(
            envelope: damagedEnvelope,
            password: "ordinary-password"
        )
        XCTAssertEqual(visible.role, .visible)
        XCTAssertEqual(visible.masterKey, created.visibleMasterKey)
    }

    func testEnvelopeRejectsUnexpectedSlotCount() throws {
        let engine = makeEngine()
        let created = try engine.createVisibleOnly(password: "ordinary-password")
        let malformed = DualAccessEnvelopeV2(
            vaultID: created.envelope.vaultID,
            accessSlots: [created.envelope.accessSlots[0]]
        )

        XCTAssertThrowsError(
            try engine.unlock(envelope: malformed, password: "ordinary-password")
        ) { error in
            XCTAssertEqual(error as? DualAccessEnvelopeError, .invalidSlotCount)
        }
    }
}
