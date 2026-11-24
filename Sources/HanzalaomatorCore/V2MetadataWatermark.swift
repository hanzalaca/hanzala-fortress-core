import CryptoKit
import Foundation
#if canImport(Security)
import Security
#endif

/// Device-local record of the newest metadata generation this device has
/// accepted for one v2 access path.
///
/// The vault folder can be rewritten by anyone who can write to it (a shared
/// iCloud folder, an external SSD). An older but authentic metadata anchor
/// still decrypts, so without a local record the app would accept it as
/// current: deleted files would come back and newer files would vanish with no
/// warning. The watermark lets the session store notice that and stop.
///
/// Keys are opaque: they are derived from the access path's master key under a
/// purpose of their own, so a key cannot be matched to the vault folder's
/// object names, and it says nothing about which access path it belongs to.
public protocol V2MetadataWatermarkStore: AnyObject {
    func generation(forKey key: String) throws -> UInt64?
    func setGeneration(_ generation: UInt64, forKey key: String) throws
}

public enum V2MetadataWatermarkStoreError: Error, Equatable, Sendable {
    case unavailable(Int32)
    case malformedRecord
}

/// For tests and for callers that keep the watermark for one process only.
public final class V2InMemoryMetadataWatermarkStore: V2MetadataWatermarkStore {
    private let lock = NSLock()
    private var values: [String: UInt64] = [:]

    public init() {}

    public func generation(forKey key: String) throws -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    public func setGeneration(_ generation: UInt64, forKey key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values[key] = generation
    }
}

#if canImport(Security)
/// Keeps the watermark in this device's Keychain. Never synced to iCloud and
/// never restored to another device, so a copy of the vault folder alone
/// cannot carry or reset it.
public final class V2KeychainMetadataWatermarkStore: V2MetadataWatermarkStore {
    public static let defaultService = "ca.hanzala.fortress.metadata-watermark"

    private let service: String

    public init(service: String = V2KeychainMetadataWatermarkStore.defaultService) {
        self.service = service
    }

    public func generation(forKey key: String) throws -> UInt64? {
        var query = baseQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw V2MetadataWatermarkStoreError.unavailable(status)
        }
        guard let data = result as? Data, data.count == 8 else {
            throw V2MetadataWatermarkStoreError.malformedRecord
        }
        return data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    public func setGeneration(_ generation: UInt64, forKey key: String) throws {
        var bigEndian = generation.bigEndian
        let data = withUnsafeBytes(of: &bigEndian) { Data($0) }

        let update = [kSecValueData as String: data]
        let status = SecItemUpdate(baseQuery(key) as CFDictionary, update as CFDictionary)
        if status == errSecSuccess {
            return
        }
        guard status == errSecItemNotFound else {
            throw V2MetadataWatermarkStoreError.unavailable(status)
        }

        var add = baseQuery(key)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw V2MetadataWatermarkStoreError.unavailable(addStatus)
        }
    }

    private func baseQuery(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: false
        ]
    }
}

public extension V2VaultSessionLifecycle {
    /// The lifecycle the apps use: rollback detection backed by this device's
    /// Keychain.
    static func withDeviceWatermark() -> V2VaultSessionLifecycle {
        V2VaultSessionLifecycle(
            sessionStore: V2VaultSessionStore(
                metadataWatermarkStore: V2KeychainMetadataWatermarkStore()
            )
        )
    }
}
#endif

/// Compares an authenticated metadata generation with the device watermark.
///
/// Fails closed only on an actual rollback. If the watermark store itself
/// cannot be read or written (for example the Keychain is unavailable), the
/// vault still opens: the owner's files are never locked away because of a
/// device problem, and that failure gives an attacker nothing they control.
final class V2MetadataWatermarkGuard {
    private static let label = Data("HZ-METADATA-WATERMARK-1".utf8)

    private let store: V2MetadataWatermarkStore
    private let keyDeriver: DomainKeyDeriver
    private let lock = NSLock()
    private var cache: [String: UInt64] = [:]

    init(store: V2MetadataWatermarkStore, keyDeriver: DomainKeyDeriver = DomainKeyDeriver()) {
        self.store = store
        self.keyDeriver = keyDeriver
    }

    func key(masterKey: Data, vaultID: UUID, accessID: UUID) throws -> String {
        let derived = try keyDeriver.derive(masterKey: masterKey, purpose: .metadataWatermarkV2)
        var message = Self.label
        message.append(Self.bytes(of: vaultID))
        message.append(Self.bytes(of: accessID))
        let code = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: derived)
        )
        return Data(code).map { String(format: "%02x", $0) }.joined()
    }

    /// Throws `V2VaultSessionError.olderCopyDetected` when `generation` is
    /// below the newest one this device accepted; otherwise raises the
    /// watermark to `generation`.
    func check(_ generation: UInt64, key: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let recorded: UInt64?
        if let cached = cache[key] {
            recorded = cached
        } else {
            recorded = try? store.generation(forKey: key)
        }

        if let recorded, generation < recorded {
            cache[key] = recorded
            throw V2VaultSessionError.olderCopyDetected
        }
        if recorded.map({ generation > $0 }) ?? true {
            try? store.setGeneration(generation, forKey: key)
        }
        cache[key] = max(generation, recorded ?? 0)
    }

    /// The owner chose to open this copy anyway: it becomes the reference.
    func accept(_ generation: UInt64, key: String) {
        lock.lock()
        defer { lock.unlock() }
        try? store.setGeneration(generation, forKey: key)
        cache[key] = generation
    }

    private static func bytes(of uuid: UUID) -> Data {
        var value = uuid.uuid
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
