import Foundation

public enum HanzalaVaultStorageFormat: UInt32, Equatable, Sendable {
    case v1 = 1
    case v2 = 2
}

public enum VaultFormatDetectorError: Error, Equatable, Sendable {
    case missingHeader
    case headerIsNotRegularFile
    case headerTooLarge
    case headerReadFailed
    case malformedHeader
    case unsupportedVersion(UInt32)
}

/// Bounded, password-independent routing probe for the public `vault.hanzala`
/// envelope/header.
///
/// v1 and v2 intentionally reuse the same public header filename. The app must
/// therefore route by the explicit serialized `formatVersion`, not by trying a
/// password against one implementation and falling back to the other. Password
/// success/failure is authentication, not a storage-format detector.
///
/// On Darwin the public header is read through the same no-follow,
/// descriptor-bound primitive used by the v2 opener. A pathname swap after open
/// therefore cannot retarget the bytes used for routing. The root identity is
/// rechecked before the detected format is returned.
///
/// This probe is only a routing hint. The selected v1/v2 opener must repeat its
/// own full structural, authentication, resource-limit, and filesystem checks.
public final class VaultFormatDetector {
    public static let maximumHeaderByteCount = V2VaultBootstrapStore.maximumEnvelopeByteCount

    private struct VersionProbe: Decodable {
        let formatVersion: UInt32
    }

    private let reader: V2DescriptorBoundEnvelopeReader
    private let decoder = JSONDecoder()

    #if canImport(Darwin)
    /// Internal deterministic seam used only by routing namespace-race tests.
    var headerOpenedHook: (() -> Void)? {
        get { reader.envelopeOpenedHook }
        set { reader.envelopeOpenedHook = newValue }
    }
    #endif

    public init(fileManager: FileManager = .default) {
        self.reader = V2DescriptorBoundEnvelopeReader(
            fileManager: fileManager,
            maximumByteCount: Self.maximumHeaderByteCount
        )
    }

    public func detect(at root: URL) throws -> HanzalaVaultStorageFormat {
        let snapshot: V2DescriptorBoundEnvelopeReader.Snapshot
        do {
            snapshot = try reader.read(at: root)
        } catch V2DescriptorBoundEnvelopeReadError.missingEnvelope {
            throw VaultFormatDetectorError.missingHeader
        } catch V2DescriptorBoundEnvelopeReadError.envelopeIsNotRegularFile {
            throw VaultFormatDetectorError.headerIsNotRegularFile
        } catch V2DescriptorBoundEnvelopeReadError.envelopeTooLarge {
            throw VaultFormatDetectorError.headerTooLarge
        } catch V2DescriptorBoundEnvelopeReadError.rootUnavailable {
            throw VaultFormatDetectorError.headerIsNotRegularFile
        } catch {
            throw VaultFormatDetectorError.headerReadFailed
        }

        guard reader.rootPathStillMatches(snapshot.rootIdentity, at: root) else {
            throw VaultFormatDetectorError.headerReadFailed
        }

        let probe: VersionProbe
        do {
            probe = try decoder.decode(VersionProbe.self, from: snapshot.data)
        } catch {
            throw VaultFormatDetectorError.malformedHeader
        }

        guard reader.rootPathStillMatches(snapshot.rootIdentity, at: root) else {
            throw VaultFormatDetectorError.headerReadFailed
        }
        guard let format = HanzalaVaultStorageFormat(rawValue: probe.formatVersion) else {
            throw VaultFormatDetectorError.unsupportedVersion(probe.formatVersion)
        }
        return format
    }
}
