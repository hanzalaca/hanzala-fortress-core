import Foundation
import ImageIO

public enum ImageMetadataScrubberError: Error, Equatable {
    case malformedImage
    case unsupportedImageFormat
    case imageDecodeFailed
    case imageEncodeFailed
}

/// Creates a publication-oriented image copy without carrying sensitive source
/// metadata into the exported file.
///
/// The encrypted original is never modified. Callers provide decrypted image
/// bytes in memory and receive new image bytes containing decoded pixel frames
/// plus only the non-sensitive orientation value needed for correct display.
/// GPS, EXIF, TIFF camera fields, IPTC, XMP, comments, and other source metadata
/// are intentionally not copied into the destination container.
public final class ImageMetadataScrubber {
    public static let supportedFileExtensions: Set<String> = [
        "jpg", "jpeg", "png", "heic", "heif", "tif", "tiff"
    ]

    private static let supportedTypeIdentifiers: Set<String> = [
        "public.jpeg",
        "public.png",
        "public.heic",
        "public.heif",
        "public.tiff"
    ]

    public init() {}

    public func supports(fileName: String) -> Bool {
        let ext = (fileName as NSString).pathExtension.lowercased()
        return Self.supportedFileExtensions.contains(ext)
    }

    public func scrub(_ input: Data) throws -> Data {
        guard let source = CGImageSourceCreateWithData(input as CFData, nil) else {
            throw ImageMetadataScrubberError.malformedImage
        }
        guard let sourceType = CGImageSourceGetType(source) else {
            throw ImageMetadataScrubberError.malformedImage
        }

        let typeIdentifier = sourceType as String
        guard Self.supportedTypeIdentifiers.contains(typeIdentifier) else {
            throw ImageMetadataScrubberError.unsupportedImageFormat
        }

        let imageCount = CGImageSourceGetCount(source)
        guard imageCount > 0 else {
            throw ImageMetadataScrubberError.malformedImage
        }

        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            output,
            sourceType,
            imageCount,
            nil
        ) else {
            throw ImageMetadataScrubberError.imageEncodeFailed
        }

        for index in 0..<imageCount {
            guard let image = CGImageSourceCreateImageAtIndex(source, index, nil) else {
                throw ImageMetadataScrubberError.imageDecodeFailed
            }

            var safeProperties: [CFString: Any] = [:]
            if let sourceProperties = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [CFString: Any],
               let orientation = sourceProperties[kCGImagePropertyOrientation] {
                // Orientation is required for correct display and does not reveal
                // source identity/location. Everything else is intentionally dropped.
                safeProperties[kCGImagePropertyOrientation] = orientation
            }

            if typeIdentifier == "public.jpeg" ||
                typeIdentifier == "public.heic" ||
                typeIdentifier == "public.heif" {
                // Re-encoding is unavoidable when metadata is removed from a decoded
                // image. Use maximum quality to avoid introducing avoidable loss.
                safeProperties[kCGImageDestinationLossyCompressionQuality] = 1.0
            }

            CGImageDestinationAddImage(destination, image, safeProperties as CFDictionary)
        }

        guard CGImageDestinationFinalize(destination) else {
            throw ImageMetadataScrubberError.imageEncodeFailed
        }

        return output as Data
    }
}
