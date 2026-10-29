import CoreGraphics
import Foundation
import ImageIO
import XCTest
@testable import HanzalaomatorCore

final class ImageMetadataScrubberTests: XCTestCase {
    private enum TestError: Error {
        case imageCreationFailed
        case destinationCreationFailed
        case destinationFinalizeFailed
    }

    func testScrubberRemovesSensitiveMetadataAndPreservesOrientation() throws {
        let input = try makeJPEGWithSensitiveMetadata()
        let originalInput = input
        let scrubber = ImageMetadataScrubber()

        let output = try scrubber.scrub(input)

        XCTAssertEqual(input, originalInput, "Scrubbing must never mutate the encrypted original's decrypted source bytes")
        XCTAssertFalse(output.isEmpty)

        let source = try XCTUnwrap(CGImageSourceCreateWithData(output as CFData, nil))
        let properties = try XCTUnwrap(
            CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any]
        )

        XCTAssertNil(properties[kCGImagePropertyGPSDictionary], "GPS metadata must not survive Publish Copy")

        let exif = properties[kCGImagePropertyExifDictionary] as? [CFString: Any]
        XCTAssertNil(exif?[kCGImagePropertyExifUserComment], "EXIF comments must not survive Publish Copy")

        let tiff = properties[kCGImagePropertyTIFFDictionary] as? [CFString: Any]
        XCTAssertNil(tiff?[kCGImagePropertyTIFFMake], "Camera make must not survive Publish Copy")
        XCTAssertNil(tiff?[kCGImagePropertyTIFFModel], "Camera model must not survive Publish Copy")

        XCTAssertEqual(
            (properties[kCGImagePropertyOrientation] as? NSNumber)?.intValue,
            6,
            "Non-sensitive orientation should be preserved so the publication copy displays correctly"
        )
        XCTAssertEqual((properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue, 2)
        XCTAssertEqual((properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue, 2)
    }

    func testSupportedFileNamesAreExplicitAndConservative() {
        let scrubber = ImageMetadataScrubber()

        XCTAssertTrue(scrubber.supports(fileName: "photo.JPG"))
        XCTAssertTrue(scrubber.supports(fileName: "camera.heic"))
        XCTAssertTrue(scrubber.supports(fileName: "scan.tiff"))
        XCTAssertFalse(scrubber.supports(fileName: "animation.gif"))
        XCTAssertFalse(scrubber.supports(fileName: "clip.mov"))
        XCTAssertFalse(scrubber.supports(fileName: "document.pdf"))
    }

    func testMalformedImageIsRejectedWithoutOutput() {
        let scrubber = ImageMetadataScrubber()
        XCTAssertThrowsError(try scrubber.scrub(Data("not-an-image".utf8))) { error in
            XCTAssertEqual(error as? ImageMetadataScrubberError, .malformedImage)
        }
    }

    private func makeJPEGWithSensitiveMetadata() throws -> Data {
        let pixels: [UInt8] = [
            255, 0, 0,    0, 255, 0,
            0, 0, 255,    255, 255, 255
        ]
        let pixelData = Data(pixels)
        guard let provider = CGDataProvider(data: pixelData as CFData),
              let image = CGImage(
                width: 2,
                height: 2,
                bitsPerComponent: 8,
                bitsPerPixel: 24,
                bytesPerRow: 6,
                space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
                provider: provider,
                decode: nil,
                shouldInterpolate: false,
                intent: .defaultIntent
              ) else {
            throw TestError.imageCreationFailed
        }

        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            output,
            "public.jpeg" as CFString,
            1,
            nil
        ) else {
            throw TestError.destinationCreationFailed
        }

        let sensitiveProperties: [CFString: Any] = [
            kCGImagePropertyOrientation: 6,
            kCGImagePropertyGPSDictionary: [
                kCGImagePropertyGPSLatitude: 53.5461,
                kCGImagePropertyGPSLatitudeRef: "N",
                kCGImagePropertyGPSLongitude: 113.4938,
                kCGImagePropertyGPSLongitudeRef: "W"
            ],
            kCGImagePropertyExifDictionary: [
                kCGImagePropertyExifUserComment: "confidential-source-comment"
            ],
            kCGImagePropertyTIFFDictionary: [
                kCGImagePropertyTIFFMake: "Sensitive Camera Maker",
                kCGImagePropertyTIFFModel: "Sensitive Camera Model"
            ],
            kCGImageDestinationLossyCompressionQuality: 1.0
        ]

        CGImageDestinationAddImage(destination, image, sensitiveProperties as CFDictionary)
        guard CGImageDestinationFinalize(destination) else {
            throw TestError.destinationFinalizeFailed
        }
        return output as Data
    }
}
