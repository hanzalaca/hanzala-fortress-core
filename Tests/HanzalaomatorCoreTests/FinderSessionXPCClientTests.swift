import XCTest

// NSXPCConnection/NSXPCListener exist only on macOS; the Finder bridge is macOS-only.
#if os(macOS)
@testable import HanzalaomatorCore

final class FinderSessionXPCClientTests: XCTestCase {
    func testClientCanBeConstructedFromLiveAnonymousEndpointWithoutPersistingIt() {
        let listener = NSXPCListener.anonymous()
        defer { listener.invalidate() }

        let client = FinderSessionXPCClient(
            endpoint: listener.endpoint,
            serverCodeSigningRequirement: "anchor apple generic"
        )

        XCTAssertNotNil(client)
    }

    func testEndpointIsIntentionallyNotArchivableWithNSKeyedArchiver() {
        let listener = NSXPCListener.anonymous()
        defer { listener.invalidate() }

        XCTAssertThrowsError(
            try NSKeyedArchiver.archivedData(
                withRootObject: listener.endpoint,
                requiringSecureCoding: true
            )
        )
    }
}

#endif
