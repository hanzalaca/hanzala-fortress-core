import Foundation

/// Objective-C compatible XPC contract for the read-only Finder mount.
///
/// Only metadata and opaque per-session handles cross the process boundary.
/// Passwords, master keys, derived encryption keys, plaintext filesystem paths,
/// and raw encrypted-object paths are intentionally absent.
@objc public protocol FinderSessionXPCProtocol: NSObjectProtocol {
    func listRoot(reply: @escaping ([FinderSessionXPCFile]?, NSError?) -> Void)
    func open(entryID: String, reply: @escaping (FinderSessionXPCHandle?, NSError?) -> Void)
    func read(
        handleID: String,
        entryID: String,
        offset: UInt64,
        length: Int,
        reply: @escaping (Data?, NSError?) -> Void
    )
    func close(handleID: String, entryID: String, reply: @escaping () -> Void)
    func invalidate(reply: @escaping () -> Void)
}

public final class FinderSessionXPCFile: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let id: String
    public let name: String
    public let byteCount: UInt64
    public let createdAt: Date

    public init(id: UUID, name: String, byteCount: UInt64, createdAt: Date) {
        self.id = id.uuidString
        self.name = name
        self.byteCount = byteCount
        self.createdAt = createdAt
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let id = coder.decodeObject(of: NSString.self, forKey: "id") as String?,
              let name = coder.decodeObject(of: NSString.self, forKey: "name") as String?,
              let createdAt = coder.decodeObject(of: NSDate.self, forKey: "createdAt") as Date? else {
            return nil
        }
        self.id = id
        self.name = name
        self.byteCount = coder.decodeInt64(forKey: "byteCount").magnitude
        self.createdAt = createdAt
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(id as NSString, forKey: "id")
        coder.encode(name as NSString, forKey: "name")
        coder.encode(Int64(clamping: byteCount), forKey: "byteCount")
        coder.encode(createdAt as NSDate, forKey: "createdAt")
    }
}

public final class FinderSessionXPCHandle: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let id: String
    public let entryID: String

    public init(id: UUID, entryID: UUID) {
        self.id = id.uuidString
        self.entryID = entryID.uuidString
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let id = coder.decodeObject(of: NSString.self, forKey: "id") as String?,
              let entryID = coder.decodeObject(of: NSString.self, forKey: "entryID") as String? else {
            return nil
        }
        self.id = id
        self.entryID = entryID
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(id as NSString, forKey: "id")
        coder.encode(entryID as NSString, forKey: "entryID")
    }
}

public enum FinderSessionXPCServiceError: Error {
    case invalidUUID
}

/// Exported object hosted by the already-unlocked main app.
///
/// The underlying `FinderSessionRPC` remains the authorization boundary: XPC
/// decoding never grants access by itself. Unknown/stale/forged handles are
/// rejected by the RPC layer and invalidation revokes the entire mount session.
public final class FinderSessionXPCService: NSObject, FinderSessionXPCProtocol {
    private let rpc: FinderSessionRPC

    public init(rpc: FinderSessionRPC) {
        self.rpc = rpc
        super.init()
    }

    public func listRoot(reply: @escaping ([FinderSessionXPCFile]?, NSError?) -> Void) {
        do {
            let files = try rpc.listRoot().map {
                FinderSessionXPCFile(id: $0.id, name: $0.name, byteCount: $0.byteCount, createdAt: $0.createdAt)
            }
            reply(files, nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    public func open(entryID: String, reply: @escaping (FinderSessionXPCHandle?, NSError?) -> Void) {
        do {
            guard let id = UUID(uuidString: entryID) else { throw FinderSessionXPCServiceError.invalidUUID }
            let handle = try rpc.open(entryID: id)
            reply(FinderSessionXPCHandle(id: handle.id, entryID: handle.entryID), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    public func read(
        handleID: String,
        entryID: String,
        offset: UInt64,
        length: Int,
        reply: @escaping (Data?, NSError?) -> Void
    ) {
        do {
            guard let handleUUID = UUID(uuidString: handleID),
                  let entryUUID = UUID(uuidString: entryID) else {
                throw FinderSessionXPCServiceError.invalidUUID
            }
            let handle = FinderSessionRPC.RemoteHandle(id: handleUUID, entryID: entryUUID)
            reply(try rpc.read(handle: handle, offset: offset, length: length), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    public func close(handleID: String, entryID: String, reply: @escaping () -> Void) {
        if let handleUUID = UUID(uuidString: handleID),
           let entryUUID = UUID(uuidString: entryID) {
            rpc.close(FinderSessionRPC.RemoteHandle(id: handleUUID, entryID: entryUUID))
        }
        reply()
    }

    public func invalidate(reply: @escaping () -> Void) {
        rpc.invalidate()
        reply()
    }
}
