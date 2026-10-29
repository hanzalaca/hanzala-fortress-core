# Hanzalaomator Finder Mount IPC v2

## Why the previous bundled XPC rendezvous was removed

The first rendezvous experiment embedded `HanzalaomatorRendezvousService.xpc` inside the main app and attempted to use it as a meeting point between the app and the FSKit extension.

That is not a valid production path for this topology. Apple documents bundled XPC services as helpers that are normally private to their containing application. The FSKit extension is a separately launched app-extension process, so the design must not assume it can discover and connect to the main app's private bundled XPC service.

The experiment was removed before being used as the Finder mount transport.

## v2 transport direction

Use an App Group as the OS-authorized IPC namespace shared by the signed main app and the signed FSKit extension. The preferred portable transport is a UNIX domain socket located inside the App Group container.

This avoids:

- a LaunchAgent or LaunchDaemon installation dependency;
- a permanent helper daemon;
- a fixed `/Applications` dependency;
- serializing `NSXPCListenerEndpoint` (which current macOS rejects outside an XPC coder);
- moving any vault key into the FSKit extension.

The app can still be copied to and run from removable storage. The filesystem extension may require one-time enablement on each Mac, but the vault and app remain movable.

## Security contract

The main app remains the only process that owns the unlocked `OpenedVault`, password-derived material, master key, index key, and object keys.

The FSKit extension may request only:

1. root metadata;
2. open one indexed entry;
3. bounded range reads for that opened entry;
4. close the handle;
5. invalidate the mount session.

The socket protocol must never accept arbitrary source paths, plaintext destination paths, encrypted `.hzo` paths, write/create/delete/rename operations, passwords, or encryption keys.

Every mount gets a fresh random session identifier and a fresh socket pathname under the App Group container. The session descriptor contains routing information only; it is not a vault unlock secret and must be deleted when the mount ends.

Before serving file data, the server must authenticate the connecting process. App Group membership is the first OS boundary. Production builds must additionally validate the peer process code identity (same expected Hanzalaomator Team ID / extension identity) using macOS peer credentials plus Security.framework code validation. UID matching alone is not enough for the production security claim.

Reads remain bounded by the existing Finder RPC maximum. Unknown, stale, forged, cross-entry, and cross-session handles fail closed.

## Plaintext exposure

Directory enumeration returns names and metadata only. Opening one file may cause only that file to be materialized by the existing on-demand lease layer when required by an external reader. Other vault objects remain ciphertext.

This reduces exposure but is not hard isolation against a fully compromised unlocked user session. A process that compromises the main app while it holds the vault master key may be able to request additional decryptions.

## Backing-drive removal

If the vault backing drive disappears while unlocked:

1. reject new socket requests;
2. invalidate all remote handles;
3. invalidate and remove plaintext leases;
4. invalidate/unmount the FSKit volume;
5. remove the socket and session descriptor;
6. stop the security-scoped resource access;
7. drop the opened vault/key references in the main app.

Never redirect writes or plaintext to another disk.

## Build/provisioning requirement

Real App Group IPC requires both the main app and FSKit extension to be signed with entitlements authorized for the same App Group. CI can compile and test the wire protocol without those credentials, but a real mount test requires the user's Apple Developer signing/provisioning setup.

The group identifier is release configuration, not a cryptographic key, and must not be invented as a production identifier in source without matching provisioning.
