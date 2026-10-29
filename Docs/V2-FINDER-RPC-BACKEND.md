# V2 Finder RPC Backend

This stage keeps the existing keyless Finder RPC surface while allowing the unlocked main app to choose either the legacy v1 Finder session or the v2 logical read-only session as its backend.

## Security boundary

The RPC client receives only:

- logical file metadata;
- an opaque remote handle tied to one authenticated entry UUID;
- bounded plaintext byte ranges requested through that handle.

The RPC surface does not expose passwords, master keys, v2 metadata anchors, manifest names, chunk names, pool-object names, or plaintext backing paths.

## V2 behavior

When `FinderSessionRPC` is initialized with `V2FinderReadOnlySession`:

- listing is derived from authenticated per-access metadata;
- opening a file creates only an in-memory logical handle;
- reads delegate to `V2VaultSessionStore.readEntryRange` through the v2 Finder session;
- single-object reads authenticate the requested object;
- chunked reads decrypt only the authenticated chunks intersecting the requested logical range;
- the RPC-level maximum read length is enforced before backend storage access;
- forged, stale, closed, or entry-mismatched remote handles fail closed;
- invalidation clears remote handles, invalidates the selected backend, and prevents newly decrypted bytes from being returned after invalidation is observed.

The same RPC types and methods remain available for the current v1 path so the wire/XPC layer does not need a storage-format-specific protocol.

## Access isolation

A v2 backend is bound to exactly one already-open `V2VaultSession`. An entry UUID from another access path cannot be opened because it is absent from the current path's authenticated metadata. The shared pool is never scanned to discover files.

## Status

This remains a disabled v2 integration stage. It does not switch the production Finder mount to v2 and does not enable Hidden/Decoy UI.

Next integration work:

1. make the app-side Finder session publisher select a v2 RPC backend only for an explicitly opened v2 session;
2. keep the FSKit extension keyless and storage-format neutral;
3. preserve peer code-signature authentication and fail-closed lock/unmount ordering;
4. add end-to-end tests from the existing socket/XPC transport through the v2 backend before enabling a production v2 mount path.
