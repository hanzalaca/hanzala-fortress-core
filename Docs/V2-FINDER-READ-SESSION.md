# Hanzalaomator v2 logical Finder read session

Status: disabled v2 Finder/storage integration. This does not enable the production Hidden/Decoy UI or switch the existing Finder mount to v2.

## Purpose

`V2FinderReadOnlySession` provides the core semantic bridge between an already-open v2 access path and future Finder/FSKit read callbacks without creating plaintext whole-file lease files.

It intentionally has no FSKit dependency. The extension remains keyless and a later RPC adapter can expose only logical file metadata, opaque logical handles, and bounded read requests.

## Enumeration

`listRoot()` reloads the current access path's authenticated metadata through `V2VaultSessionStore` and returns only:

- logical entry UUID;
- original display name;
- logical byte count;
- creation time.

Enumeration does not read file content and does not scan the shared object pool.

## Open handles

`open(entryID:)` verifies that the requested UUID exists in the current authenticated access metadata and then creates an in-memory logical handle.

It does not:

- decrypt the complete file;
- create a plaintext temporary file;
- expose a master key;
- expose the manifest name;
- expose chunk names;
- turn a caller-provided pool name into a capability.

A forged or closed handle is rejected before a storage read.

## Bounded reads

`read(handle:offset:length:)` is bounded by the same default 4 MiB read ceiling used by the current Finder RPC and `V2VaultSessionStore`.

The method validates the logical handle and delegates to `V2VaultSessionStore.readEntryRange`.

For a bounded single-object entry, only that authenticated object is opened. For a chunked entry, the authenticated private manifest is bound back to the live entry and only chunks intersecting the requested range are opened.

No whole large file is assembled into one plaintext `Data` value by this Finder bridge.

## Invalidation

`invalidate()` atomically prevents new logical I/O and forgets every open handle. There are no v2 plaintext lease files to remove.

If invalidation races a range read, the bridge checks its active state again after the storage read and discards the decrypted result instead of returning bytes once invalidation has been observed.

This is a semantic fail-closed boundary inside the process. The stronger hostile-process/filesystem race review remains separate.

## Visible/concealed isolation

Visible and concealed paths use exactly the same Finder-session implementation.

An entry UUID from the other access path cannot be opened because discovery starts only from the current path's authenticated private metadata. The shared pool is never scanned to find files.

## Compatibility

The existing v1 `FinderReadOnlySession` is unchanged. It continues to use on-demand plaintext leases for the existing production Finder path.

This stage adds the v2 logical read primitive only. It does not silently replace v1 behavior.

## Next integration stage

The next step is to adapt the keyless Finder RPC boundary so it can be backed by either:

- the existing v1 `FinderReadOnlySession`; or
- `V2FinderReadOnlySession`.

That adapter must preserve the current RPC limits and FSKit peer-authentication model while ensuring the extension receives no password, master key, manifest name, chunk name, or filesystem path to decrypted content.

After RPC integration, remaining work includes interruption/power-loss tests across v2 import/read/remove, physical allocation and macOS metadata-leakage review, security fuzzing, and production enablement only after those stages are stable.
