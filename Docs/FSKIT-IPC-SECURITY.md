# Hanzalaomator FSKit IPC Security Contract

Status: design contract for the first read-only Finder mount.

## Goal

The FSKit extension is a keyless filesystem client. The unlocked main Hanzalaomator app remains the only process that owns the `OpenedVault` and its master key. The extension must never receive the user's password, wrapped-password material, master key, index key, object key, or a reusable capability that can unlock a vault after the app locks.

## Transport

Use a local XPC connection between the embedded FSKit extension and the containing Hanzalaomator app/service. The production connection must validate the peer's code identity before serving vault operations. Do not expose a TCP/UDP listener, localhost HTTP API, UNIX socket with ambient user access, or a persistent bearer token on disk.

The app creates one ephemeral mount session after the vault is already unlocked. Every request is scoped to that session and to the currently mounted vault. Session state is memory-only and is destroyed on Lock, unmount, app termination, connection invalidation, or backing-drive disappearance.

## Allowed RPC surface

The extension may request only these semantic operations:

1. `listRoot` — decrypted names and non-secret file metadata from the encrypted index.
2. `open(entryID)` — open exactly one selected entry and receive an opaque handle.
3. `read(handle, offset, length)` — read a bounded range for an already-open handle.
4. `close(handle)` — release that handle and its plaintext lease.
5. `invalidate` — fail-close the mount session.

No RPC accepts a filesystem path chosen by the extension for plaintext output. No RPC returns encryption keys. No RPC permits arbitrary object IDs, raw `.hzo` paths, create, write, delete, rename, or export.

## Handle rules

- Handles are random, opaque, memory-only values.
- A handle is bound to one mount session and one vault entry.
- A handle from another session must be rejected.
- Closing a handle is idempotent.
- Lock/invalidate revokes all handles before the main app discards the unlocked vault session.
- Requests after invalidation fail closed.

## Read limits

The app validates offset/length and applies a maximum per-RPC read size. Large Finder reads are split into bounded requests. Integer overflow, negative lengths, stale handles, unknown entries, and reads after Lock are rejected.

## Plaintext exposure

Root enumeration does not materialize file contents. Opening one entry may create one Hanzalaomator-owned short-lived plaintext lease for that entry because the current secretstream format is sequential and random seeks are expensive. Other vault objects remain ciphertext. Final close or session invalidation removes Hanzalaomator-owned lease files.

Deletion of temporary plaintext is cleanup, not guaranteed secure erase on APFS/SSD/swap/snapshots/backups. External viewers can retain their own caches. A compromised unlocked user session may still ask the authorized mount to read additional files; lazy decryption reduces exposure but is not a hard security boundary against a fully compromised session.

## Portable-app requirement

The IPC design must not depend on `/Applications`, a machine-specific absolute path, or a device-bound vault key. The containing `.app` and embedded FSKit extension may run from a removable SSD/USB where macOS permits it. First use on a Mac may require enabling/provisioning the File System Extension, but the encrypted vault format and unlock key remain portable.

## Shutdown order

1. Reject new IPC/filesystem I/O.
2. Invalidate the Finder session and all opaque handles.
3. Remove Hanzalaomator-owned plaintext leases.
4. Unmount/invalidate the FSKit volume.
5. Verify the decrypted Finder view is gone.
6. Drop the unlocked vault session/key material from the app.

Backing-drive disappearance follows the same fail-closed order and must never fall back to another plaintext or writable location.
