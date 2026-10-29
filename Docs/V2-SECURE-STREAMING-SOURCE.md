# V2 descriptor-bound streaming imports

Large-file v2 imports stay bound to one secure source capability from path traversal through final encrypted publication.

## Boundary

`V2SecureSourceFile` traverses the selected absolute path on Darwin with retained directory descriptors. Every ordinary ancestor is opened with `openat(... O_NOFOLLOW | O_DIRECTORY)` and the final component is opened with no-follow `openat` relative to the last directory descriptor. The final regular file's device/inode/size/mtime/ctime identity is captured with `fstat` and that descriptor is kept for the lifetime of the import.

The same final descriptor is used for:

1. the bounded SHA-256 pre-hash pass;
2. rewind before encrypted publication;
3. every bounded chunk read in pass two;
4. the final unchanged-file check.

`V2VaultSessionStore.importFile` reuses the descriptor it opened before choosing bounded or chunked routing. The large route never resolves the source pathname a second time.

## Path and ancestor replacement

Replacing the final pathname after the source descriptor exists cannot redirect plaintext reads. Replacing an ancestor after Hanzalaomator has opened that directory also cannot redirect subsequent components because `openat` proceeds from the retained directory descriptor.

Strict device/inode/size/mtime/ctime validation may treat a rename as a suspicious mutation and fail closed. That is intentional. The safety property is not that every benign rename succeeds; it is that attacker replacement bytes are never silently imported as though they were the selected source.

If the opened inode itself changes, the pending chunk claim is rolled back through authenticated ownership rules before a manifest is published. Unknown pool objects are never scanned or deleted.

## What this does not claim

This is not a general hostile-filesystem or hostile-kernel proof. In particular:

- a real directory entry substituted before its component is first opened can still become the retained directory capability;
- a hostile kernel/root process can interfere below these checks;
- mount/filesystem semantics outside the process boundary remain relevant;
- host filesystem metadata, snapshots, Time Machine/cloud history, swap, crash logs, and SSD/TRIM artifacts remain outside this guarantee;
- the encrypted ownership/recovery state machine remains the authority for which pool objects may be finalized or removed.

Hidden/Decoy UI remains disabled and v1 is unchanged.
