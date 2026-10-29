# V2 Descriptor-Bound Removal

This stage narrows the hostile-filesystem race around authenticated v2 deletion on macOS.

## Previous gap

HZOBJ003 reads were already bound to retained no-follow file descriptors, but deletion still authenticated through that descriptor-bound read and later reopened the `objects/<opaque-name>` pathname for removal. A hostile local process could therefore replace either the pool pathname or the final opaque name between authentication and unlink.

## Darwin deletion path

For authenticated deletion, `V2PoolObjectStore` now:

1. opens the vault root with `O_NOFOLLOW | O_DIRECTORY`;
2. opens the public `objects` directory with `openat` relative to the retained root descriptor;
3. opens the exact opaque object with `openat(..., O_NOFOLLOW)` relative to that retained pool descriptor;
4. validates and reads the ciphertext from the already-open object descriptor;
5. authenticates HZOBJ003 under the access key and verifies the expected private kind/logical length;
6. rechecks that the public `objects` name still identifies the same retained directory inode;
7. rechecks that the exact opaque name still identifies the same authenticated object inode;
8. calls `unlinkat` relative to the retained pool descriptor;
9. synchronizes that same retained pool directory descriptor before deletion is reported durable.

Recovery-only confirmation of an already-absent authenticated name also uses `fstatat` plus synchronization on a retained pool descriptor instead of reopening the containing directory by pathname.

## Fail-closed behavior

If either the pool directory or the opaque object name is rebound after the authenticated descriptors were opened, removal fails with the generic object-delete failure and the higher-level authenticated tombstone remains pending. The substituted namespace entry is preserved.

The shared pool is never enumerated and no unknown object becomes a deletion candidate.

## Residual boundary

macOS does not provide a general unlink-by-open-file-descriptor primitive equivalent to Linux `AT_EMPTY_PATH`. There remains a very small hostile-process race between the final `fstatat` identity check and `unlinkat` on the same directory descriptor. This change materially narrows the previous pathname reopen window but does not claim to eliminate every namespace race against a process with concurrent filesystem mutation privileges, and it does not defend against a compromised kernel.

A process that can copy ciphertext can also preserve ciphertext elsewhere; authenticated deletion is not a secure-erasure claim for APFS, SSD flash translation layers, snapshots, backups, or cloud history.

Hidden/Decoy UI remains disabled and v1 is unchanged.
