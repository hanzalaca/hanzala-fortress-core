# V2 descriptor-bound metadata commits

This stage narrows hostile filesystem namespace races around the private v2 access-metadata anchor on macOS.

## Initial metadata publication

Initial metadata anchors now publish through the same descriptor-bound immutable HZOBJ003 pool-object writer used for ordinary v2 objects. The exact deterministic opaque anchor name remains AEAD-bound to the ciphertext.

## Generation replacement

For an existing metadata anchor, the Darwin path now keeps these capabilities open together:

1. the selected vault root directory;
2. the shared `objects` directory opened with `openat(..., O_NOFOLLOW | O_DIRECTORY)` relative to that root;
3. the exact opaque metadata anchor opened with `openat(..., O_NOFOLLOW)` relative to the retained pool directory.

The authenticated current generation is read from the retained anchor descriptor. The normal generation/access-ID/budget checks are performed against those bytes before a replacement staging file is created.

The replacement ciphertext is written to a random 0600 staging entry with descriptor-relative `openat(O_CREAT | O_EXCL | O_NOFOLLOW)`, synchronized, and then the code rechecks that:

- the public `objects` name still resolves to the retained pool inode;
- the metadata anchor name still resolves to the inode that was authenticated;
- the staging name still resolves to the staged inode.

Only then is `renameat` performed relative to the retained pool descriptor. The resulting anchor is checked to reference the staged inode and the retained pool directory is synchronized before success is returned.

## Failure behavior

If the public pool directory or metadata-anchor pathname is replaced before the final namespace mutation, the operation fails closed. Cleanup only removes the staging entry when that name still resolves to the inode created by the current operation. Substituted entries are not deleted.

A namespace-sync failure after the rename is an ambiguous committed state. Higher-level authenticated transaction recovery remains the authority on the next open.

## Remaining boundary

macOS does not provide a compare-and-swap rename primitive keyed to an expected destination inode. A hostile process can therefore still race the final `fstatat` identity check and `renameat` call. This PR substantially narrows the window but does not claim to eliminate every hostile same-host namespace race.

The protection also does not cover a compromised kernel, malicious storage firmware, APFS snapshot/history leakage, Time Machine or cloud version history, swap/crash artifacts, or SSD/TRIM forensic behavior.

Hidden/Decoy UI remains disabled and v1 is unchanged.
