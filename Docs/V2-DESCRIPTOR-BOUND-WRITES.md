# V2 Descriptor-Bound Pool Writes

This stage binds immutable HZOBJ003 pool-object publication to the same retained macOS directory capability used by hardened reads and removals.

## Previous gap

`V2PoolObjectStore` already authenticated reads through retained no-follow descriptors and authenticated deletion was moved to retained descriptors in the preceding stage. New object publication still created a pathname-based staging file and later moved it using the public `objects/...` pathname. A hostile local process with namespace mutation privileges could replace the public pool directory while an ownership transaction was staging ciphertext.

## Darwin publication path

For a new immutable pool object, the store now:

1. opens the vault root with `O_NOFOLLOW | O_DIRECTORY`;
2. opens the public `objects` directory with `openat` relative to the retained root descriptor;
3. records the retained pool directory device/inode identity;
4. creates a random staging entry with `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` relative to that pool descriptor and mode `0600`;
5. writes and synchronizes the staging descriptor using the existing durable file-sync policy;
6. verifies the random staging name still refers to the same retained staging inode;
7. verifies the public `objects` name still refers to the retained pool inode;
8. rechecks that the final opaque name is absent;
9. publishes with Darwin `renameatx_np(..., RENAME_EXCL)` inside the retained pool directory so an existing destination is never overwritten;
10. verifies the final opaque name resolves to the inode that was staged;
11. best-effort synchronizes the retained pool directory descriptor, preserving the existing new-write recovery contract.

HZOBJ003 ciphertext remains AEAD-bound to the final opaque object name. The staging filename is not authenticated data and is never promoted unless its inode identity still matches the descriptor that received the synchronized ciphertext.

## Failure behavior

If the public pool path changes after staging begins, publication fails closed. If the random staging pathname itself is replaced, cleanup does not unlink the substitute because staging cleanup is inode-checked. If a destination appears before publication, the existing destination wins and is preserved.

Pre-namespace simulated power loss still leaves staging residue, and post-namespace simulated power loss can leave the final object published. Existing authenticated pending-import recovery remains the authority for deciding whether that object becomes live.

## Boundaries

This change does not make the host trusted and does not prevent a process with sufficient privileges from copying ciphertext, mutating the filesystem before descriptors are first opened, or attacking the kernel. Metadata-anchor replacement and the public `vault.hanzala` envelope are separate mutation paths and are intentionally not folded into this PR.

Hidden/Decoy UI remains disabled and v1 is unchanged.
