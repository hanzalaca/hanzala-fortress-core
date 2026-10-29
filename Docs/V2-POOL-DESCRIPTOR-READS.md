# V2 descriptor-bound pool reads

Status: hostile-filesystem hardening. Hidden/Decoy production UI remains disabled and v1 is unchanged.

## Purpose

The v2 object pool previously validated an object pathname and then reopened that pathname through `Data(contentsOf:)`. A hostile external process could replace the directory entry between validation and the actual read.

On Darwin, `V2PoolObjectStore.readObject` now binds the ciphertext read to retained descriptors:

1. open the selected vault root as a no-follow directory descriptor;
2. open the role-neutral `objects` pool with `openat(... O_NOFOLLOW | O_DIRECTORY)` relative to that root descriptor;
3. open the exact validated opaque object name with `openat(... O_NOFOLLOW)` relative to the retained pool descriptor;
4. use `fstat` on that already-open object descriptor to require a regular file and enforce the maximum HZOBJ003 envelope size;
5. read exactly the captured bounded size from the descriptor and reject truncation or growth;
6. authenticate/decode those bytes with the existing HZOBJ003 AEAD binding to the requested opaque object name.

The final pathname is never reopened after descriptor acquisition. A deterministic test replaces the public object pathname after the object descriptor is opened and verifies that the read still authenticates the originally opened ciphertext rather than the attacker replacement.

## Preserved security properties

- arbitrary object symlinks are not followed;
- pool-directory symlinks are not followed by the Darwin read path;
- oversized objects are rejected before an unbounded read;
- wrong-key and wrong-name HZOBJ003 authentication behavior is unchanged;
- visible/concealed role information is not added to public paths or filenames;
- unknown pool objects are not scanned.

## Remaining boundary

This stage hardens reads only. `deleteAuthenticatedObject` first authenticates through the new descriptor-bound read, but physical deletion is still a later pathname namespace operation. A hostile external process can still race replacement between authentication and unlink. Closing that window requires a separate authenticated quarantine/rename design so no unauthenticated replacement is destroyed.

The vault-root pathname's own ancestors are also outside this stage, as are a compromised kernel/root process, host snapshots/history, Spotlight, swap/crash artifacts, and SSD/TRIM behavior.
