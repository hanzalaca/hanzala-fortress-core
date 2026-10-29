# V2 descriptor-bound envelope reads

This stage hardens reads of the public `vault.hanzala` envelope used to begin v2 password and HZRK recovery opens.

## Why the public envelope still needs binding

The envelope is not secret, but it controls the public vault identity, password KDF parameters, and encrypted access slots. Validating one pathname and later reopening it leaves a namespace race where another process can substitute a different file between those operations.

On macOS, `V2DescriptorBoundEnvelopeReader` instead:

1. opens the vault root with `O_NOFOLLOW | O_DIRECTORY` or accepts a caller-owned retained root capability;
2. captures the root device/inode identity with `fstat`;
3. opens exactly `vault.hanzala` with `openat(..., O_NOFOLLOW)` relative to that retained root descriptor;
4. requires a regular file and enforces the existing 1 MiB bound before allocating;
5. reads only from the retained envelope descriptor;
6. rechecks the envelope device/inode, size, and mtime snapshot after the read.

`ctime` is intentionally not used as a content-stability test. On macOS, renaming an already-open inode can update its status-change time even though the retained descriptor still points to the same unchanged bytes. Device/inode binding prevents pathname retargeting, while size and mtime remain the content-change checks for this bounded read.

Replacing the public envelope pathname after the descriptor has been opened therefore cannot retarget the bytes being decoded and does not create a false corruption result merely because the original inode was renamed.

## Password and recovery open binding

`V2VaultBootstrapStore.openAccess` and `openRecoveryAccess` now acquire one `V2RetainedVaultRoot` before the envelope read and keep it alive through the credential-selected private-anchor reads. Password metadata, and recovery-anchor plus metadata resolution, therefore use the same root directory capability instead of reopening the public root pathname between identity checks.

Immediately before publishing an unlocked foundation, the public root path must still resolve to the retained device/inode. Recovery-side root/anchor failures continue to collapse onto the existing generic invalid-recovery surface rather than exposing a new probe.

The detailed transaction boundary is documented in `V2-UNLOCK-ROOT-CAPABILITY.md`. The shared object pool is still never scanned to discover another access path.

## Failure behavior

- missing envelope remains `missingEnvelope`;
- symlink/non-regular envelope remains `envelopeIsNotRegularFile`;
- oversize envelope remains `envelopeTooLarge`;
- short, content-changed, malformed, or otherwise unsafe descriptor reads fail as `invalidEnvelope` at the bootstrap boundary;
- HZRK open continues to collapse private-access failures to the generic recovery error.

## Remaining boundary

The earlier replace-and-restore gap caused by independently reopening the vault root for private unlock reads is closed by the retained unlock-scoped root capability. The capability is not yet retained for the entire unlocked session; later reads and mutations use their own descriptor-bound operations.

The protection also does not cover a compromised kernel, storage firmware, APFS snapshots, Time Machine/cloud history, swap, crash artifacts, Spotlight/recent-item metadata, or SSD/TRIM allocation history.

Hidden/Decoy UI remains disabled and v1 is unchanged.
