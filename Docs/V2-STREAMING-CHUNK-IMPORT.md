# Hanzalaomator v2 bounded streaming chunk import

Status: disabled v2 storage foundation. This does not enable production Hidden/Decoy UI.

## Purpose

Large journalist files must not be materialized as one complete plaintext `Data` value merely to enter the v2 encrypted object pool.

`V2ChunkOwnershipTransactionCoordinator.importChunkedFile` adds a bounded file-backed path that keeps plaintext I/O at one canonical chunk (about 4 MiB) or less while preserving the existing authenticated multi-object transaction and crash-recovery format.

The existing `importChunkedData` method remains for tests and callers that already have a bounded in-memory value, but it is not the preferred file-backed large-file path.

## Why the file is read twice

The current authenticated pending transaction stores the final whole-file SHA-256 digest before any pool object is created. That digest is needed by crash recovery to decide whether a complete chunk set is the expected logical file before it may create/finalize the manifest.

To preserve that format without keeping the entire plaintext in memory, the streaming path intentionally uses two bounded sequential passes:

1. **Pre-hash pass:** validate the source and compute SHA-256 with bounded reads.
2. Commit the future manifest name and every future chunk name, plus the known logical size and digest, inside encrypted authenticated metadata.
3. **Write pass:** reopen the source, read exactly one canonical chunk at a time, recompute SHA-256 independently, and immutably create the name-bound encrypted chunk objects.
4. Require the second-pass byte count and digest to match the first pass.
5. Authenticate the completed chunks, create/authenticate the encrypted manifest, and transition the pending claim to one live entry.

The second read costs I/O, but avoids introducing a partially defined digest state or a new public journal while v2 remains disabled and under review.

## Source validation

Before the pre-hash pass, the source must be:

- a regular filesystem file;
- not a symbolic link;
- large enough to require the chunked representation;
- small enough to fit the current 16,384-chunk manifest bound.

The expected file size is fixed from filesystem metadata before hashing. The pre-hash pass must read exactly that size and reach EOF.

Before the write pass the source is checked again for regular-file/symlink/size consistency. The write pass must again read exactly the fixed size and reach EOF.

## Detecting source changes

The write pass computes SHA-256 independently. A same-size source modification between passes therefore fails before manifest publication when the second digest does not equal the authenticated pending digest.

Shrink/growth is detected by exact-length reads and an EOF check. A source that changes while preserving both byte count and SHA-256 would require a practical SHA-256 second-preimage/collision break for this check to miss the content change.

## Rollback on source failure

If a source metadata/open/read/change failure happens before manifest publication, the importer attempts a conservative rollback:

- only chunk names already present in authenticated pending metadata are considered;
- every present chunk must authenticate under the current access key, exact opaque filename, `.data` role, and claimed logical length before deletion;
- missing chunks are already in the desired rollback state;
- the pending claim is removed only after its authenticated chunks are absent.

If a regular object unexpectedly occupies the claimed manifest name, rollback does not cross that boundary. The pending claim is preserved for recovery/investigation rather than guessing whether an external writer reached manifest publication.

Non-source failures such as an unexpected name collision or authentication problem also remain fail-closed and can be handled by the existing pending-chunk recovery state machine.

## Memory bound

The streaming source reader requests at most:

`V2ChunkOwnershipTransactionCoordinator.maximumStreamingReadByteCount`

which currently equals the 4 MiB canonical chunk plaintext target.

The write pass holds at most one logical chunk plaintext `Data` value at a time before handing it to the authenticated object codec. The whole logical file is never assembled by the streaming importer.

This is an exposure reduction, not a claim that the operating system will never page plaintext or retain filesystem/cache artifacts. macOS swap, snapshots, backups, crash logs, filesystem caches, and SSD/TRIM behavior remain separate threat-model work.

## Existing transaction guarantees retained

The streaming path still uses the same v2 rules:

- all manifest/chunk names are authenticated before any pool object write;
- objects are immutable and collision-safe;
- every object is XChaCha20-Poly1305 authenticated and bound to its exact opaque filename;
- chunk lengths and ordering are private inside authenticated metadata/manifest content;
- manifest creation occurs only after the complete chunk set authenticates and the whole-file digest matches;
- crash recovery never scans the shared pool;
- visible and concealed access paths use the same role-neutral storage implementation.

## Remaining work

Before production enablement, Hanzalaomator still needs:

- session-level file import routing that selects bounded single-object vs streaming chunked storage without exposing raw keys;
- Finder/FSKit range-read integration that avoids whole-file plaintext leases for chunked entries;
- broader power-loss and source-disconnect testing, including removable media;
- physical encrypted-byte accounting and allocation-leakage review;
- hostile-filesystem race review for source reads and deletion;
- focused fuzzing/security review;
- production UI only after the complete v2 path is stable.

Existing v1 vault behavior remains unchanged.
