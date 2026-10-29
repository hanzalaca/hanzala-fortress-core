# Hanzalaomator v2 session file import routing

Status: disabled v2 storage integration. This does not enable production Hidden/Decoy UI.

## Purpose

`V2VaultSessionStore.importFile` is the first session-level file import entry point that automatically selects the existing authenticated single-object transaction or the streamed multi-object chunk transaction without exposing the access master key or opaque pool names to callers.

The caller supplies only:

- a regular source file URL;
- an optional presentation/original filename;
- an already-open `V2VaultSession`.

## Routing rule

The source file is inspected before import. Symbolic links and non-regular files are rejected.

If the source length is at or below `V2DataObjectPaddingPolicy.maximumLogicalContentByteCount`, the session reads the file using bounded sequential reads and then commits it through the existing authenticated single-object ownership transaction.

If the source length is larger than that threshold, the session routes directly to `V2ChunkOwnershipTransactionCoordinator.importChunkedFile`.

The large-file path therefore keeps the two-pass behavior already reviewed for v2:

1. bounded pre-hash pass;
2. authenticated reservation of manifest/chunk names;
3. bounded encrypted chunk-write pass;
4. digest agreement check;
5. encrypted manifest publication;
6. authenticated pending-to-live metadata transition.

## Memory boundary

The automatic file API never constructs one complete large-file `Data` value.

Large files remain bounded to the canonical streaming/chunk read size. Small files may be materialized only because they are already bounded by the single-object plaintext ceiling.

The existing `importData` API remains available for already-materialized bounded values. It is intentionally not changed into an unbounded large-file API.

## Session and recovery boundary

Before inspecting or reading the source file, `importFile`:

1. revalidates the pinned public access envelope;
2. reloads authenticated private metadata;
3. verifies the session access identity;
4. refuses mutation if authenticated pending import/removal recovery exists.

This keeps file import on the same session mutation contract as the existing data import and removal APIs.

For a finalized import, the session reloads authenticated metadata and confirms that the committed entry is present before returning it.

## Source safety

The session rejects source paths that are symbolic links or non-regular files. The bounded single-object path checks the expected source size before opening, reads exactly that many bytes, requires EOF, and checks the file metadata again before committing the resulting data.

The streamed large-file path retains its own second-pass source checks and digest comparison. If a large source changes between passes before manifest publication, only authenticated claimed chunks may be rolled back.

This stage does not claim race-free source handling against a hostile external process that can replace filesystem entries between path checks and open/read operations. Descriptor-relative POSIX source handling should be considered separately during the hostile-filesystem review.

## Access isolation

The automatic routing rule is role-neutral. Visible and concealed sessions use the same source inspection, size threshold, single-object transaction, chunk transaction, padding, and recovery rules.

No public filename, directory, switch, or on-disk marker indicates which access role imported a file.

## Remaining work

Before v2 file mutation can be enabled in production, Hanzalaomator still needs:

- Finder/session bounded-read integration for the v2 logical file API;
- Finder or app-side file import wiring that calls `importFile` rather than importing large plaintext values through `Data`;
- interruption/power-loss tests spanning streamed import, bounded read, and chunk-aware removal together;
- physical allocation and host metadata-leakage review;
- focused security review/fuzzing;
- production UI enablement only after the storage path is stable.

Existing v1 behavior remains unchanged.
