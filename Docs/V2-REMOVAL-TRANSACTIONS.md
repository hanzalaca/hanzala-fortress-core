# V2 authenticated removal transactions

This document freezes the authenticated deletion protocol for the v2 shared object pool. It remains storage-foundation code: production Hidden/Decoy mutation stays disabled until the larger v2 integration and security review are complete.

## Security goal

An unlocked access path must never delete a pool object merely because that object is absent from its own live index. The shared pool can contain objects belonging to another access path, so unknown objects are always preserved.

Deletion authority is derived only from authenticated private metadata that previously contained the exact logical entry. For chunked entries, every manifest/chunk name is copied into encrypted pending-removal metadata before any physical deletion begins.

The caller supplies only a live entry UUID. It never supplies an opaque manifest name, chunk name, or raw deletion plan.

## Single-object state machine

A bounded single-object removal follows this order:

1. Read and authenticate the current per-access metadata anchor.
2. Find the requested live entry by authenticated entry UUID.
3. Move that entry to `V2PendingRemoval` inside encrypted metadata.
4. Commit the next authenticated metadata generation.
5. Read/authenticate the exact opaque `.data` pool object under the same master key and filename binding.
6. Require the logical length recorded by the former live entry.
7. Re-check regular-file, symlink, and bounded-size filesystem properties.
8. Physically delete only that exact opaque object.
9. Commit another authenticated metadata generation that removes the pending-removal record.

## Chunked state machine

A chunked removal is more conservative because deleting only the manifest or only some chunks could orphan authenticated ownership.

Before the live entry becomes a tombstone, the coordinator:

1. Reads the encrypted manifest only through the authenticated live entry's primary opaque name.
2. Requires `.manifest` role and successful AEAD authentication under the current access key and exact filename.
3. Binds the private manifest back to the live entry UUID, total logical length, and ordered authenticated auxiliary chunk names.
4. Authenticates every manifest-declared chunk and recomputes the encrypted whole-file SHA-256 incrementally.
5. Only after that full preflight succeeds, commits `V2PendingRemoval` containing the manifest name plus the exact ordered auxiliary chunk names copied from authenticated live metadata.

Physical deletion then proceeds from the authenticated pending record:

1. Re-open and authenticate the manifest.
2. Re-bind manifest file ID, logical length, and ordered chunk names to the pending-removal record.
3. For every chunk, require exact opaque filename, `.data` role, and manifest-declared logical length before unlink.
4. Already-missing chunks are tolerated as a crash-resume state while the manifest still exists.
5. Delete the encrypted manifest **last**, after all chunk deletion attempts have reached the desired absent state.
6. Finalize the pending-removal metadata generation only after the complete object set is absent.

The manifest's encoded JSON byte length is not the logical file length, so its physical deletion authenticates exact name + AEAD + `.manifest` role without inventing a false logical-length comparison.

## Why the manifest is deleted last

While the manifest remains, it is the authenticated private map from a logical file to its ordered chunk names and chunk lengths. If the process crashes after deleting some chunks, recovery can reopen the manifest and safely continue with only the names already held in encrypted pending-removal metadata.

If recovery finds the manifest already absent, it may finalize only when **every authenticated auxiliary chunk name is also absent**. If even one auxiliary object remains, recovery fails closed with `manifestMissingWithAuxiliaryObjects` rather than guessing a length or deleting an object without the manifest's authenticated chunk description.

Malformed, wrong-key, wrong-kind, symlink, oversized, or otherwise inconsistent remaining objects also fail closed and preserve the pending record for investigation/recovery.

## Crash windows

### Crash after tombstone, before any physical deletion

The pending-removal record owns the exact manifest/chunk names inside authenticated metadata. Recovery verifies the manifest, verifies each present chunk under its declared length, removes the chunks, deletes the manifest last, and finalizes metadata.

### Crash after one or more chunks are deleted

The manifest remains. Recovery treats already-missing chunks as completed work, authenticates/deletes the remaining chunks, then deletes the manifest and finalizes metadata.

### Crash after manifest deletion, before metadata finalization

Recovery first confirms that every authenticated auxiliary name is also absent. Only then may it finalize the pending-removal record. A surviving auxiliary object causes a fail-closed error.

### Authentication or filesystem failure

Wrong-key ciphertext, tampering, wrong object role, logical-length mismatch, manifest/entry ownership mismatch, symlink substitution, non-regular files, oversized objects, and read failures all fail closed. No unknown object is selected as a substitute.

## Capacity behavior

Moving a live entry to pending removal decrements the live usage ledger, but the pending-removal logical file length is still included in validation's reserved usage. Capacity is not released for a new import until physical deletion has completed and the pending-removal record is finalized.

For a chunked file the usage ledger still counts one logical file, not the number of physical chunks. The pending-removal record preserves every physical object name while reserving the logical file length.

## Shared-pool safety

`authenticatedOwnedObjectNames` includes live entry primary/auxiliary names, pending imports, pending chunk imports, every pending-removal primary/auxiliary name, and legacy authenticated tombstones.

`authenticatedTombstonedObjectNames` includes every pending-removal primary/auxiliary name plus legacy authenticated tombstones.

`V2PoolCleanupPolicy` therefore continues to preserve unknown objects. Physical deletion remains an internal primitive and requires successful authenticated object open plus the expected role; data objects/chunks additionally require their authenticated logical length.

## Metadata compatibility

`V2PendingRemoval.auxiliaryObjectNames` was added while v2 remains disabled. Earlier pending single-object removal records decode with an empty auxiliary list. Existing v1 vaults are not migrated or modified by this work.

## Threat boundary

The metadata store serializes key-owning writers inside the main app process and rejects stale generations. The object store re-checks file safety immediately before deletion.

This version does not claim race-free deletion against a hostile external process that can replace filesystem entries between authentication and unlink. Descriptor-relative POSIX deletion and file-identity checks should be evaluated separately before any hostile-filesystem race-resistance claim.

No plaintext journal is created. No public file indicates visible vs concealed role. Recovery never scans the shared pool to discover deletion candidates.
