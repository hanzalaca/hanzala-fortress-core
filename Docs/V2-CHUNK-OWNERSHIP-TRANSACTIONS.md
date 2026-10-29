# Hanzalaomator v2 Multi-Object Chunk Ownership Transactions

Status: disabled storage foundation. This does not enable production Hidden/Decoy UI or large-file mutation through the public session API.

## Goal

A chunked file is physically represented by one encrypted manifest object plus multiple encrypted data chunk objects in the shared role-neutral `objects/` pool.

The security requirement is stricter than simply writing those files and later listing them in metadata: **the manifest name and every chunk name must already be authenticated as owned by the currently unlocked access path before the first corresponding pool object is created.**

That rule prevents cleanup or crash recovery from turning an arbitrary pre-existing opaque filename into a deletion capability.

## Authenticated metadata claim

`V2PendingChunkImport` is stored only inside the encrypted `V2AccessMetadata` anchor. It records:

- one transaction/file UUID;
- the opaque manifest object name;
- the original user-visible leaf filename;
- total logical byte length;
- the ordered opaque chunk names and logical chunk lengths;
- the whole-file SHA-256 digest;
- creation time.

The transaction UUID becomes the eventual live entry ID and the private manifest `fileID`.

All manifest/chunk names are included in `authenticatedOwnedObjectNames` while pending. After finalization, the live `V2AccessEntry` keeps the manifest as its primary opaque object and the chunk names as authenticated `auxiliaryObjectNames`, so ownership does not disappear after the pending record is removed.

Immediately preceding disabled v2 metadata remains decodable: missing `pendingChunkImports` and missing entry `auxiliaryObjectNames` decode as empty.

## Write order

`V2ChunkOwnershipTransactionCoordinator` follows this order:

1. generate one manifest name and the canonical ordered chunk names;
2. reject duplicates, invalid opaque names, authenticated ownership conflicts, and existing safe pool objects;
3. commit the complete multi-object ownership claim to authenticated metadata;
4. write every chunk immutably under its exact claimed name;
5. authenticate every chunk as `.data`, verify its logical length, and recompute the whole-file SHA-256 digest;
6. encode and immutably write the encrypted `.manifest` object under the already-claimed manifest name;
7. reopen/authenticate the manifest and require it to exactly match the pending transaction;
8. atomically transition authenticated metadata from pending chunk import to one live logical entry.

No chunk object is intentionally created before step 3.

## Chunk policy

The manifest foundation keeps the canonical chunk policy introduced previously:

- full chunk authenticated plaintext target: 4 MiB;
- logical full-chunk payload: target minus the private 10-byte pool-object header;
- every non-final chunk must use the canonical full logical length;
- only the final chunk may be shorter;
- the final chunk is still padded to the same 4 MiB authenticated plaintext target;
- maximum manifest chunk count: 16,384.

The pool-object AEAD remains XChaCha20-Poly1305 and remains bound to the exact opaque filename as associated data.

## Crash recovery

Recovery never scans the shared object pool. It starts from the authenticated pending transaction and inspects only its claimed names.

### Crash before all chunks exist and before manifest creation

If the manifest is absent and one or more chunks are missing:

1. every present claimed chunk must authenticate under the current access master key, exact opaque name, `.data` role, and expected logical length;
2. only those authenticated present chunks are eligible for rollback deletion;
3. missing chunks are already in the desired rollback state;
4. after rollback, the pending metadata claim is removed.

A wrong-key, malformed, wrong-kind, wrong-length, symlinked, or otherwise unsafe present object fails closed and the pending claim is preserved.

### Crash after all chunks exist but before manifest creation

Recovery authenticates all chunks, recomputes the whole-file SHA-256 digest, creates the already-claimed encrypted manifest, authenticates it, and finalizes the pending transaction.

### Crash after manifest creation but before metadata finalization

Recovery authenticates the manifest and every chunk, verifies the digest, then finalizes the live entry.

### Manifest exists but a chunk is missing

Recovery fails closed. It does **not** delete the remaining objects or silently downgrade the transaction to an incomplete rollback because manifest existence means the transaction reached the publish-preparation boundary. This state is treated as possible corruption/data loss requiring explicit handling.

## Removal boundary

The existing single-object removal coordinator is not allowed to process a live entry that has auxiliary chunk objects. `V2AccessMetadata.beginningRemoval` throws `chunkedRemovalUnsupported` for those entries.

This is intentional: deleting only the manifest would orphan chunks, while deleting chunks without a separately authenticated multi-object removal transaction would weaken the ownership proof.

## Public session boundary

`V2VaultSessionStore` now runs authenticated pending chunk recovery during session open/recovery and blocks ordinary mutation while any chunk recovery remains pending.

However, the public session API still exposes only bounded single-object import/read/remove. Large-file import, bounded-range reconstruction, and multi-object removal remain disabled until their complete security boundaries are implemented and tested.

## Remaining work

Before large-file v2 can be enabled through the production app:

1. streaming import from file handles without requiring the entire large file as one `Data` value;
2. authenticated bounded-range reads that open the manifest, map ranges to chunks, authenticate only required chunks, and verify file-level integrity appropriately;
3. authenticated multi-object removal/tombstone recovery for manifest + every chunk;
4. physical-byte accounting in addition to logical capacity accounting;
5. corruption tests for missing/reordered/swapped chunks and manifest tampering across reopen;
6. power-loss/fault injection across every transaction boundary;
7. metadata leakage mitigation for timestamps, snapshots, backups/iCloud history, Spotlight, thumbnails, swap, crash logs, allocation behavior, and SSD/TRIM;
8. focused security review and fuzzing before enabling v2 by default.

Existing v1 vaults are unchanged and are not migrated by this work.
