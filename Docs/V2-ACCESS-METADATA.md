# Hanzalaomator v2 Access Metadata

Status: authenticated metadata foundation only. The production v2 mutation/write path remains disabled.

## Purpose

Each unlocked v2 access path needs private metadata that can describe its own files without exposing a public `hidden-index`, `decoy-index`, original filename, capacity reservation, or cleanup state.

`V2AccessMetadataStore` uses the access path's master key to derive an opaque deterministic anchor name through `V2StorageNamespaceLocator`. The metadata itself is encoded and sealed as a generic v2 pool object with XChaCha20-Poly1305. The public `objects/` directory therefore sees only another 64-character opaque filename and a generic authenticated ciphertext envelope.

## Private authenticated state

`V2AccessMetadata` currently models:

- a private random access identifier;
- a monotonic generation counter for the future transaction layer;
- live entries with opaque object names, original leaf filenames, logical byte counts, and creation timestamps;
- tombstoned object names;
- the role-neutral v2 storage budget;
- logical usage and object count.

Validation rejects duplicate IDs/names, unsafe original leaf names, invalid opaque names, live/tombstone overlap, ledger mismatches, arithmetic overflow, unsupported versions, and usage above the access path's budget.

## Padding

Metadata is padded inside authenticated encryption into coarse plaintext buckets beginning at 4 KiB. This reduces direct leakage of small metadata-size changes. It is not a complete cover-traffic, physical allocation, timestamp-hiding, or snapshot-deniability scheme.

## Ownership safety boundary

The public store intentionally supports only:

1. creation of an **empty** authenticated metadata anchor; and
2. authenticated reading of that anchor.

There is deliberately no public arbitrary `replace(metadata:)` API yet.

A caller must not be able to add an arbitrary existing pool filename to its metadata, later tombstone it, and thereby cause cleanup to delete an object belonging to another access path. New ownership claims therefore require a transaction protocol that proves the object name was allocated by the current authenticated access path before metadata is allowed to claim it.

That transaction layer is the next required stage.

## Initial-anchor behavior

Creation is fail-closed:

- the shared pool must be a real directory and not a symbolic link;
- an existing deterministic anchor is never overwritten;
- the complete sealed metadata is staged in the same directory and moved into place only after the staged write succeeds;
- failed staging files are removed best-effort.

Reads reuse `V2PoolObjectStore` protections for non-regular files, symbolic links, and oversized ciphertext before authentication and decoding.

## Remaining work

Before normal v2 file mutations are enabled, the implementation still needs:

- an authenticated transaction protocol for allocating and claiming new object names;
- generation-checked metadata replacement that accepts only proven ownership transitions;
- crash recovery for pending imports and interrupted metadata publication;
- tombstone execution that cannot delete another access path's objects;
- dummy/real metadata-anchor provisioning so visible-only and dual-access vault setup do not differ by an obvious missing second anchor;
- physical-capacity and padding allocation policy;
- stronger review of hostile concurrent filesystem races;
- migration/version selection and rollback testing.

Existing v1 vaults remain unchanged.
