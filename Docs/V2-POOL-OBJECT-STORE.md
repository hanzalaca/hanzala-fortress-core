# Hanzalaomator v2 Pool Object Store

Status: storage primitive only. The production v2 vault write path is still not enabled.

## Purpose

`V2PoolObjectStore` persists the authenticated objects produced by `V2PoolObjectCodec` into the shared v2 `objects/` pool without exposing original filenames or object roles in public paths.

## Write invariants

- final object names are validated 32-byte random lowercase-hex identifiers;
- an existing final object is never replaced;
- collisions retry with a new opaque name;
- the final opaque name is selected before encryption and is included in the AEAD associated data;
- ciphertext is therefore cryptographically bound to the exact public opaque filename under which it is committed;
- ciphertext is staged in the same pool directory and moved only after the complete staged write succeeds;
- staging files are removed on failure;
- the shared pool must be a real directory, not a symbolic link.

These rules are designed so an ordinary/decoy access path cannot accidentally overwrite an object that may belong to another access path, and so same-key ciphertext cannot be silently rebound by copying it to another opaque pool name.

## Read invariants

Before loading ciphertext into memory, the store verifies that:

- the requested name is a valid opaque v2 object name;
- the shared pool is a real non-symlink directory;
- the object exists and is a regular non-symlink file;
- the filesystem size does not exceed `V2PoolObjectCodec.maximumEnvelopeByteCount`.

The codec then authenticates the envelope with XChaCha20-Poly1305 using the exact opaque name as associated data before returning plaintext. A ciphertext encrypted for one valid object name fails authentication if read under another name, even with the same access master key.

## Metadata anchors

`V2AccessMetadataStore` derives one deterministic opaque anchor per access master key. Metadata ciphertext is sealed with that exact anchor name as associated data. Copying a valid metadata object to another opaque anchor cannot rebind it to another namespace.

## Deletion boundary

Physical deletion exists only as an internal authenticated primitive used by `V2RemovalTransactionCoordinator`.

Before deletion, the exact opaque object must:

- come from authenticated pending-removal metadata derived from a formerly-live entry;
- authenticate under the same access master key and exact opaque filename;
- have the expected private object kind;
- have the expected authenticated logical length;
- still pass regular-file, non-symlink, and bounded-size checks.

Unknown shared-pool objects are never selected for deletion merely because they are absent from the currently unlocked access path.

## Remaining work

Before production v2 storage can be enabled, the implementation still needs:

- a reviewed padding/bucket allocation and physical-capacity strategy;
- integrated v2 vault/session orchestration connecting the dual-access envelope to the authenticated metadata and transaction primitives;
- rollback and power-loss testing across the complete v2 path;
- chunk-level authenticated random-access storage for larger files;
- review of filesystem race resistance for hostile local concurrent modification;
- metadata leakage mitigation for snapshots, backups, indexing, thumbnails, swap, crash logs, timestamps, and SSD/TRIM behavior;
- migration/version-selection and recovery semantics;
- focused security review/fuzzing before enablement.

Authenticated metadata, ownership/import transactions, conservative cleanup policy, and authenticated removal transactions already exist as separate foundation layers.

v1 vaults and their write path remain unchanged.
