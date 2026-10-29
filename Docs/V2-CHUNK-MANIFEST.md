# Hanzalaomator v2 authenticated chunk manifest

Status: chunk-format and authenticated ownership foundation only. This does not yet enable large-file mutation through the production v2 session API.

## Purpose

The v2 pool object format intentionally caps authenticated plaintext at 16 MiB. Large journalist files must not bypass that bound or fall back to an unreviewed encryption path.

`V2ChunkManifest` provides the private authenticated map for one future multi-object logical file, and `V2ChunkOwnershipTransactionCoordinator` now provides the first authenticated ownership state machine around that map.

## Private manifest

`V2ChunkManifest` records, inside authenticated encryption:

- manifest format version;
- logical file UUID;
- total logical file length;
- ordered opaque chunk object names;
- authenticated logical length for every chunk;
- SHA-256 digest of the reconstructed logical file.

The manifest is stored as `V2PoolObjectKind.manifest`. That role is inside the existing `HZOBJ003` encrypted payload. The public object envelope and opaque filename do not expose that the object is a manifest.

## Chunk allocation policy

A full chunk uses a 4 MiB authenticated plaintext target. The generic v2 encrypted payload header occupies ten bytes inside that target, so a full logical chunk contains:

`4 MiB - 10 bytes`

The final chunk may contain fewer logical bytes, but it is padded to the same 4 MiB authenticated plaintext target by the pool object codec.

All non-final chunks must use the canonical full logical chunk length. Caller-selected intermediate chunk boundaries are rejected so they cannot become a configurable public allocation fingerprint.

Chunked representation is accepted only when the logical file is larger than the maximum content that fits in one v2 pool object. Smaller files remain on the single-object path.

## Validation

Before a manifest is trusted:

- format version must match;
- there must be at least two chunk references and no more than 16,384;
- every opaque chunk name must be valid and unique;
- every chunk length must be non-zero and within the fixed chunk limit;
- all non-final chunks must have the canonical full length;
- overflow-safe sum of chunk lengths must equal total logical length;
- the whole-file SHA-256 field must be exactly 32 bytes;
- the total must be large enough to require chunking.

The 16,384-chunk cap bounds manifest parsing/memory and currently limits this foundation to roughly 64 GiB per logical file. A future format revision may deliberately change that bound after review.

## Manifest confidentiality and binding

The encoded manifest uses the same XChaCha20-Poly1305 `HZOBJ003` object codec used elsewhere in v2.

The manifest's opaque public filename remains mandatory AEAD associated data. Copying the ciphertext to another opaque filename causes authentication failure.

The encoded manifest receives the existing coarse metadata padding policy before encryption, so small differences in chunk count do not directly map to exact public manifest size.

## Whole-file digest

The manifest carries SHA-256 of the reconstructed logical file as an additional end-to-end consistency check. This digest is encrypted; it is not a public fingerprint.

Chunk-object AEAD remains the primary authenticity mechanism. The digest does not replace per-object authentication, object-name binding, or authenticated ownership metadata.

The ownership coordinator recomputes the digest after all claimed chunks authenticate and before manifest creation/finalization. Crash recovery repeats that check when all chunks are present.

## Authenticated ownership transaction now implemented

The disabled v2 foundation now pre-commits the manifest name and every chunk name inside encrypted `V2AccessMetadata` before any corresponding object is intentionally written.

The transaction order is:

1. authenticated multi-name ownership claim;
2. immutable encrypted chunk creation;
3. per-chunk kind/length authentication plus whole-file digest verification;
4. immutable encrypted manifest creation;
5. manifest authentication;
6. authenticated pending-to-live metadata transition.

Recovery follows only names from the authenticated pending transaction and never scans the shared pool. Incomplete pre-manifest writes can roll back only authenticated claimed chunks. A present manifest with missing chunks fails closed.

Finalized chunked entries preserve the chunk names as authenticated auxiliary ownership, while single-object removal is explicitly blocked for such entries until a chunk-aware removal transaction exists.

See `Docs/V2-CHUNK-OWNERSHIP-TRANSACTIONS.md` for the full recovery and ownership boundary.

## What is intentionally not implemented yet

This stage still does not:

- stream a source file from a file handle into chunks without holding the complete logical file as one `Data` value;
- provide authenticated bounded-range reconstruction through `V2VaultSessionStore`;
- delete a manifest and all of its chunks through an authenticated multi-object tombstone transaction;
- account for physical encrypted bytes separately from logical file capacity;
- expose chunked import/read/remove through the production session/UI path;
- claim protection against host-level metadata leakage such as snapshots, backups, Spotlight, thumbnails, swap, crash logs, allocation history, or SSD/TRIM behavior.

Those are the next large-file stages. Existing v1 behavior remains unchanged.
