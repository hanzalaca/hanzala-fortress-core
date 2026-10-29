# Hanzalaomator v2 session-bound chunk reads

Status: disabled v2 storage integration. This does not enable production Hidden/Decoy UI.

## Purpose

`V2VaultSessionStore` exposes bounded logical reads through an authenticated session capability for both bounded single-object files and previously finalized chunked files.

Callers provide only:

- the already-open `V2VaultSession`;
- an authenticated live entry UUID;
- logical offset and bounded read length.

They do not provide raw master keys, manifest names, chunk names, or arbitrary pool object names.

## Security boundary

Every read first reloads authenticated per-access metadata and revalidates the pinned public access-envelope identity and access ID. A caller therefore cannot forge a `V2AccessEntry` to redirect a read toward an unrelated shared-pool object.

For single-object entries, the stored object must authenticate as `.data` under the session key, exact opaque filename, and metadata-declared logical length.

For chunked entries, `V2ChunkedFileReader` re-authenticates the encrypted manifest and binds it back to:

- the authenticated live entry UUID;
- the entry's total logical length;
- the ordered authenticated auxiliary chunk ownership names.

Only chunks intersecting the requested range are opened. Each touched chunk must authenticate under the session key and exact opaque filename and match its manifest-declared logical length.

## Bounded reads

`V2VaultSessionStore.defaultMaximumReadLength` is 4 MiB, matching the current Finder RPC default bound. A custom smaller bound may be injected for testing or future callers.

Negative lengths are rejected. Reads larger than the configured bound are rejected before storage access. Reads that extend beyond EOF are clamped to the remaining logical bytes.

The legacy full-value `readEntry` API remains limited to bounded single-object entries. It deliberately refuses chunked files so a large logical file cannot accidentally be materialized as one giant `Data` value through that path.

## Integrity verification

`verifyEntryIntegrity` authenticates one live entry without requiring the caller to know storage names.

- bounded single-object entries are authenticated and length-checked;
- chunked files authenticate the manifest, authenticate every chunk, and recompute the encrypted whole-file SHA-256 incrementally without assembling the complete file in memory.

## Access isolation

The shared object pool is never scanned for discovery. A visible session cannot read or verify a concealed entry UUID because that entry is absent from the visible path's authenticated metadata, and vice versa.

## Removal integration

The v2 removal coordinator now has a chunk-aware authenticated path. Before a chunked live entry becomes pending removal, it verifies the private manifest, binds the manifest to the entry's ID/length/ordered auxiliary ownership, authenticates every chunk, and recomputes the whole-file digest. The pending tombstone then owns the manifest plus every chunk name before physical deletion begins.

Chunks are removed using manifest-authenticated lengths and the encrypted manifest is removed last, preserving a crash-recovery map until the final physical step. Recovery never scans the pool and fails closed if a manifest is missing while an authenticated auxiliary object still remains.

The public metadata transition `beginningRemoval` still rejects chunked entries directly; only the coordinator can reach the internal chunk-aware transition after completing the manifest/integrity preflight.

## Remaining work

Before the chunked path can be enabled end to end, Hanzalaomator still needs:

- streamed file import so large source files do not arrive as one giant in-memory `Data` value;
- Finder/session integration that uses bounded range reads without plaintext whole-file materialization;
- broader power-loss and corruption tests across chunked import/read/remove together;
- physical allocation / metadata-leakage review;
- descriptor-relative deletion / hostile-filesystem race review;
- focused security review and fuzzing;
- production UI enablement only after the storage path is stable.

Existing v1 behavior remains unchanged.
