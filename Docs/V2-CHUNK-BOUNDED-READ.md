# Hanzalaomator v2 Authenticated Bounded Chunk Reads

Status: disabled storage foundation. This does not yet enable production Hidden/Decoy UI or expose chunked files through the public v2 session/Finder path.

## Goal

Large v2 files are represented by one authenticated encrypted manifest plus multiple independently authenticated encrypted chunk objects. A read path must not reconstruct the entire file merely to serve a small Finder-style range, and it must never accept raw pool filenames from an untrusted caller.

`V2ChunkedFileReader` provides the storage primitive for bounded logical range reads.

## Trust boundary

The reader accepts a `V2AccessEntry` that must already have come from authenticated per-access metadata. From that entry it obtains only the manifest object's authenticated primary opaque name.

The reader then:

1. opens the manifest object under the current access master key and the exact opaque filename;
2. requires the private object role to be `.manifest`;
3. decodes and validates the authenticated `V2ChunkManifest`;
4. binds the manifest back to the authenticated metadata entry by requiring:
   - `manifest.fileID == entry.id`;
   - `manifest.logicalByteCount == entry.logicalByteCount`;
   - ordered manifest chunk names exactly equal `entry.auxiliaryObjectNames`;
5. maps the requested logical range to the private manifest chunk ranges;
6. reads only intersecting chunk objects;
7. requires every touched chunk to authenticate under the current master key, exact opaque filename, `.data` role, and manifest-declared logical length;
8. returns exactly the requested logical bytes, clamped at EOF.

The shared pool is never scanned. A caller cannot provide or substitute a raw chunk object name.

## Read bound

The default logical read limit is 4 MiB. This intentionally matches the existing Finder RPC maximum while remaining a storage-layer constant.

Requests larger than the configured bound fail before chunk materialization. A legal request may cross a chunk boundary, but the implementation holds at most one bounded decrypted chunk at a time plus the returned range buffer.

The underlying v2 object store still authenticates the complete touched chunk object before any bytes from it are returned.

## Range semantics

- negative length: rejected;
- length above configured maximum: rejected;
- zero length: empty result;
- offset at/past logical EOF: empty result;
- request extending past EOF: clamped to remaining logical bytes;
- arithmetic and assembled-length inconsistencies: fail closed.

## Whole-file integrity

An arbitrary range read does **not** recompute the manifest's whole-file SHA-256 digest. Recomputing it would require reading every chunk for each small random-access request and would defeat the bounded-read goal.

For a range read, authenticity comes from:

- XChaCha20-Poly1305 authentication of the manifest;
- manifest filename AEAD binding;
- XChaCha20-Poly1305 authentication of every touched chunk;
- exact chunk filename AEAD binding;
- authenticated chunk role and logical length;
- authenticated ordered ownership binding between metadata entry and manifest.

`verifyWholeFile` is the explicit end-to-end verification operation. It walks the authenticated manifest order, authenticates every chunk, checks every chunk length, feeds plaintext incrementally into SHA-256, and compares the result with the encrypted manifest digest. It does not assemble the complete file in memory.

## Corruption behavior

A corrupted untouched chunk does not prevent a bounded range that does not intersect it from being served, because that chunk is not opened. Explicit whole-file verification will detect the corruption.

A touched chunk with damaged ciphertext, a wrong key, wrong opaque filename, wrong private role, or wrong logical length fails closed before its bytes are returned.

A manifest whose ID, total length, or ordered chunk ownership does not match the authenticated metadata entry is rejected before chunk reads.

## Remaining work

Before chunked files are exposed through the production v2 session/Finder path:

1. bind this reader directly to `V2VaultSessionStore` so callers provide only an authenticated entry UUID rather than a `V2AccessEntry` value;
2. add handle-style session semantics for repeated bounded reads without exposing master keys or pool names;
3. stream large-file imports from source file handles instead of accepting a complete large `Data` value;
4. implement authenticated multi-object removal for manifest + chunks;
5. add physical encrypted-byte accounting and fault injection;
6. test reopen/corruption behavior across the complete session path;
7. complete host metadata leakage mitigations and security review before enabling v2 by default.

Existing v1 behavior remains unchanged.
