# Hanzalaomator v2 integrated access session

Status: integrated storage foundation only. Production v2 vault mutation and UI remain disabled.

## Purpose

`V2VaultSessionStore` is the first capability-style API that connects the already-reviewed v2 pieces behind one unlocked access session:

- symmetric v2 bootstrap and password-selected access;
- authenticated encrypted per-access metadata;
- opaque name-bound pool objects;
- authenticated import ownership transactions;
- authenticated removal transactions;
- crash recovery;
- centralized data-object padding buckets.

Visible and concealed access paths use the same session implementation. The role selected by the password does not choose a different storage backend or public layout.

## Session capability

A `V2VaultSession` pins:

- vault root;
- public vault UUID;
- authenticated access UUID;
- in-memory access role;
- the unlocked master key internally;
- a canonical binding of the exact public access envelope internally.

The raw master key and envelope binding are not public API fields.

After opening a session, callers use authenticated entry UUIDs. They do not provide raw pool object names or raw master keys for reads or deletes.

## Envelope and access identity pinning

Before session operations, the store:

1. re-reads the bounded regular-file v2 public envelope;
2. canonicalizes it with the same sorted-key/ISO-8601 representation;
3. requires it to match the envelope bound when the session opened;
4. reads the deterministic encrypted metadata anchor using the session master key;
5. requires the authenticated metadata `accessID` to match the session's pinned access identity.

This catches accidental or hostile replacement of the public envelope while a session is active and also rejects a valid same-key metadata anchor from a different access identity.

This is not a claim of full hostile-filesystem race resistance. Descriptor-relative POSIX operations and stronger file-identity checks remain separate work.

## Open and crash recovery

`openSession` first unlocks exactly one password-selected access path through `V2VaultBootstrapStore`. It does not scan the shared pool for other access paths.

Before returning a usable session it runs:

1. authenticated pending-import recovery;
2. authenticated pending-removal recovery;
3. a final envelope/access-identity validation.

If a pending object is malformed, wrong-key, wrong-kind, wrong-length, symlinked, oversized, or otherwise unsafe, recovery fails closed and no usable session is returned.

Ordinary import/removal mutations are also blocked if authenticated pending work exists later in the same session. The caller must recover it first.

## Read path

To read an entry the caller provides only a live entry UUID.

The session store:

1. authenticates current metadata;
2. resolves the UUID to the authenticated opaque object name and logical length;
3. reads exactly that object;
4. authenticates XChaCha20-Poly1305 including the opaque filename binding;
5. requires private object role `.data`;
6. requires decrypted logical length to match authenticated metadata.

The store does not scan unknown pool objects.

## Import path

The session API does not accept a caller-selected ciphertext size. `V2DataObjectPaddingPolicy` selects a common authenticated plaintext bucket:

- 4 KiB
- 16 KiB
- 64 KiB
- 256 KiB
- 1 MiB
- 4 MiB
- 16 MiB

The encrypted private payload header is included when choosing the bucket.

Single objects remain bounded by `V2PoolObjectCodec.maximumPlaintextByteCount`. Larger files are deliberately rejected until the separate chunked-file format is implemented. They are not silently written using an unreviewed fallback.

The selected target then flows through the existing pending-claim -> immutable encrypted object -> live-metadata transaction.

## Removal path

The caller supplies only an authenticated live entry UUID. The existing removal coordinator derives the opaque name and length from authenticated metadata, commits the pending-removal tombstone first, authenticates the exact name-bound object, deletes it, and finalizes metadata.

An unlocked ordinary/decoy session still has no authority to delete pool objects that are unknown to its authenticated metadata.

## Remaining security work

This stage does not enable production v2 UI or claim complete plausible deniability. Remaining work includes:

- chunked authenticated storage for files larger than one pool object;
- stronger crash/power-loss testing across complete session operations;
- descriptor-relative filesystem operations and race review;
- physical allocation accounting beyond logical budget enforcement;
- recovery-key semantics that do not expose concealed-mode existence;
- host metadata treatment for APFS snapshots, Time Machine, Spotlight, thumbnails, swap, crash logs, iCloud/version history, SSD/TRIM behavior, and similar surfaces;
- focused fuzzing and external security review;
- version-selection/migration design before any v1 vault is changed.

Existing v1 vault behavior remains unchanged.