# Hanzalaomator v2 Durable Commit Hardening

Status: durability foundation. This is **not** a claim that sudden power loss is fully solved on every filesystem or device.

## Problem

The v2 storage foundation already used same-directory staging followed by move/replace, but the staged bytes were not explicitly forced through the storage stack before the namespace commit. A process crash was handled by transactional metadata rules, while sudden machine power loss could still leave a larger durability window.

## Commit ordering

`V2DurableFileCommitter` now provides one role-neutral ordering primitive:

1. create a random same-directory staging file with mode `0600`;
2. write the complete ciphertext/envelope bytes;
3. call `FileHandle.synchronize()`;
4. on Darwin, request `F_FULLFSYNC` when supported by the backing filesystem;
5. close the staging descriptor;
6. only then move a new file or replace an existing file;
7. best-effort sync the parent directory after the namespace mutation.

If a filesystem rejects `F_FULLFSYNC` with `EINVAL` or `ENOTSUP`, the mandatory ordinary synchronization remains the durability floor. Other synchronization failures abort **before** the final move/replace.

Parent-directory synchronization is deliberately best-effort. A failure occurs after the rename/replace may already have committed; throwing a normal pre-commit-style error at that point would create ambiguous transaction semantics. This is documented as a remaining limitation rather than hidden behind a false guarantee.

## Integrated v2 writers

The helper is used by:

- immutable `V2PoolObjectStore` object creation, covering ordinary data, chunks, manifests, recovery anchors, and generic pool objects;
- `V2AccessMetadataStore` initial anchors and authenticated metadata generation replacements;
- `V2VaultBootstrapStore` final public access-envelope publication.

Immutable pool writes still use no-replacement semantics. A racing destination is preserved and reported as a collision.

Metadata replacement still occurs only after authenticated generation/staleness checks and physical-capacity admission. The new staging file must synchronize successfully before `replaceItemAt` is attempted.

Bootstrap still publishes `vault.hanzala` last, after the encrypted metadata and recovery anchors are created. The envelope staging file is now synchronized before its final move.

## Fail-closed tests

The durable-committer tests require that:

- a new destination receives exactly the staged bytes and no staging file remains;
- an existing immutable destination is never replaced;
- injected sync failure publishes no new destination;
- injected sync failure preserves an old metadata-style destination;
- successful replacement happens only after the synchronizer completes;
- replacement never silently creates a missing destination.

The existing v2 integration tests continue to cover authenticated object, metadata, bootstrap, session, Finder, and recovery behavior through these updated writers.

## Remaining power-loss work

This stage narrows the durability window but does not prove atomic recovery from every crash point. Remaining work includes:

- fault-injection tests around every bootstrap and metadata commit boundary;
- validation on APFS and supported external-volume filesystems;
- explicit handling/recovery for incomplete initial bootstrap layouts after hard power loss;
- review of directory-entry persistence guarantees by filesystem;
- deletion durability and transaction recovery after sudden power loss;
- hostile cross-process filesystem race hardening.

No plaintext bootstrap journal is introduced, and no filename or public marker identifies visible, concealed, dummy, or recovery roles.
