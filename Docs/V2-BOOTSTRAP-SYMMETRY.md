# Hanzalaomator v2 Bootstrap Symmetry

Status: disabled storage foundation only. This does not make plausible deniability production-ready and does not enable Hidden/Decoy in the application UI.

## Problem

A two-slot public access envelope is not sufficient if visible-only and dual-access vaults create visibly different storage layouts.

For example, if a visible-only vault created one encrypted metadata or recovery anchor while a dual-access vault created two, an observer could use the public object count as evidence that an additional access path exists even though the envelope itself has the same two-slot shape.

## Required public invariant

Every newly bootstrapped v2 vault creates:

- one generic `vault.hanzala` v2 access envelope with exactly two public password slots;
- one shared generic `objects/` pool;
- exactly two initial encrypted metadata anchors in that pool;
- exactly two encrypted recovery anchors in that pool;
- no v1 `index.hanzala`;
- no plaintext marker identifying any anchor as metadata, recovery, visible, concealed, real, dummy, enabled, or disabled.

All four anchors use the same generic `HZOBJ003` authenticated pool-object envelope. Metadata and recovery roles exist only inside authenticated ciphertext. Recovery anchors use a fixed 4 KiB plaintext padding target so visible-only and dual-access bootstrap expose the same recovery-object size shape.

## Visible-only bootstrap

`DualAccessEnvelopeEngine.createVisibleOnly` creates a second public slot protected by a random password that is never given to the user.

During bootstrap only, the engine retains that dummy slot's random master key long enough to create its matching encrypted metadata anchor. The bootstrap layer also generates two independent recovery secrets. The visible recovery key is returned to the caller; the dummy recovery secret is used once to create a matching recovery anchor and is then discarded.

The result is that a visible-only vault contains four initial encrypted pool objects: two metadata anchors and two recovery anchors. The second metadata/recovery pair is intentionally inaccessible after bootstrap and must be treated as unknown shared-pool data by conservative cleanup.

## Dual-access bootstrap

A dual-access vault creates the same four-object public shape. Each independently wrapped access master key receives:

- one deterministic metadata anchor derived from the access master key;
- one deterministic recovery anchor derived from its independent HZRK recovery secret and the public vault ID.

Both user passwords and both user recovery keys can later open only their own access path. Opening or recovering one access path does not enumerate or identify the other anchors.

## Password opening behavior

`V2VaultBootstrapStore.openAccess`:

1. reads and validates the bounded, regular, non-symlink v2 envelope;
2. attempts the fixed two-slot password unlock flow;
3. derives only the successful access path's opaque metadata anchor;
4. authenticates only that metadata object.

It does not scan `objects/` looking for another metadata anchor.

## Recovery opening behavior

`V2VaultBootstrapStore.openRecoveryAccess`:

1. reads the same public v2 envelope only to obtain and validate the vault identity;
2. normalizes the supplied HZRK recovery secret and reconstructs its original 32-byte random material;
3. derives exactly one opaque recovery-anchor name from that secret plus the public vault ID;
4. opens that one HZOBJ003 object under the recovery secret;
5. verifies the encrypted vault ID, access role, master key, and access ID;
6. derives the recovered master key's metadata anchor and requires its authenticated access ID to match before returning an opened foundation.

Malformed keys, missing anchors, authentication failures, wrong object kind, malformed payload, and vault-ID mismatch collapse to one generic recovery failure. The pool is never scanned.

## Public-shape tests

The bootstrap test suite requires visible-only and dual-access creation, when given equivalent initial budgets and the same public timestamp/UUID shape, to have:

- the same public password-slot count;
- the same envelope byte length;
- the same initial pool object count of four;
- the same sorted initial pool object size vector.

The serialized public envelope is also checked for absence of role/recovery markers such as `hidden`, `concealed`, `visible`, `role`, `enabled`, `recovery`, or `hzrk`.

This is a narrow bootstrap-shape invariant. It is not a claim that later usage patterns, timestamps, snapshots, backups, or physical allocation remain indistinguishable.

## Creation safety

Bootstrap refuses to reinterpret or overwrite any existing known Hanzalaomator layout component (`vault.hanzala`, `index.hanzala`, `objects/`, or `.journal`).

All four deterministic anchor names are derived before mutation and are required to be distinct. If an in-process creation step fails, rollback removes only exact anchors whose successful creation was recorded by that invocation. It never recursively deletes unknown shared-pool contents. A newly created `objects/` directory or root is removed only when empty.

A hard power loss can still leave an incomplete bootstrap layout. Full power-loss recovery is a later required stage; no plaintext bootstrap journal is introduced here because such a journal could itself create new observable state.

## Threat boundary and non-claims

This layer does not solve:

- APFS snapshots or clone history;
- Time Machine or cloud version history;
- filesystem creation/modification timestamps;
- Spotlight, recent-items databases, thumbnails, swap, or crash logs;
- SSD wear-leveling/TRIM artifacts;
- hostile external filesystem races;
- later traffic/usage analysis after one access path starts receiving files;
- secure user workflow for storing, printing, exporting, rotating, or revoking recovery keys.

The purpose of this stage is narrower: prevent the initial password/recovery bootstrap shape from creating an immediate deterministic visible-only-vs-dual-access fingerprint.
