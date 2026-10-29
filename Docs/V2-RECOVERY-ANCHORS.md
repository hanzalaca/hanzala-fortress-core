# Hanzalaomator v2 Recovery Anchors

Status: disabled v2 foundation. This design is not exposed as production Hidden/Decoy UI and is not a claim of complete plausible deniability.

## Goal

Recovery must not add a public disk marker that tells an observer whether a second user-accessible path exists. The v2 design therefore does not put a recovery flag, recovery KDF, recovery role, or hidden/visible label in `vault.hanzala`.

Instead, every v2 bootstrap creates two encrypted recovery anchors inside the same generic `objects/` pool, regardless of whether the second password slot is real or dummy.

## Recovery secret

Each recovery credential is an independently generated 256-bit random secret displayed in the existing human-copyable `HZRK-....` format.

The displayed secret is not persisted in the vault. Internally the HZRK text is normalized back to the original 32 random bytes. Those bytes are domain-separated for recovery-namespace derivation and are also supplied as the key input to the existing HZOBJ003 pool-object codec.

## Anchor location

A recovery attempt derives exactly one 64-character lowercase hexadecimal filename:

1. HKDF-SHA256 derives `hanzala/recovery-namespace/v2` from the 32-byte recovery secret.
2. HMAC-SHA256 authenticates the fixed recovery-anchor label plus the public vault UUID.
3. The HMAC bytes become the opaque pool filename.

Including the vault UUID means accidental recovery-secret reuse across two vaults still produces different anchor names.

The recovery path never scans the shared pool looking for objects that might decrypt.

## Encrypted recovery payload

The recovery anchor uses the existing generic `HZOBJ003` envelope and encrypted object kind `recovery`. The kind is inside authenticated ciphertext and is not public.

The encrypted payload contains:

- payload format version;
- vault UUID;
- access UUID;
- access role;
- 32-byte access master key.

The object is padded to a fixed 4 KiB plaintext target. HZOBJ003 also binds the ciphertext to its exact opaque filename through AEAD associated data, so copying a valid recovery ciphertext to another derived anchor name does not rebind it.

## Visible-only symmetry

Visible-only bootstrap generates two recovery secrets:

- the first protects the real visible access path and its HZRK key is returned to the caller;
- the second protects the dummy second access path and its HZRK key is discarded after its anchor is created.

No persistent reference to the dummy recovery secret is intentionally retained.

## Dual-access symmetry

Dual-access bootstrap also generates exactly two recovery secrets. One recovers the visible access path and one recovers the concealed access path. Their recovery anchors have the same public envelope format and padding target used by visible-only bootstrap.

Thus both modes begin with the same four generic pool objects: two metadata anchors plus two recovery anchors.

## Recovery authentication chain

A successful `openRecoveryAccess` requires two independent authenticated steps:

1. the HZRK secret must locate and authenticate its exact recovery anchor, yielding a master key and encrypted access UUID;
2. that master key must locate and authenticate its normal metadata anchor, and the metadata access UUID must equal the recovery payload's access UUID.

A recovery ciphertext therefore cannot silently redirect to an unrelated authenticated metadata path without satisfying both bindings.

## Failure behavior

At the recovery API boundary, these cases intentionally collapse to `invalidRecoveryKeyOrCorruptedAnchor`:

- malformed HZRK text;
- candidate anchor absent;
- wrong-key AEAD failure;
- malformed or oversized pool object;
- wrong encrypted object kind;
- malformed encrypted payload;
- vault UUID mismatch;
- invalid role/master-key payload;
- recovered metadata missing, corrupted, or carrying a different access UUID.

The goal is not to expose which stage of a recovery-key probe failed.

## Capacity and rollback

Recovery anchors are checked by the v2 physical-capacity guard before creation using their padded ciphertext-envelope size plus the encrypted access budget's normal reserve and safety margin.

Bootstrap derives all metadata and recovery anchor names before mutation and rejects collisions. In-process rollback removes only exact anchors whose successful creation was recorded. It never scans or recursively cleans the pool.

## Non-claims and remaining work

This mechanism does not solve:

- secure UI/storage workflow for showing, printing, exporting, rotating, or revoking recovery keys;
- recovery-key exposure through screenshots, clipboard history, logs, backups, or user mistakes;
- APFS snapshots, Time Machine/cloud history, timestamps, Spotlight, thumbnails, swap, crash logs, SSD/TRIM artifacts, or hostile filesystem races;
- hard power-loss recovery of an interrupted first bootstrap;
- proving that no additional access path exists.

Recovery UI remains disabled until those surrounding semantics are reviewed together with the broader Hidden/Decoy threat model.
