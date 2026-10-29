# V2 Physical Capacity Guard

## Purpose

`V2StorageBudget` and `V2LogicalUsageLedger` remain authenticated **logical** accounting. They prevent an access path from admitting more logical file bytes than its encrypted policy allows, but logical accounting alone does not preserve real free space on the host volume.

`V2PhysicalCapacityGuard` adds a separate conservative host-volume admission check before v2 ciphertext/staging writes.

For an ordinary control-plane metadata write, the guard requires at least:

```
physical staging bytes + reserveBytes + safetyMarginBytes
```

For a data or manifest object write, it additionally preserves one maximum v2 object envelope of control-plane headroom. This keeps enough bounded free space for the authenticated metadata transition that must follow a successful object write:

```
physical object bytes
+ reserveBytes
+ safetyMarginBytes
+ controlPlaneHeadroomBytes
```

All arithmetic is overflow checked.

## What is charged

Admission uses the **padded ciphertext envelope size**, not the logical file length. A 1-byte logical object placed in a 4 KiB plaintext bucket therefore consumes the 4 KiB bucket plus the fixed public envelope overhead for physical admission.

Large files are checked once per canonical encrypted chunk. The encrypted manifest is checked independently before creation. Capacity is re-read for each physical object, so already-written chunks reduce the available value seen by later checks.

Authenticated metadata anchor creation/replacement is also checked before its same-directory staging write. Replacement temporarily coexists with the committed anchor, so the complete new sealed anchor is charged.

## Low-space authenticated removal exception

Ordinary reserve-preserving admission can become counterproductive after **external** disk pressure. For example, APFS snapshots or another process may consume free space until less than `reserveBytes` remains. If every metadata replacement still required the full reserve at that point, the vault could be unable to record a pending deletion and therefore unable to delete its own authenticated ciphertext to recover space.

The v2 metadata store therefore has one internal low-space exception for **exact authenticated removal transitions only**.

The store does not trust a caller-provided recovery boolean. Before using the exception it reconstructs the requested transition from authenticated current metadata and accepts only one of these exact state changes:

1. one live entry becomes one matching pending-removal record through `beginningRemoval` or `beginningChunkedRemoval`; or
2. one existing pending-removal record is removed through `finalizingRemoval`.

An import, ownership expansion, filename change, budget change, unrelated metadata mutation, or arbitrary caller-selected pool object does not qualify.

For an accepted space-releasing metadata transition the physical admission requirement is intentionally narrower:

```
physical metadata staging bytes
```

The transition may therefore temporarily use free space that the ordinary policy would have kept inside `reserveBytes` / `safetyMarginBytes`. This is deliberate: the exception exists so authenticated deletion can release physical storage after the ordinary reserve boundary has already been crossed by external pressure. It is **not** a promise that the reserve remains untouched under that condition.

If even the complete metadata staging ciphertext cannot fit, removal still fails closed before physical deletion starts. This preserves the crash-recovery invariant that destructive deletion never begins before its authenticated recovery description is committed.

## Role neutrality

The ordinary guard consumes only `V2StorageBudget.reserveBytes` and `safetyMarginBytes`. Those field names do not encode visible, concealed, hidden, or decoy semantics and remain stored only inside authenticated encrypted metadata.

The low-space removal exception is also role-neutral. It is selected from the authenticated transition shape, not from access role, filenames, object counts, or a public layout marker.

The caller that provisions a dual-access vault chooses the encrypted budget for each access path. The physical guard does not infer an access role from public state.

## Failure behavior

The guard fails closed when:

- host-volume available capacity cannot be measured;
- required-capacity arithmetic overflows;
- a padding target cannot represent a valid v2 sealed envelope;
- measured available capacity is below the applicable admission boundary.

A failed data admission occurs after an authenticated pending ownership claim but before that object is created. The single-object path best-effort aborts that missing-object claim immediately; normal recovery can also abort it later. Chunk recovery similarly rolls back authenticated partial chunks when no manifest reached the publish boundary.

A low-space removal admission fails before any owned data object is deleted if the replacement metadata ciphertext itself cannot fit.

## Security boundary and limitations

This is **not** a hard physical allocator, partition, preallocated hidden container, or guarantee of plausible deniability.

The capacity check is a check-before-write guard. Another process, APFS snapshot activity, Time Machine, cloud/versioning behavior, filesystem metadata, or a hostile OS can consume free space after the check. The subsequent filesystem write must still fail closed on `ENOSPC` or any other I/O failure.

This guard also does not solve forensic allocation-history leakage, SSD TRIM behavior, APFS snapshots, swap, crash logs, thumbnails, or cloud version history. Those remain separate threat-model work before production Hidden/Decoy claims.

## Current integration

The guard is applied to:

- initial authenticated v2 metadata anchors;
- ordinary authenticated metadata generation replacement staging;
- bounded single-object ownership imports;
- every chunk in a chunked import;
- encrypted chunk manifests, including recovery-time manifest creation;
- exact authenticated pending-removal creation/finalization through the narrower low-space removal admission.

Unknown shared-pool objects remain outside deletion authority and are never scanned as garbage.

Hidden/Decoy creation UI remains disabled. Recovery-key semantics and broader filesystem/forensic hardening remain required before the feature is described as production-ready.
