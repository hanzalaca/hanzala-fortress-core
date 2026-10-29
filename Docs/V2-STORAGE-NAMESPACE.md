# Hanzalaomator v2 Storage Namespace

Status: foundation only. No v2 write path is enabled by this change.

## Purpose

After a v2 access slot is unlocked, its 32-byte master key must locate that access path's encrypted metadata without a public filename such as `hidden-index`, `decoy-index`, or `primary-index`.

`V2StorageNamespaceLocator` derives a namespace key with HKDF-SHA256 using the existing domain-key framework and the new purpose `hanzala/namespace/v2`. It then computes an HMAC-SHA256 over a fixed internal index-anchor label. The lowercase hexadecimal result is used as the opaque index-object filename.

Different master keys therefore derive different metadata anchors while the public object pool contains no role name.

## Public layout

The v2 foundation deliberately reuses the existing generic names:

- access envelope: `vault.hanzala`
- shared pool: `objects/`

There is no public `hidden/`, `concealed/`, or `decoy/` directory.

## Capacity reservation / overwrite protection foundation

`V2StorageBudget` adds a role-neutral encrypted capacity policy for an unlocked access path. It uses only generic fields such as `totalBytes`, `reserveBytes`, and `safetyMarginBytes`; no serialized field name reveals whether reserved capacity is intended for concealed data, padding, recovery headroom, or another internal purpose.

The visible/ordinary writer must run admission control **before** creating or extending an object. The maximum visible logical usage is:

`totalBytes - reserveBytes - safetyMarginBytes`

Any write that would cross that boundary is rejected before disk mutation. Arithmetic is overflow-checked.

`V2LogicalUsageLedger` tracks only the unlocked access path's logical byte usage and object count. It is intended to live inside authenticated encrypted metadata and must not be written into plaintext public metadata.

For a dual-access vault, `HiddenVaultCapacityPlan.v2StorageBudget()` converts the approved hidden-capacity plan into this generic reserve model. The resulting reserve value must remain encrypted at rest.

This protects a reserved capacity budget without requiring the ordinary access path to enumerate or understand concealed objects. It also avoids defining a stable public hidden offset. This is an admission-control foundation, not yet a complete physical allocator.

## Important limitation

Capacity reservation prevents the ordinary writer from consuming the reserved quota, but a filesystem-level implementation must still ensure that maintenance operations, cleanup, compaction, repair, and garbage collection never delete opaque objects merely because the ordinary index does not reference them. Unreferenced-from-this-access-path must **not** mean safe-to-delete.

A production v2 pool therefore needs conservative garbage collection or an authenticated cross-access ownership mechanism that does not disclose concealed state to the ordinary path.

## Security boundary

The namespace and capacity policy solve only part of the storage problem. They do **not** make the object pool plausibly deniable by themselves.

Before v2 storage can be enabled, later work must address:

- a common authenticated pool-object format so index/data/padding roles are not exposed by a cleartext type marker;
- object-size and timestamp leakage;
- physical allocation and garbage-collection safety;
- crash/rollback behavior;
- cover/padding policy if strong deniability is a product goal;
- APFS snapshots, Time Machine, Spotlight, thumbnails, recent-item databases, swap/crash logs, iCloud history, and SSD/TRIM behavior.

## Compatibility

The current v1 `VaultStore`, `VaultHeader`, `index.hanzala`, and existing vaults are not modified by this namespace/capacity foundation. A future v2 store must be separately versioned and explicitly selected; no automatic in-place migration is allowed without a tested rollback path.
