# Hanzalaomator v2 Shared Pool Cleanup Safety

Status: foundation only.

## Core rule

The currently unlocked access path must never interpret an object that is absent from its own encrypted index as garbage. In a dual-access vault, that object may belong to another access path.

`V2PoolCleanupPolicy` therefore fails closed:

- unknown to the current authenticated ownership set -> preserve;
- authenticated owned + live -> preserve;
- authenticated owned + explicitly tombstoned -> eligible for deletion;
- invalid opaque filename -> preserve.

A tombstone alone is not enough. Ownership and tombstone state must both come from authenticated encrypted metadata for the currently unlocked access path.

## Opaque names

`V2OpaqueObjectName` generates 32 random bytes encoded as 64 lowercase hexadecimal characters. Names contain no sequence, timestamp, original filename, or role. The validator also blocks traversal-style and non-opaque names before building an object URL.

## Why this matters

A normal garbage collector that scans `objects/` and deletes files not referenced by the ordinary index would destroy concealed data. The v2 pool must instead preserve anything the current access path cannot positively authenticate as its own deleted object.

## Remaining work

This policy does not yet physically delete files or prove cross-device synchronization safety. Production integration still needs atomic tombstone/index commits, crash recovery, rollback testing, and careful handling of cloud conflict copies and filesystem snapshots.
