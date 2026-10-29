# V2 descriptor-bound envelope publication

This stage hardens publication of the public `vault.hanzala` envelope during v2 bootstrap on macOS.

## Root identity

After the new vault root and shared `objects` directory are created, bootstrap captures the root filesystem identity. Private metadata and recovery anchors are then created and authenticated before any public envelope is published.

Immediately before envelope publication, the public root path must still resolve to that captured directory identity.

## Descriptor-relative publication

The envelope publisher opens the root with `O_NOFOLLOW | O_DIRECTORY`, verifies that its `fstat` identity matches the captured bootstrap identity, and then delegates to the existing descriptor-relative durable writer.

The envelope staging entry is therefore created relative to the retained root descriptor, written with mode 0600, synchronized, and published with `RENAME_EXCL` only if the public root path still resolves to the captured root.

A replacement root directory cannot redirect the final write. If the root path changes before publication, the operation fails closed and the substituted path is not used for bootstrap cleanup.

## Bootstrap ordering

The four private initial objects (two authenticated metadata anchors and two encrypted recovery anchors) are verified before the public envelope is committed. This prevents a normal successful create result from publishing a header before its private foundation has authenticated.

## Failure and rollback boundary

When the captured root path is still intact, ordinary cooperative bootstrap failures retain the existing exact-name cleanup behavior. If the root pathname no longer refers to the captured directory, pathname-based cleanup is skipped rather than risking deletion in an unrelated replacement directory.

Deterministic simulated power-loss exceptions also bypass cooperative cleanup because a real dead process could not execute rollback code.

This can leave encrypted orphan bootstrap state in a displaced original directory. That is deliberate fail-closed behavior; deleting unrelated data is worse than leaving unreachable ciphertext.

## Remaining boundary

This does not make bootstrap a full filesystem transaction. In particular:

- ancestor pathname traversal before the root descriptor is opened is not yet represented by a retained parent-chain capability;
- private anchor stores still open the root independently during bootstrap;
- a hostile process may attempt namespace changes in very small intervals around identity checks;
- a compromised kernel or storage firmware is outside this boundary;
- APFS snapshots, Time Machine/cloud history, swap/crash artifacts, and SSD/TRIM metadata are separate host-leakage surfaces.

Hidden/Decoy UI remains disabled and v1 is unchanged.
