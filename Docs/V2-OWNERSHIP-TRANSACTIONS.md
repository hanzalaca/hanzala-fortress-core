# Hanzalaomator v2 Authenticated Ownership Transactions

Status: import/crash-recovery foundation only. The production v2 vault mutation path remains disabled.

## Security problem

A shared object pool cannot safely use “present in my index” as the only proof of ownership. If an access path were allowed to add any existing opaque pool filename to its encrypted metadata, it could later tombstone that name and authorize cleanup of an object belonging to another access path.

The v2 transaction protocol therefore establishes authenticated ownership **before** object creation.

## Import order

`V2OwnershipTransactionCoordinator.importData` performs these steps:

1. generate a fresh role-neutral 32-byte opaque object name;
2. confirm that the current authenticated metadata does not already own the name and that no pool object currently occupies it;
3. commit a `V2PendingImport` into authenticated encrypted metadata, incrementing its generation;
4. immutably create the encrypted data object at exactly the pre-claimed name, with no replacement semantics;
5. authenticate the new object and verify its logical length;
6. commit a second metadata generation that converts the pending claim into a live entry and updates the logical-usage ledger.

Padding is mandatory at the coordinator API. The final padding/allocation policy is still a separate stage.

## Crash states

The ordering gives bounded recovery states without a public plaintext journal:

- **crash before pending metadata commit:** no ownership state and no object were created;
- **pending claim exists, object missing:** recovery removes only the authenticated pending claim;
- **pending claim exists, authenticated object exists:** recovery verifies and finalizes the live entry;
- **pending claim exists, object is malformed/wrong-key/symlink/oversized/wrong-kind:** recovery fails closed and leaves the pending claim and object untouched;
- **live entry exists:** the import is complete.

Recovery never deletes an unverified object.

## Capacity reservation

Pending logical bytes count against the access path’s role-neutral storage budget before the object is created. This prevents multiple interrupted or concurrent pending imports from silently overcommitting the writable limit.

The live `V2LogicalUsageLedger` continues to count only finalized live objects; validation checks `live logical bytes + pending logical bytes` against the budget.

## Metadata generation control

`V2AccessMetadataStore.commitTransition` is internal and accepts only a one-generation transition with:

- unchanged private `accessID`;
- unchanged role-neutral storage budget;
- exact equality with the authenticated metadata version the caller read;
- next generation equal to current generation + 1.

A process-wide lock serializes metadata mutations across store instances in the main app process. This matches the architecture in which the main app owns keys and the FSKit side remains keyless. This mechanism is **not** claimed to defend against a hostile external process racing filesystem paths.

## No arbitrary ownership mutation API

There is still no public “replace metadata with this caller-supplied object list” API. The only new disk mutation path is the coordinator-controlled pending -> object -> live protocol. This keeps ownership derivation tied to a name that was pre-claimed by the authenticated access path before creation.

## Compatibility

`pendingImports` was added while v2 remains disabled for production. Metadata decoding treats a missing `pendingImports` field as an empty list so anchors created by the immediately preceding v2 foundation remain readable.

Existing v1 vaults and their write path remain unchanged.

## Remaining work before production v2 mutation

- authenticated tombstone/removal transactions and cleanup execution;
- physical capacity accounting and the final data-padding bucket policy;
- dummy/real second metadata-anchor provisioning so visible-only and dual-access setup are not distinguishable by an obvious anchor count;
- stronger analysis of hostile cross-process filesystem races and APFS behavior;
- rollback/snapshot/cloud-history threat documentation and tests;
- integration with the real v2 vault creation/open UI only after the storage state machine is complete.
