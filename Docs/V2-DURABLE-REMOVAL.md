# V2 Durable Removal

This stage tightens the v2 authenticated removal transaction around filesystem namespace durability.

## Ordering

For an ordinary single-object entry:

1. the live entry is moved into encrypted authenticated `pendingRemovals` metadata;
2. the exact opaque object is opened and authenticated under the current access master key;
3. object kind and authenticated logical length are checked;
4. the exact object is unlinked;
5. the shared pool directory is synchronized;
6. only then is the encrypted pending-removal tombstone finalized.

Chunked entries preserve the existing rule that the encrypted manifest is deleted last. Each authenticated chunk deletion uses the same durable namespace rule.

## Ambiguous unlink handling

An unlink may succeed even if the following directory synchronization fails. In that case Hanzalaomator deliberately reports failure and leaves the authenticated removal tombstone pending.

On a later fresh open/recovery:

- if the exact authenticated object exists again, it is authenticated and deletion is retried;
- if the exact authenticated name is already absent, the pool directory is synchronized in the current boot before the tombstone is finalized.

This prevents the current process view of “file is missing” from being treated as sufficient proof that the namespace deletion is durable.

## Shared-pool safety

Recovery never enumerates the shared pool to discover garbage. The only names that may be deleted or durably confirmed absent are exact opaque names already carried by authenticated pending-removal metadata (and, for chunked files, the authenticated manifest ownership list).

Unknown pool objects remain preserved because they may belong to another access path.

## Limits

This is crash/power-loss hardening, not a guarantee of perfect storage transactions. Filesystem, controller, firmware, external-drive, network-filesystem, APFS snapshot, SSD/TRIM, and hostile-host behavior can differ. A fully compromised operating system remains outside this durability guarantee.

This stage does not enable Hidden/Decoy production UI and does not change v1.
