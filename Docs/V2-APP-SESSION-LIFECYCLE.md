# V2 App Session Lifecycle

This stage introduces a memory-only application lifecycle owner for one unlocked v2 access path.

## Security boundary

`V2VaultSessionLifecycle` privately owns the active `V2VaultSession`. Application callers do not receive the raw v2 session or master key. They receive only:

- non-secret session identity (`root`, `vaultID`, `accessID`, role for internal unlocked-state use);
- authenticated entry operations routed through `V2VaultSessionStore`;
- tracked read-only Finder leases.

The locked UI must not display the access role. Password selection remains generic: the supplied password selects whichever authenticated slot it can unlock.

## Finder revocation

Each Finder capability issued by the lifecycle is tracked. `lock()`:

1. removes all tracked Finder leases from the lifecycle;
2. drops active/opening session state;
3. invalidates every previously issued `V2FinderReadOnlySession` before returning.

This gives the app a second fail-closed barrier in addition to stopping the AF_UNIX server. If `umount(8)` is delayed or fails, stale Finder handles still cannot request additional decrypted ranges.

## Concurrent open cancellation

Opening a v2 vault can spend time in Argon2id. The lifecycle marks each open attempt with a random attempt identifier. If `lock()` runs while an open is still deriving/unwrapping keys, the lifecycle changes back to the locked state. A late successful KDF result is discarded and returns `openCancelled`; it cannot silently reactivate the vault after a lock request.

## Scope and limitation

This stage does not claim that clearing a Swift `Data` reference securely erases every historical in-memory copy of key material. It reduces lifetime and reachability of the active session but does not replace OS/process memory-hardening work.

The strong immediate revocation guarantee in this stage applies to tracked Finder sessions. Other synchronous app operations should remain serialized through the app lifecycle/UI actor; future asynchronous mutation paths must add explicit cancellation/generation checks before they are allowed to run concurrently with lock.

## Production gate

The lifecycle is not yet wired into the normal create/open UI. Existing v1 behavior remains unchanged. v2 production UI should be enabled only after:

- the app state owns one lifecycle instance for the entire unlocked window;
- Lock, sleep/session resign, app termination, failed mount, and backing-volume loss converge on lifecycle revocation;
- Finder leases are released on normal unmount and invalidated on global lock;
- locked presentation stays identical regardless of visible-only versus dual-access vault setup.
