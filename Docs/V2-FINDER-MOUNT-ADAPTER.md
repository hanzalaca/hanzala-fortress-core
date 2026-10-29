# V2 Finder Mount Adapter

This stage adds an explicit app-side mount adapter for an already-open v2 access session while keeping the production v1 path unchanged.

## Explicit selection only

`FinderMountCoordinator` has two separate entry points:

- `mount(vault:)` for the existing v1 `OpenedVault` path;
- `mount(v2FinderLease:)` for a lifecycle-owned v2 read-only Finder capability.

The coordinator does not inspect a vault and guess its format, does not migrate v1 data, and does not select v2 merely because a second password or hidden-capacity concept exists.

The v2 path no longer accepts a raw `V2VaultSession` plus `V2VaultSessionStore`. Instead, `V2VaultSessionLifecycle` privately owns the unlocked cryptographic session and issues a tracked `FinderLease`. This narrows the app/Finder integration boundary: the mount coordinator receives only the root URL and an already-bound `V2FinderReadOnlySession`.

## Shared keyless transport

Both v1 and v2 converge only after the app has constructed a storage-specific read-only session. They then use the same `FinderSessionRPC` and `FinderSessionPublishedServer` boundary.

The FSKit side therefore remains storage-format neutral and does not receive:

- passwords;
- master keys;
- v2 metadata anchors;
- manifest or chunk names;
- pool-object names;
- plaintext backing paths.

The existing code-signature peer authorizer remains mandatory before the published server accepts Finder traffic.

## Fail-closed unmount ordering

The coordinator revokes/stops the published Finder server **before** invoking `umount(8)`.

This ordering applies both to normal Lock/unmount and mount-setup failure cleanup. It prevents a busy or delayed filesystem unmount from leaving a window where new decrypted ranges can still be requested.

For v1, server invalidation also clears active plaintext leases. For v2, the lifecycle additionally tracks every issued Finder session and invalidates it on lock, independently of the macOS unmount result.

## Status

The v2 Finder transport and end-to-end AF_UNIX coverage are now in `main`, and the app-session lifecycle foundation is being added on top. Production v2/Hidden UI remains disabled.

Next work:

1. wire `V2VaultSessionLifecycle` into `VaultAppState` behind an explicit v2 format gate;
2. keep the locked UI generic so it never exposes whether the password opened a visible or concealed access path;
3. make app termination, sleep/session-resign, backing-volume loss, and failed unmount all call the same lifecycle lock path;
4. only after those lifecycle paths are tested, enable v2 creation/opening in the production UI.
