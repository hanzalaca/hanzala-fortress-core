# V2 App State Gate

This stage prepares the normal macOS application to route an existing vault into the correct v1 or v2 backend without using credential success/failure as a format detector. Production v2/Hidden UI remains disabled.

## Public format routing

Both v1 and v2 intentionally use the same public `vault.hanzala` filename. `VaultFormatDetector` reads only the bounded public JSON `formatVersion` field and returns v1 or v2.

The detector:

- rejects a missing, symbolic-link, or non-regular header;
- caps the header read to 1 MiB before allocation;
- on macOS, opens the vault root and exact header with retained no-follow descriptors rather than validating one pathname and reopening it;
- rechecks the captured root device/inode identity before returning a routing result;
- rejects malformed and unsupported versions;
- never tries a password or recovery key;
- never falls back to another storage implementation after an authentication failure.

A replacement of the public header pathname after its descriptor has already been opened cannot retarget the bytes used for format detection. Rebinding the vault root during the routing read fails closed.

The detector is a routing hint only. `VaultStore` or `V2VaultBootstrapStore` must still repeat full parsing, authentication, KDF-resource, and filesystem validation. Descriptor-bound routing therefore does not turn format detection into an authentication boundary.

## V2 application bridge

`V2AppVaultBridge` wraps the shared `V2VaultSessionLifecycle` and exposes app-safe operations for exactly one authenticated access path.

The bridge does not expose:

- the raw `V2VaultSession`;
- the master key;
- metadata-anchor names;
- recovery-anchor names;
- manifest/chunk names;
- pool-object names.

For the existing SwiftUI file list it projects authenticated v2 entries into presentation-only `VaultEntry` values and deliberately leaves `opaqueObjectName` empty. Storage identifiers remain behind the lifecycle/session-store boundary.

Password open remains a single generic operation: there is no visible/concealed mode selector. The password selects whichever authenticated v2 slot it can open.

The bridge now also has a gated `openRecovery(at:recoveryKey:)` entry point. It first performs the same password-independent v2 format check and then delegates to the same memory-only lifecycle used by password open. A valid HZRK selects its authenticated access path without the app naming that path or receiving the recovered master key.

`openRecovery` is intentionally a backend/app-state capability only. It is **not** currently connected to a dedicated locked-screen button, visible/concealed selector, or production Hidden/Decoy recovery workflow.

After either password or recovery open, `openedIdentity` contains only non-secret session identity and every subsequent list/import/read/remove/Finder operation uses the same bridge methods.

## Finder mount race hardening

The mount coordinator tracks both an active mount-attempt identifier and the server created before `mount(8)` begins.

If Lock/unmount occurs while `mount(8)` or mount-table verification is suspended:

1. the in-flight server is stopped immediately;
2. the mount-attempt identifier is cancelled;
3. the suspended mount operation checks the identifier after each awaited tool call;
4. a late mount result is cleaned up instead of being published back to the UI.

This closes the window where an in-flight mount could otherwise finish after Lock and resurrect a Finder read path.

Recovery-opened sessions do not get a different Finder route. Once the bridge stores the recovered lifecycle identity, `mountFinder()` issues the same revocable keyless Finder lease used after password open.

## Sleep and process termination

`AutoLockGuard` synchronously revokes the shared v2 lifecycle before awaiting Finder unmount on sleep/display-sleep/session-resign.

It also observes normal AppKit termination and revokes the v2 lifecycle synchronously before process teardown. Finder unmount and temporary-plaintext cleanup remain defense-in-depth after capability revocation.

## Current production gate

New vaults are now created as **visible-only v2** vaults (`V2VaultBootstrapStore.createVisibleOnly`), the same format the iPhone app uses, so an encrypted vault folder can be copied between devices (owner decision, 2026-10-19). The recovery key is shown before the new vault is opened. Existing v1 vaults keep opening through `VaultStore`.

"Forgot password? Use Recovery Key" now opens a v2 vault with its HZRK through `openRecovery` (see `V2-RECOVERY-LIFECYCLE.md`). v2 password change is enabled for the visible access path (see `V2-PASSWORD-CHANGE.md`). This stage still does **not** enable Hidden/Decoy controls. The existing locked presentation does not gain a visible/concealed choice.

Before a recovery UI is enabled, the remaining UX work must preserve the same rule: the user supplies one generic HZRK credential and the credential determines the access path. The UI must not enumerate or reveal whether another recoverable access path exists.

Host metadata leakage, hostile filesystem races, and final security review remain separate production-readiness work.
