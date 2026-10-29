# Hanzalaomator v2 Recovery Lifecycle

Status: integrated core lifecycle foundation. Hidden/Decoy production UI remains disabled.

## Purpose

The v2 application lifecycle must not create a second, weaker session model for recovery. A valid HZRK recovery credential should resolve exactly one authenticated access path and then enter the same memory-only lifecycle used by password unlock.

`V2VaultSessionLifecycle.openRecovery(at:recoveryKey:)` therefore consumes `V2RecoverySessionCoordinator` and publishes only `V2VaultLifecycleOpenResult`.

The lifecycle never exposes:

- the recovered master key;
- opaque metadata, manifest, chunk, or recovery-anchor names;
- a visible/concealed mode selector;
- a second Finder implementation.

## Shared opening state machine

Password and recovery opens both use the same `performOpen` transition:

1. require the lifecycle to be locked;
2. enter one `opening(attemptID)` state;
3. perform the credential-specific authenticated open outside the lifecycle lock;
4. require the same attempt ID still to be active;
5. publish one standard `V2VaultSession` capability internally;
6. return only non-secret identity and authenticated crash-recovery report data.

If `lock()` runs while either credential path is opening, the later completion is discarded with `openCancelled` and cannot become the active session.

A failed recovery attempt returns the lifecycle to `locked`, allowing a later legitimate password or recovery attempt.

## Finder behavior

A recovery-opened session uses the existing `makeFinderLease()` path. Finder receives the same revocable `V2FinderReadOnlySession` capability as a password-opened session.

`lock()` invalidates every Finder lease before forgetting the active session. A recovery credential therefore does not widen the plaintext exposure window or grant Finder access to raw key material.

## Isolation tests

The lifecycle tests require that a concealed recovery key:

- opens the concealed authenticated access identity;
- cannot list a visible access entry;
- can read its own entry through the normal Finder lease;
- loses Finder readability immediately after lifecycle lock.

They also require a wrong recovery key to leave the lifecycle locked and permit a subsequent valid password retry.

## Non-claims

## Recovery UI

Both apps now expose one generic recovery control on the locked screen ("Forgot password? Use Recovery Key"): the Mac app routes a v2 vault to `V2AppVaultBridge.openRecovery`, the iPhone app to `V2VaultSessionLifecycle.openRecovery`. There is no visible/concealed choice, every recovery failure shows the same message, and the key is never stored. After a recovery open, both apps offer to set a new password (see `V2-PASSWORD-CHANGE.md`); cancelling keeps the old password.

This stage does not claim protection against:

- a fully compromised macOS kernel or Hanzalaomator process while unlocked;
- APFS snapshots or clone history;
- Time Machine or cloud version history;
- filesystem timestamps, Spotlight, thumbnails, recent-item databases, swap, or crash artifacts;
- SSD wear-leveling/TRIM artifacts;
- hostile external filesystem races;
- later traffic or usage-pattern analysis.

The goal is narrower: recovery now enters the same fail-closed in-memory capability lifecycle as password unlock without exposing hidden-mode controls or raw keys.
