# v2 password change

A v2 password protects one copy of the vault's master key inside the public
envelope (`vault.hanzala`). Changing the password re-wraps that copy; the master
key itself never changes. Encrypted files, metadata anchors and recovery anchors
are therefore untouched, and the Recovery Key keeps working.

## What is rewritten

- Only slot 0, the visible slot. Bootstrap always writes the visible slot first.
- The new slot gets a fresh Argon2id salt and a fresh XChaCha20-Poly1305 nonce,
  with the default KDF parameters.
- Slot 1 is copied byte for byte. In a visible-only vault it is the dummy slot;
  in a dual-access vault it is the concealed slot. Either way it never changes
  on a visible password change, so comparing old and new envelopes reveals
  nothing about it.
- `vaultID` and `createdAt` stay the same.

Before anything is written, the new envelope is unlocked in memory with the new
password. It must give exactly the same master key on the visible role. A new
password that would also open the second slot fails as `ambiguousPassword`.

## Who may change it

- An open visible session, whether it was opened with the password or with the
  Recovery Key. That makes the recovery flow on both apps: open with the HZRK
  key, then choose a new password.
- A concealed session is refused (`passwordChangeUnavailable`). Hidden/Decoy is
  not in V1.
- The session's master key must authenticate this vault's metadata anchor
  through the same retained root descriptor that read the envelope.

## Publication

A session whose envelope binding is already stale (another session changed the
password first) fails before any work with `envelopeIdentityChanged`.
`V2VaultBootstrapStore.replaceVisiblePassword` then compares the envelope on
disk with the session's binding twice: before deriving the new slot, and again
just before publishing. A change that lands in between fails with
`envelopeChangedDuringPasswordChange` and changes nothing.

The new envelope is staged in the vault root, synchronized, and swapped in
atomically (`V2DurableFileCommitter.replaceExisting`). A crash leaves either the
old envelope or the new one, each fully valid on its own. The written envelope is
read back and compared before success is reported.

Limitation: the swap is path based, not descriptor bound. The root path is
checked against the retained root right before the swap, but a hostile process
could still rebind the root in the narrow window that remains. This matches the
existing threat model, which does not claim a filesystem-wide transactional root.

The second check and the swap are not one atomic step, and no file lock is
taken across processes. Two processes changing the same vault at the same instant could both
pass the check; the later swap wins. The other writer's new password then does
not open the vault and its session fails closed on the next operation. One app
instance per vault is the supported use.

## Session effects

`V2VaultSessionLifecycle.changePassword(to:)` swaps the active session for one
bound to the new envelope, so the open vault keeps working. Finder leases are
bound to the old envelope, so they are revoked; the Mac app mounts Finder again.
Any other session still bound to the old envelope (another app instance) fails
closed with `envelopeIdentityChanged` on its next operation.

If `lock()` runs while the new password is being derived, the new password is
already saved and the lifecycle throws `lockedAfterPasswordChange`. The same
happens when the swap may have been published but could not be confirmed
(`passwordChangeOutcomeUncertain`): the lifecycle locks instead of reporting a
plain failure, so nobody keeps using a password that no longer works. The apps
say so plainly: open the vault with the new password.

One change runs at a time per lifecycle (`passwordChangeInProgress`), so two
changes from the same app cannot race each other. Every other failure is shown
with one generic message; the reason (for example that the new password would
also open the second slot) is not revealed.

On the iPhone, a password saved for Face ID is replaced with the new one; if
that fails, Face ID unlock is turned off.

Tests: `V2PasswordChangeTests`, and the password-change cases in
`MobileVaultModelTests`.
