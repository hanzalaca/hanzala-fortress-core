# Hanzalaomator v2 Access Envelope Identity Binding

Status: disabled v2 storage foundation. This does not enable Hidden/Decoy in the production UI.

## Problem

`vault.hanzala` intentionally contains a small amount of public routing/bootstrap metadata, including the v2 `vaultID`. Earlier v2 foundation password slots encrypted only the access role and master key. That meant editing the public `vaultID` could leave password unwrap apparently successful even though recovery-anchor namespace derivation would now use a different vault identity.

A public identifier that affects private object lookup must not be silently mutable across successful authentication.

## Slot payload revision 2

Every password slot now wraps an internal payload containing:

- encrypted payload revision `2`;
- encrypted access role;
- the canonical 36-byte lowercase UUID string for the same public `vaultID`;
- the 32-byte access master key.

The password KDF/wrapping layer therefore authenticates the vault identity together with the access capability.

The public envelope itself still carries `formatVersion = 2`. This change does **not** introduce a new public storage-format router version. Instead, the private slot payload revision changes from 1 to 2 while v2 remains disabled and unreleased as a production storage format.

There is deliberately no compatibility path that accepts the earlier internal slot-payload revision 1. Carrying an unauthenticated-vault-ID compatibility path forward would preserve the integrity weakness this change removes.

## Unlock behavior

`DualAccessEnvelopeEngine.unlock` still attempts every public slot before returning. For every slot whose password unwrap succeeds, the engine additionally requires the encrypted embedded vault UUID to equal the public envelope UUID.

If the public UUID was changed, the attempt is discarded exactly like a wrong password, damaged slot, or malformed encrypted payload. If no single valid match remains, the caller receives the existing generic:

`invalidPasswordOrCorruptedEnvelope`

This keeps the fixed two-slot attempt pattern and does not introduce a separate public error that identifies vault-ID tampering.

## Recovery interaction

V2 recovery anchors are derived from an HZRK recovery secret plus the public vault UUID. Binding password slots to that UUID prevents normal password unlock from silently accepting a header identity that would redirect recovery-anchor lookup.

Recovery itself remains fail-closed if the public vault UUID is corrupted: the supplied HZRK derives a different candidate anchor name and recovery returns its existing generic invalid/corrupt failure. Recovery does not scan the shared pool trying alternate identities.

Bootstrap integration tests rewrite a correctly encoded envelope with a different UUID while leaving the encrypted slots and pool untouched. They require:

- both valid password paths to fail with the generic password/corruption result;
- recovery to fail with the generic recovery/corruption result;
- no shared-pool mutation during either failure;
- restoring the original envelope to restore recovery.

## Public shape

The encrypted UUID adds the same fixed 36 bytes to every password-slot plaintext. Visible-only and dual-access vaults still have:

- exactly two public slots;
- equal wrapped-payload length vectors;
- no public slot role or enabled-state marker.

The UUID itself was already public, so authenticating a copy inside each password-protected payload does not add a new public role signal.

## What is not bound here

`createdAt` remains public descriptive metadata and is not copied into the encrypted slot payload. It is not currently used to derive metadata/recovery namespaces or select an access capability, so this stage does not make it security-critical.

Accordingly, this change must **not** be described as authenticating every byte of `vault.hanzala`. It specifically binds the security-relevant public vault identity to each password-protected access slot.

A future format can bind additional public fields if they gain security semantics.

## Remaining threat boundary

This does not address APFS snapshots, Time Machine/cloud version history, timestamps as forensic evidence, Spotlight, recent-items databases, thumbnails, swap, crash logs, SSD/TRIM artifacts, hostile cross-process filesystem races, or later access-pattern analysis. It also does not make it possible to prove that no second access path exists.
