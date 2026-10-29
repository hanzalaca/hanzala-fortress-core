# Hanzalaomator Hidden Vault — Security Design Contract

Status: foundation only. This document does not claim that plausible deniability is production-ready.

## Goal

Add a future two-password vault mode in which one password opens an ordinary/decoy view and a different password opens a hidden view, without adding a visible locked-state indicator that a hidden view exists.

## Non-negotiable rules

1. **Do not invent cryptographic primitives.** Use reviewed primitives from maintained libraries.
2. **Authenticated encryption only.** Do not use AES-XTS by itself as the hidden-vault confidentiality/integrity mechanism.
3. **Independent access secrets.** Visible and hidden passwords must be distinct and must use independent KDF salts and independently wrapped key material.
4. **No fixed hidden ratio.** The file format must not assume that hidden capacity is always 20%, 30%, 40%, or any other constant percentage.
5. **No obvious hidden marker.** Do not add an on-disk filename, magic string, JSON field, UI badge, or other plaintext marker whose sole purpose reveals that hidden storage is enabled.
6. **Same locked unlock surface.** The locked application should present the same password entry flow regardless of whether the supplied password resolves to the visible or hidden view.
7. **Protect hidden capacity from visible writes.** Once hidden storage exists, a visible/decoy session must not allocate into or overwrite capacity reserved for hidden data.
8. **Do not overclaim deniability.** APFS snapshots, Time Machine, Spotlight, recent-items databases, thumbnails, swap, crash logs, iCloud version history, SSD/TRIM behavior, and other host metadata can weaken plausible deniability. These surfaces require explicit treatment before the feature is described as providing strong plausible deniability.
9. **Recovery behavior must be designed deliberately.** A recovery mechanism must not reveal hidden-mode existence from the visible side. Existing recovery-key behavior must not be silently reused for hidden mode without a separate review.
10. **Existing v1 vaults remain compatible.** Hidden-vault work must not mutate the current v1 layout until a versioned migration path and rollback strategy exist.

## Current foundation

`HiddenVaultPolicy.swift` provides:

- validation that visible and hidden passwords are both present and distinct;
- a capacity model with user-selected hidden size and optional protected reservation;
- an explicit contract that locked UI does not expose hidden state;
- an explicit contract that visible writes may not consume hidden reservation.

`DualAccessEnvelope.swift` now provides the first access-envelope implementation boundary:

- v2 always exposes exactly two generic public access slots;
- a visible-only v2 envelope still has two slots, with the second protected by a random password that is immediately discarded;
- a dual-access v2 envelope has the same public slot count and ciphertext sizes;
- each slot has an independent Argon2id salt and independently wrapped random master key material;
- the visible/concealed role exists only inside the authenticated encrypted slot payload, not as public JSON metadata;
- unlock attempts every slot before returning instead of early-returning on the first success, avoiding a simple slot-position timing signal;
- existing v1 `VaultHeader` and vault layout are untouched.

`PasswordKeyEngine.swift` also now:

- exposes a generic authenticated payload wrapper while preserving the existing v1 master-key API;
- rejects KDF parameters above libsodium's sensitive limits before attempting Argon2id, limiting resource-exhaustion risk from malicious serialized headers.

This stage intentionally does **not** add:

- hidden offsets;
- hidden object filenames;
- a fixed capacity percentage;
- migration of existing v1 vaults;
- production UI controls;
- automatic recovery behavior for concealed access;
- a claim that host-level metadata leakage has been solved.

## Why every v2 envelope has two slots

A public `hiddenEnabled` flag or an optional second slot would immediately reveal whether concealed access was configured. Therefore the v2 envelope has a fixed public shape. The second slot is either a real independently password-protected access path or an indistinguishable dummy slot created with an unretained random password.

This design only addresses the public envelope shape. It does not, by itself, make the storage pool or host operating system metadata deniable.

## Required next implementation stages

1. Connect the reviewed v2 envelope to a versioned storage namespace without changing v1 vaults.
2. Define authenticated random-access object/chunk storage for concealed mode. Existing secretstream remains valid for sequential object encryption but should not be forced into a random-access role it was not designed for.
3. Add capacity-allocation and overwrite-protection logic without exposing a stable hidden offset fingerprint.
4. Add corruption, wrong-password, rollback, and power-loss tests across the full v2 storage path.
5. Define recovery-key semantics for visible and concealed views without exposing concealed-mode existence from visible recovery metadata.
6. Add UI only after the storage format and tests are stable.
7. Run focused security review/fuzzing before enabling the feature by default.
