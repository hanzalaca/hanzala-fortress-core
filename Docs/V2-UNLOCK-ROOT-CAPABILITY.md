# V2 retained root capability during unlock

This stage closes the remaining root-path reopen window between the public `vault.hanzala` read and the private anchors needed to complete a v2 password or HZRK recovery open.

## One root capability per unlock

On macOS, `V2VaultBootstrapStore` now acquires one `V2RetainedVaultRoot` before reading the public envelope. The capability opens the selected vault root with `O_NOFOLLOW | O_DIRECTORY`, captures its device/inode identity, and retains that descriptor until the credential-selected private path has been resolved.

Password open uses that same retained root for:

1. the bounded descriptor-relative `vault.hanzala` read;
2. password-slot authentication;
3. derivation of exactly one metadata anchor from the recovered master key;
4. descriptor-relative read and authentication of that metadata object.

HZRK recovery uses that same retained root for:

1. the bounded descriptor-relative `vault.hanzala` read;
2. derivation and authentication of exactly one recovery anchor;
3. derivation and authentication of the matching metadata anchor;
4. the existing recovery-access-ID versus metadata-access-ID check.

Neither path enumerates the shared `objects` pool.

## Replace-and-restore resistance

Before this stage, each private store reopened the public root pathname independently. A hostile process could attempt to move the real root aside, place a different authenticated object tree at the same pathname during a private read, then restore the original root before the next device/inode pathname check.

Private unlock reads are now relative to the already-open root descriptor. Temporarily changing what the public pathname names therefore does not retarget recovery or metadata reads.

Immediately before an unlocked foundation is returned, the public root pathname must resolve to the retained root device/inode. A root that remains rebound fails closed. HZRK failures continue to collapse onto the existing generic recovery-error surface.

Deterministic tests construct replacement roots containing correctly authenticated metadata, and for recovery a valid copied recovery object plus same-access-ID attacker metadata. The returned unlock must still use the original root's authenticated metadata.

## Wire-format and public-shape invariants

No public vault format changes are introduced:

- `vault.hanzala` remains the same v2 envelope;
- HZOBJ003 remains exact-filename AEAD-bound;
- visible-only and dual-access bootstrap keep the same initial public object-count/size shape;
- the recovery payload format remains version 1 and is shared by normal and retained-root decoders;
- no visible/concealed/recovery marker is added to public storage.

## Scope and remaining boundaries

The retained root exists only for the unlock transaction. Normal unlocked-session operations continue to perform their own descriptor-bound root/pool/object checks and do not yet retain one root descriptor for the entire session lifetime.

The `objects` directory is opened relative to the retained root for each exact private-anchor read rather than being retained for the entire unlock. Existing descriptor checks still apply to each object operation.

On non-Darwin platforms the compatibility path remains pathname-based because this hardening targets the macOS application threat model.

This does not protect against a compromised kernel/root-equivalent process that can read process memory or subvert system calls. It also does not hide APFS snapshots, Time Machine/cloud history, Spotlight/recent-item metadata, swap/crash artifacts, or SSD/TRIM allocation history, and it is not a general claim of plausible deniability.

Hidden/Decoy UI remains disabled and v1 is unchanged.
