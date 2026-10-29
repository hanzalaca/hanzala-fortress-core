# Security notes — Hanzalaomator v0.1

## Threat model target
The intended future target is protection of sensitive journalistic source material when the storage provider, cloud account, or removable disk is exposed. The vault key must never be stored on a HANZALA server.

## Non-goals of storage encryption
Vault encryption does not protect plaintext while the device is already compromised and the vault is unlocked. It also does not remove source-identifying metadata from material exported for publication.

## Design rules
1. Do not invent cryptographic primitives.
2. Keep key derivation and AEAD algorithms versioned in the vault header.
3. Random master key; password only wraps that key.
4. Never sync plaintext indexes or original names.
5. No plaintext previews, thumbnails, Quick Look caches, or temp copies in the final version.
6. Add large-file secretstream before handling real videos.
7. Add crash-safe writes and authenticated recovery metadata.
8. Audit before real source material.
