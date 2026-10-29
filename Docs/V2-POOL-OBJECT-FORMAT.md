# Hanzalaomator v2 Pool Object Format

Status: foundation only. This does not enable the production v2 storage path.

## Goal

Every object stored in the shared v2 `objects/` pool must use one public envelope shape regardless of whether the encrypted payload contains access metadata, ordinary file data, a chunk manifest, or padding.

Each ciphertext must also be cryptographically bound to the exact opaque filename under which it is stored. A ciphertext copied or swapped to another valid opaque name must not authenticate, even when both objects use the same access master key and have the same logical length.

## Cryptography

`V2PoolObjectCodec` uses libsodium XChaCha20-Poly1305 IETF AEAD through `swift-sodium`.

The per-access object key is derived from the 32-byte unlocked master key using the dedicated HKDF-SHA256 domain:

`hanzala/pool-object/v2`

This domain is separate from the v2 namespace locator domain.

## Public envelope

The current foundation revision is identified by the generic magic:

`HZOBJ003`

The public bytes are:

`genericMagic | XChaCha20-Poly1305 nonce+ciphertext`

The generic magic identifies only the v2 pool-object format. It does not reveal the encrypted object's role.

## Associated-data name binding

The AEAD associated data is:

`genericMagic | 0x00 | opaqueObjectName`

`opaqueObjectName` is already the public, role-neutral 64-character lowercase-hex object filename. Binding it as associated data therefore adds no new plaintext role or filename metadata.

The binding means:

- modifying ciphertext fails authentication;
- moving/copying ciphertext to a different opaque object name fails authentication;
- swapping two same-key, same-size ciphertext files fails authentication at both names;
- deterministic per-access metadata anchors are authenticated under their exact derived opaque anchor names as well.

The earlier `HZOBJ002` foundation revision authenticated only the generic magic and was not bound to an opaque filename. `HZOBJ003` intentionally does not accept those foundation ciphertexts. The v2 production path has not been enabled, so this hard format break is taken now rather than carrying an unbound compatibility mode into production.

## Encrypted payload

Inside the authenticated ciphertext:

`payloadVersion | privateKind | logicalLength | content | randomPadding`

The private kind currently distinguishes metadata, ordinary data, padding, and chunk manifests **only after successful decryption**. The logical content length is encrypted as well.

`manifest` does not add a new public header or filename convention. A chunk manifest uses the same `HZOBJ003` envelope and opaque name as every other pool role.

## Padding

The codec can pad different logical payload sizes to one common encrypted plaintext target. With the same target, different private roles produce equal public envelope lengths.

Individual pool objects are capped at 16 MiB of authenticated plaintext to bound memory use. The new authenticated chunk-manifest foundation defines how a future large logical file can reference multiple bounded objects without weakening this per-object limit.

This is an implementation primitive, not a complete physical cover-traffic policy. Callers should not choose object-specific exact sizes that reintroduce obvious role fingerprints.

## Security behavior

- wrong master key: authentication failure;
- wrong opaque filename binding: authentication failure;
- modified ciphertext: authentication failure;
- truncated/malformed envelope: rejected;
- invalid opaque binding name: rejected;
- padding target smaller than the encrypted payload: rejected;
- oversized object/padding target: rejected before large allocation;
- invalid master-key size: rejected before encryption;
- no cleartext object role or logical length.

## Current higher-level foundations

The repository now separately contains:

- opaque random naming and immutable collision-safe object creation;
- per-access authenticated encrypted metadata;
- authenticated ownership/import transactions;
- authenticated removal transactions;
- symmetric visible-only/dual-access bootstrap;
- integrated password-selected v2 session orchestration;
- a private authenticated chunk-manifest format for the next large-file stage.

The chunk manifest is not yet wired to multi-object ownership transactions or the session read/write path.

## Remaining work

Before v2 storage can be enabled for production, Hanzalaomator still needs:

- transactional multi-object chunk import/removal with pre-committed ownership of every chunk and manifest name;
- streaming reconstruction and end-to-end digest verification;
- rollback and power-loss testing across the complete v2 path;
- descriptor-relative filesystem race hardening;
- physical capacity/accounting policy beyond logical budget enforcement;
- recovery semantics that do not expose concealed-mode existence;
- metadata mitigation for timestamps, filesystem snapshots, iCloud/backup history, Spotlight, thumbnails, swap, crash logs, and SSD/TRIM behavior;
- focused security review and fuzzing before the v2 path is enabled.

Existing v1 objects continue to use the v1 format and are not migrated by this work.
