# Independent security review: scope and guide

This page is for the team reviewing HANZALA FORTRESS Core. It says what to
review, where it is, how to run it, and what we most want checked.

Review target: this repository, `main` at commit
`7189154730443dab1eb49c1b6d8c1fec68597b7e` (or a later commit agreed in
writing before the review starts).

## What the product is

An offline encrypted vault for photos, documents and files on iPhone, Mac and
Android, built for journalists, their sources and people whose devices may be
seized. There are no accounts, no servers and no network code in the core.
The iPhone app is on the App Store; Android and Mac builds are downloaded
directly. All three open the same vault, byte for byte.

## In scope

| Area | Where |
| --- | --- |
| Vault format v2 (frozen for version 1) | `Docs/V2-VAULT-FORMAT-SPEC.md` |
| Threat model | `Docs/THREAT-MODEL.md` |
| Swift core (iPhone and Mac), about 14,400 lines | `Sources/HanzalaomatorCore` |
| Kotlin core (Android), about 3,500 lines | `Android/vault-core/src/main` |
| Python reference reader, written from the spec only | `Scripts/vault_format_reference` |
| Test vectors and fixture vault | `Tests/HanzalaomatorCoreTests/Fixtures/v2-format-vectors` |

Inside that, the parts that matter most:

1. **Key derivation and unlock:** Argon2id (libsodium `crypto_pwhash`
   argon2id13), HKDF-SHA256 key separation, password slots and the
   recovery key (`PasswordKeyEngine`, `DomainKeyDeriver`,
   `DualAccessEnvelope`, `RecoveryKeyEngine`, spec sections 3, 4 and 7).
2. **Encryption of objects and chunks:** XChaCha20-Poly1305 and
   secretstream, nonce handling, padding buckets, chunk manifests,
   truncation and reordering (`SecretStreamEngine`, `V2PoolObjectCodec`,
   `V2ChunkManifest`, spec sections 6 and 10).
3. **Metadata:** what an attacker with a copy of a locked vault learns:
   file count, sizes, names, timestamps (spec sections 5, 8 and 11,
   `Docs/V2-FIXED-CAPACITY-POOL.md`).
4. **Crash safety and tampering:** interrupted writes, rollback, swapped or
   replaced objects (`V2DurableFileCommitter`, the transaction
   coordinators, `Docs/V2-DURABLE-COMMITS.md`).
5. **Agreement between implementations:** the Swift and Kotlin cores must
   accept and reject exactly the same vaults.

## Out of scope

- The app screens (kept in a separate, private project).
- Attacks that need the vault password, or a device that is already unlocked
  and open, or malware on the device (see `Docs/THREAT-MODEL.md`).
- The Finder mount code (`Finder*`), which release builds do not ship.
- libsodium itself.

## Known issues (please confirm or challenge)

Section 14 of the spec lists the open questions found while freezing the
format. The main ones:

- Passwords are hashed without Unicode normalization (14.1).
- Some envelope fields, including slot order, are not authenticated; unlock
  only accepts each role in its own slot (14.2).
- Readers accept any Argon2id parameters libsodium accepts (14.3).
- File timestamps on disk still show roughly how much was added since a
  fixed-size vault was filled (`Docs/V2-FIXED-CAPACITY-POOL.md`).

## How to run it

Swift (macOS with Xcode):

```sh
swift test
```

Kotlin (JDK 17 and Gradle):

```sh
cd Android
gradle :vault-core:test
```

Python reference reader (needs PyNaCl):

```sh
python Scripts/vault_format_reference/open_vault.py --check-vectors
```

CI runs all three on every change (`.github/workflows/tests.yml`), plus
CodeQL.

## What we would like back

- Findings with severity, how to reproduce them, and a suggested fix.
- A short public summary we can publish here, linked from the README.
- A retest of the fixes.

## Contact

Report findings privately through GitHub's "Report a vulnerability" button
on this repository's Security tab (see `SECURITY.md`).
