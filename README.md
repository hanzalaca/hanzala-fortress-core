# HANZALA FORTRESS Core

The encryption core of [HANZALA FORTRESS](https://github.com/hanzalaca/hanzala-fortress-downloads), an offline encrypted vault for photos, documents and files on iPhone, Mac and Android. It is built for journalists, their sources and people whose devices may be seized.

This repository holds the part that protects the files: the v2 vault format, its cryptography and the storage engine. The app screens are kept in a separate project.

> **Status: not yet independently audited.** Do not rely on this code for your safety until an independent security review has been published here. Reports of problems are very welcome (see [SECURITY.md](SECURITY.md)).

## What is here

| Path | What it is |
| --- | --- |
| `Sources/HanzalaomatorCore` | Swift core used by the iPhone and Mac apps |
| `Tests/HanzalaomatorCoreTests` | Swift tests, plus the fixture vault and test vectors |
| `Android/vault-core` | Kotlin reader and writer for the same format, used by the Android app |
| `Scripts/vault_format_reference` | Independent Python reader written from the specification only |
| `Docs/V2-VAULT-FORMAT-SPEC.md` | The vault format specification (frozen for version 1) |
| `Docs/THREAT-MODEL.md` | What the vault protects against, and what it does not |

## Design in short

- **Offline only.** The core makes no network connections. There are no accounts and no servers.
- **Standard, vetted primitives.** Argon2id for passwords, HKDF-SHA256 for key separation, XChaCha20-Poly1305 (libsodium) for encryption. No home-made cryptography.
- **One file at a time.** Only the file being opened is decrypted. The vault is never decrypted as a whole.
- **Fixed-size vaults.** A vault can be filled to a chosen size with random covers, so its size does not show how much is stored.
- **Recovery key.** A separate recovery key can open the vault if the password is lost.

## Build and test

Swift (macOS with Xcode):

```sh
swift test
```

Kotlin (JDK 17 and Gradle):

```sh
cd Android
gradle :vault-core:test
```

Python reference reader (Python 3.12 and PyNaCl):

```sh
python -m pip install pynacl
python Scripts/vault_format_reference/open_vault.py --check-vectors
```

All three implementations must open the same fixture vault and agree on every vector.

## Licence

Copyright (C) 2026 Hani, HANZALA FORTRESS.

This core is free software under the [GNU Affero General Public License v3.0](LICENSE). If you use it in software you distribute or offer as a service, you must publish that software's source code under the same licence.

The copyright holder also uses this core in the HANZALA FORTRESS apps under separate terms. The name "HANZALA FORTRESS" and its logo are not covered by the licence and may not be used for other products.

Contributions are welcome under the terms in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## بالعربية

هذا هو قلب التشفير في تطبيق HANZALA FORTRESS، وهو خزنة مشفّرة تعمل بدون إنترنت لحماية صور الصحفيين ومستنداتهم. نشرنا هذا الجزء علناً ليتمكن خبراء الأمن من فحصه. الكود لم تتم مراجعته بعد من جهة مستقلة. إذا وجدت مشكلة أمنية، راسلنا بحسب التعليمات في [SECURITY.md](SECURITY.md).
