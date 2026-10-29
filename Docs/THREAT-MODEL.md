# Hanzalaomator Threat Model

## Primary objective
Protect confidential journalistic source material at rest and reduce accidental disclosure of source-identifying metadata.

## In scope
- Theft or copying of a locked vault from iCloud, external storage, SSD, or an ordinary folder.
- Offline password guessing against a copied vault.
- Tampering, truncation, corruption, or replacement of encrypted file objects.
- Filename disclosure from the encrypted storage layout.
- Large photo/video files without loading an entire plaintext file into memory.

## Explicitly not solved by storage encryption
- A compromised device while the vault is unlocked.
- Malware, keyloggers, screenshots, or spyware with access to plaintext presented by the operating system.
- Plaintext intentionally exported outside the vault.
- Metadata leaked by a publish copy unless a separate sanitization workflow removes it.
- Source identity leaked through messaging, account records, contacts, network metadata, or operational mistakes.

## Design requirements
1. Do not invent cryptographic primitives.
2. Password KDF: Argon2id with numeric parameters stored in the vault header.
3. Random master key independent of the password; password-derived key wraps the master key.
4. Authenticated encryption only.
5. Large file objects use libsodium secretstream XChaCha20-Poly1305 with bounded chunks.
6. Original filenames exist only inside authenticated encrypted metadata/index data.
7. Encrypted object names are random and opaque.
8. A FINAL authenticated stream tag is mandatory so truncation is detected.
9. Reject unreasonable frame lengths before allocating buffers.
10. Updates to critical encrypted metadata must use crash-conscious replacement.

## Release gate
No build is approved for real confidential-source material until round-trip, wrong-key, tamper, truncation, large-file, interruption/recovery, and sync-conflict tests pass and the crypto/storage design receives independent review.
