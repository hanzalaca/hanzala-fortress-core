# Hanzalaomator v2 adversarial parser testing

Status: security-hardening foundation. This does not enable production Hidden/Decoy UI.

## Purpose

The v2 storage path accepts attacker-controlled filesystem bytes before any plaintext is released. Authenticated envelopes, encrypted metadata anchors, and private chunk manifests must therefore fail closed when they are truncated, extended, corrupted, randomly malformed, or supplied at hostile boundary sizes.

This stage adds a deterministic adversarial corpus to the normal Swift test suite so every CI run exercises the same malformed inputs and failures are reproducible.

## Current coverage

`V2AdversarialFuzzTests` exercises:

- hundreds of deterministic random pool envelopes carrying the correct public `HZOBJ003` magic but unauthenticated protected bytes;
- sampled bit flips across a valid name-bound authenticated pool object;
- truncation at fixed and strided offsets across a valid encrypted object;
- unauthenticated trailing-byte extensions of otherwise valid ciphertext;
- the public maximum-envelope bound before authenticated parsing;
- ciphertext mutations of a real encrypted metadata anchor, verifying that no mutation decodes as a different authenticated generation;
- deterministic random private manifest bytes through `V2ChunkManifestCodec.decodeContent`, requiring decode/validation failure.

The corpus is intentionally bounded so it can run on every pull request without turning CI into a long-running fuzzer.

## Security invariants

The tests reinforce these existing invariants:

1. Public object magic is not authentication.
2. Any change to AEAD-bound ciphertext, nonce, tag, or associated object name must fail before private content is accepted.
3. Truncated or extended encrypted objects must never be accepted as alternate valid encodings.
4. Oversized public envelopes are rejected before unbounded parser/allocation work.
5. Encrypted metadata cannot be transformed into a different accepted generation by unauthenticated byte mutation.
6. Manifest parsing is followed by structural validation; malformed private bytes are not accepted merely because JSON decoding happens to succeed.

## What this does not prove

This is deterministic adversarial testing, not a complete cryptographic audit or continuous coverage-guided fuzzer. It does not prove resistance to:

- every possible malformed input;
- implementation defects in libsodium, CryptoKit, Foundation, APFS, or the operating system;
- hostile kernel/root memory inspection while a vault is unlocked;
- filesystem race attacks that require descriptor-relative POSIX hardening;
- metadata leakage through snapshots, cloud history, Spotlight, thumbnails, swap, crash artifacts, or SSD wear-leveling/TRIM;
- side-channel or traffic-analysis attacks.

## Next hardening stage

Before enabling v2/Hidden for production, the security program should continue with:

- a coverage-guided fuzz target or external fuzz runner for authenticated envelope and manifest parsers;
- descriptor-relative/no-follow filesystem handling for source import and shared-pool mutation;
- additional corruption/fault injection around bootstrap and recovery-anchor creation;
- APFS and supported external-volume destructive power-loss validation;
- independent cryptographic and filesystem security review.
