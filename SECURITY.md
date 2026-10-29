# Security

This code has **not yet been independently audited**. Reviews are very welcome.

## Reporting a problem

Please report security problems privately through GitHub's **"Report a vulnerability"** button on the Security tab of this repository. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and what an attacker could gain. You will get an answer as soon as possible, and the fix will credit you unless you prefer otherwise.

## Scope

In scope: the vault format, key derivation, encryption, recovery keys, fixed-size vaults, and anything that lets a seized vault reveal more than its fixed size.

Out of scope: the app screens (kept in a separate project) and attacks that need the vault password or a device that is already unlocked and open.

The threat model is in [Docs/THREAT-MODEL.md](Docs/THREAT-MODEL.md).
