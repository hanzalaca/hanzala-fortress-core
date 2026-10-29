# Cryptographic Inventory and Post-Quantum Roadmap

Status: architecture requirement from v0.1 onward.
Priority: medium implementation priority now; high architectural priority.

## Safety rule

Hanzalaomator does not invent cryptography and does not replace the currently selected, reviewed primitives merely for post-quantum readiness. Production cryptographic changes require mature standards, ecosystem support, testing, and independent security review.

## Crypto inventory

Every cryptographic use must be discoverable and attributable. The inventory tracks:

- purpose and data protected
- primitive / algorithm and implementation library
- key type, origin, storage location, lifetime, rotation and destruction path
- signatures and authentication
- key derivation and password-based protection
- encrypted storage and backup/archive formats
- transport protocols and negotiated cryptography
- certificates, tokens and credentials
- platform cryptographic APIs and hardware-backed key facilities
- third-party dependencies that select or hide cryptographic behavior
- file/format/protocol version that would be affected by migration
- owner, migration prerequisite and compatibility constraints

The inventory contains metadata only. Never place live keys, passwords, recovery secrets, tokens, credentials, plaintext source material, or secret values in it.

## Crypto agility

Cryptographic choices must remain behind explicit versioned boundaries so storage formats, key wrapping, signatures, authentication and transport can migrate independently. Persistent encrypted formats must carry non-secret version/algorithm identifiers sufficient for deterministic migration without guessing.

Do not scatter algorithm selection across UI or feature code. New cryptographic use must be represented in this inventory before release.

## Post-quantum policy

Current reviewed primitives remain in place until a deliberate migration is approved. PQ readiness means inventory, isolation, versioning and migration capability first — not experimental algorithm deployment.

Track standards and platform/library support for standardized post-quantum mechanisms. Hybrid or PQ mechanisms may be introduced only when appropriate standards and audited implementations are mature for the relevant use case.

Long-lived journalist/source material receives the highest migration priority because confidentiality may need to survive for years.

## Review gates

For each release:

1. Re-scan source, configuration, manifests/lockfiles, scripts, tests and documentation for cryptographic use.
2. Reconcile findings with this inventory.
3. Flag newly introduced cryptography or untracked dependencies.
4. Review long-lived keys, signatures/authentication, storage formats and network transport for migration blockers.
5. Record prerequisites that depend on Apple/platform APIs, libsodium, protocols, vendors or standards.
6. Require human security review before changing a primitive or encrypted format.

## Roadmap

### Now
- Maintain this crypto inventory from the first version.
- Preserve current audited/standard primitive direction.
- Keep cryptographic implementation isolated and versioned.
- Treat untracked cryptography as an architecture/security finding.

### Next
- Automate repository cryptography discovery and inventory-drift reporting.
- Add CI checks that surface newly introduced crypto APIs/dependencies for review.
- Map long-lived data and credentials to harvest-now-decrypt-later and future authentication risk.

### PQ migration phase
- Select only standardized, interoperable, reviewed mechanisms appropriate to each use.
- Prefer migration paths that preserve backward recovery and controlled re-encryption/re-wrapping.
- Independently review the migration before production use.

## Reference model

Cloudflare's CryptoLabe work is used as an architectural reference for discovery and inventory methodology, not as a cryptographic implementation dependency. Its useful pattern is repository discovery -> deep analysis -> merged findings -> inventory/reporting, with explicit migration prerequisites.
