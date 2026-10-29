# Hanzalaomator v2 Recovery Sessions

Status: disabled v2 foundation. This does not enable Hidden/Decoy or recovery UI in the production application.

## Purpose

`V2RecoveryAnchorStore` and `V2VaultBootstrapStore.openRecoveryAccess` authenticate an HZRK credential and recover exactly one access capability. This stage connects that authenticated foundation to the normal v2 session boundary so a valid recovery credential can use the same read/import/removal and crash-recovery machinery as a password-opened session.

## Coordinator

`V2RecoverySessionCoordinator.openSession` performs the following sequence:

1. call `V2VaultBootstrapStore.openRecoveryAccess`;
2. authenticate exactly one recovery anchor derived from the supplied HZRK secret;
3. require the recovered master key to authenticate its normal metadata anchor and matching access ID;
4. capture the current canonical public envelope bytes as the normal session envelope binding;
5. construct the same internal `V2VaultSession` capability used by password opening;
6. run `V2VaultSessionStore.recover(session:)` before publishing the session;
7. re-enter the normal session boundary once more through `listEntries` so envelope and access identity are revalidated after recovery.

No raw master key is exposed through the public result and the shared pool is never scanned.

## Access-path isolation

A recovery-created session carries exactly the recovered access ID, role, master key, and envelope binding. It therefore sees only entries authenticated by that access path's metadata anchor.

Tests create independent visible and concealed files, recover the concealed session using only its HZRK credential, and require the recovered session to list/read only the concealed entry. The visible entry remains unknown to that access path.

## Pending transaction recovery

Recovery-key opening is not a shortcut around the normal crash-recovery protocol. Before a session is returned, it runs the same authenticated recovery order as password sessions:

- pending bounded imports;
- pending chunk imports;
- pending removals.

Unknown pool objects remain untouched. A test creates an authenticated pending import whose object was never written, then opens through the HZRK path and requires the missing-object transaction to be aborted before the session is published.

## Failure behavior

Malformed, absent, wrong, or corrupted HZRK credentials retain the generic `invalidRecoveryKeyOrCorruptedAnchor` boundary established by the recovery-anchor layer. No partially constructed session is returned in that case.

Once an HZRK credential has successfully authenticated its recovery anchor and metadata identity, failures in authenticated pending transaction recovery may surface their normal storage-integrity errors. At that point the caller already possesses a valid access capability, so collapsing every subsequent corruption into the credential error would hide actionable vault-integrity failures.

## Envelope identity

The returned recovery session uses the same canonical envelope binding and subsequent `V2VaultSessionStore` validation used by password sessions. The v2 password slots separately bind the security-relevant public vault UUID inside their encrypted payload revision 2.

This coordinator does not create an alternate recovery-only session model and does not relax envelope/access identity checks.

## Non-claims

This stage does not implement recovery-key display, printing, clipboard policy, export, rotation, revocation, secure destruction, or header repair. It also does not address APFS snapshots, Time Machine/cloud history, Spotlight, thumbnails, swap, crash logs, SSD/TRIM artifacts, hostile cross-process filesystem races, or later access-pattern analysis.
