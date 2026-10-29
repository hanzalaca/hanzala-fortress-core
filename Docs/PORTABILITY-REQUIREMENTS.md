# Hanzalaomator portability requirements

These requirements are mandatory architectural constraints, not optional release conveniences.

## Portable application

- `Hanzalaomator.app` must remain usable when copied to a removable SSD/USB drive and launched from there, subject only to normal macOS Gatekeeper/signing rules.
- The application must not require installation into `/Applications` as a functional dependency.
- The application must not depend on absolute paths tied to one Mac or one username.
- Any helper, extension, or Finder-mount component must be bundled with the app or provisioned through an Apple-supported mechanism that does not bind the vault to one physical Mac.
- Signing/notarization may authorize the code, but must not turn the app into a device-bound product.

## Portable vault

- A vault may live on an external HDD/SSD, USB drive, iCloud Drive, OneDrive/Dropbox-style synced folder, or ordinary local folder.
- The vault format and wrapped master key must remain independent of the Mac on which the vault was created.
- macOS Keychain may be used only as an optional convenience. It must never be the sole storage location for information required to unlock a vault.
- Moving the entire vault folder to another supported Mac must preserve the ability to unlock it with the same vault password.

## Finder mount

- Unlocking a vault may expose a virtual Finder volume, but the encrypted `.hzo` objects remain the authoritative storage.
- The mount implementation must not require the vault itself to be copied to an internal disk.
- The mount must support a vault whose backing store is on a removable drive.
- The mount lifecycle must handle backing-drive removal safely: stop new I/O, invalidate the mount, drop vault keys, and surface a clear error instead of silently writing elsewhere.
- No mount cache may become a second authoritative plaintext copy of the vault.

## Removable app + removable vault scenarios that must be tested

1. App on internal disk, vault on external SSD.
2. App on external SSD, vault on the same external SSD.
3. App on external SSD, vault on a different removable drive.
4. Copy app to a second Mac, attach the original vault drive, unlock with the same password.
5. Safely eject the vault drive while locked.
6. Attempt drive removal while unlocked and verify fail-safe unmount/key cleanup behavior.

## Release rule

Do not merge a Finder-mount architecture that breaks any of the above portability scenarios unless the limitation is explicitly documented as a temporary prototype blocker and a migration path exists.
