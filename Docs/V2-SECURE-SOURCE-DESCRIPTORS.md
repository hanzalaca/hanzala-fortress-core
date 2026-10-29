# Hanzalaomator v2 secure source descriptors

Status: hostile-filesystem hardening. This does not enable production Hidden/Decoy UI.

## Purpose

`V2SecureSourceFile` is the source capability used by v2 filesystem imports. It keeps plaintext reads attached to one already-open regular file instead of repeatedly resolving an untrusted pathname.

## Darwin behavior

On macOS the helper now:

1. requires an absolute file URL;
2. opens `/` as a directory descriptor;
3. traverses every ancestor with `openat(..., O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)`;
4. opens the final component relative to the last retained directory descriptor with `openat(..., O_RDONLY | O_CLOEXEC | O_NOFOLLOW)`;
5. rejects arbitrary symlink/non-directory ancestors without following them;
6. uses `fstat(2)` on the already-open final descriptor to require a regular file and bounded representable size;
7. captures device, inode, size, modification time, and change time from that descriptor;
8. performs all reads through the retained `FileHandle` wrapping the same descriptor;
9. rewinds with `lseek(2)` rather than reopening the pathname;
10. checks the descriptor snapshot before reuse so in-place size/timestamp changes fail closed.

macOS exposes `/tmp`, `/var`, and `/etc` as fixed root-level compatibility aliases. The traversal maps those known prefixes to `/private/tmp`, `/private/var`, and `/private/etc` without following an arbitrary runtime symlink. This keeps standard temporary paths usable while arbitrary user-controlled ancestor symlinks remain forbidden.

## Ancestor replacement property

Once an ancestor directory has been opened, later renaming or replacing that pathname cannot retarget the remaining traversal. `openat` continues from the retained directory descriptor. A focused deterministic test replaces an ancestor after its descriptor is opened and verifies that the final source still comes from the original directory, not the attacker replacement.

This does not authenticate the user's intended pathname before traversal begins. A hostile process that substitutes a real directory entry before Hanzalaomator opens that component may still influence which directory is opened. Preventing that requires an external trusted identity/bookmark boundary, not pathname traversal alone.

## Test coverage

The focused tests verify:

- normal regular-file reading and descriptor rewind;
- final-component symlink rejection;
- arbitrary symbolic-link ancestor rejection;
- directory/non-regular source rejection;
- final pathname replacement after open does not redirect reads;
- replacement of an already-open ancestor cannot retarget the final source;
- in-place source growth is detected before descriptor reuse.

## Remaining threat boundary

Descriptor-relative traversal closes symlink following and post-open ancestor-retargeting windows; it is not a hostile-kernel proof. A compromised kernel/root process, substitutions that occur before a component is opened, mount/filesystem behavior below the process boundary, snapshots, cloud history, Spotlight, swap/crash artifacts, and SSD wear-leveling/TRIM remain outside this guarantee.

v1 is unchanged.
