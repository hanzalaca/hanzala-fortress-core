# Hanzalaomator v2 secure session import

Status: hostile-filesystem hardening. This does not enable production Hidden/Decoy UI.

## Current source boundary

`V2VaultSessionStore.importFile` opens the selected source once through `V2SecureSourceFile` before deciding whether it fits the bounded single-object route or requires chunked streaming.

On macOS the source path is traversed descriptor-relatively. Ancestor directories are opened with no-follow `openat` directory descriptors and the final component is opened with no-follow `openat` from the retained parent descriptor. Regular-file identity and size then come from `fstat` on the final descriptor.

For both small and large files:

1. pending authenticated recovery work is rejected before opening the source;
2. plaintext reads come only from the retained source descriptor;
3. pathname replacement after final open cannot redirect the bytes being encrypted;
4. replacing an ancestor after that ancestor descriptor is opened cannot retarget later components;
5. descriptor snapshot checks fail closed if the opened source inode changes in size/mtime/ctime;
6. no raw source descriptor, master key, or opaque pool name crosses the session capability boundary.

## Bounded single-object path

Small-file plaintext remains bounded by `V2DataObjectPaddingPolicy.maximumLogicalContentByteCount`. The complete bounded value is read from the retained descriptor only, validated again, then passed into the existing authenticated single-object ownership transaction.

## Large-file path

Large files use the same retained `V2SecureSourceFile` for both the bounded SHA-256 pre-hash pass and encrypted chunk-write pass. The descriptor is rewound with `lseek`; the pathname is not reopened between passes. The final digest and descriptor snapshot must agree before the manifest is published.

A suspicious rename/path replacement can therefore either leave the read attached to the original opened object or cause the strict ctime/identity checks to fail closed. It must never redirect the import to a newly placed attacker pathname.

## Remaining threat boundary

Descriptor-relative traversal prevents following arbitrary ancestor symlinks and prevents replacement of an already-open ancestor from redirecting later traversal. It cannot prove what directory entry the user intended before each component was first opened. A hostile process that substitutes a real directory entry before its `openat` can still affect which directory becomes the retained capability.

A compromised root/kernel, filesystem behavior below the process boundary, snapshots, cloud history, Spotlight, swap/crash artifacts, and SSD wear-leveling/TRIM remain outside this stage.

v1 is unchanged.
