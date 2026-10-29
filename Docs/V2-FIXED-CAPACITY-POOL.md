# v2 fixed-capacity pool (size hiding)

Status: **wired into v2 sessions** (imports, removals, crash recovery and
fixed-size metadata). Turning it on from the Mac and iPhone apps is the next
step. Ordinary vaults are unchanged and keep their exact metadata format.

## Problem

Zero Bulk Decryption means that someone holding an unlocked device reaches only
the file that is open. But the vault folder still shows how much is stored:

- the total size, which on an iPhone is visible in Settings > Storage;
- the number of objects;
- the size of each object.

Per-object bucket padding (`V2DataObjectPaddingPolicy`) already hides exact file
sizes. Nothing hides the amount, though, and for a journalist under pressure,
"there is a lot in here you are not showing us" is itself dangerous.

## Idea

The user chooses a capacity when the vault is created, for example 2, 5 or
10 GB. The whole capacity is filled at once with encrypted padding objects
("covers"). Covers use the same `HZOBJ003` envelope, the same random opaque
names and the same bucket sizes as real objects, and they are sealed under the
same key with private kind `padding`. Without the key they cannot be told apart
from real data.

- **Storing** puts the real object into the smallest free slot that fits it,
  then deletes that slot's cover. The real object has exactly the cover's size.
- **Deleting** writes a fresh cover of the same size, then deletes the real
  object.
- **A full bucket.** If the right-sized bucket is used up, a larger slot is used
  instead. This wastes space but never changes the pool's shape. The vault is
  full only when no slot is big enough.

So the number of objects, each object's size and the total never change. The
slot profile (`V2FixedCapacityPlan`) depends only on the chosen capacity. Fixed
shares go to each bucket (small buckets have a maximum slot count), and the
4 MiB chunk bucket takes the rest. Capacity counts authenticated plaintext;
each object adds a fixed 48-byte envelope on disk.

| Bucket | Share of capacity |
| --- | --- |
| 4 KiB | 1%, at most 4096 slots |
| 16 KiB | 1%, at most 2048 slots |
| 64 KiB | 2%, at most 1024 slots |
| 256 KiB | 4%, at most 512 slots |
| 1 MiB | 8%, at most 512 slots |
| 16 MiB | 16% |
| 4 MiB | the rest |

Capacity ranges from 64 MiB to 256 GiB, which keeps the slot count under about 65,000. Less than 4 MiB of the capacity goes
unused.

Cover names are not random: each is HMAC-SHA256, under the access path's
namespace key, of a fixed label, the bucket size and the slot index. Without the
key they look like any other opaque name. Because they are derived:

- `V2CoverLedger` needs only one bit per slot ("holds a cover"). That is a few
  kilobytes even at the largest capacity, so it fits the fixed-size metadata.
  It still reveals how full the vault is, so it must only ever live inside the
  access path's encrypted metadata.
- `fill` is resumable. After an interruption, running it again writes only the
  missing covers.
- Store and release pick a random slot, so covers are not consumed in a
  predictable order.

## Safety rules kept

- Covers are deleted only after they authenticate under the vault key as
  `padding` with an empty length, through the existing authenticated deletion
  primitive. Unknown objects are never deleted.
- Every swap commits the new object first and removes the old one second. An
  interruption leaves at most one extra object, never a missing one. If the
  second step fails, the first is rolled back, and the ledger changes only
  after both steps succeed.
  If the rollback itself fails, the error is `swapIncomplete`, so the caller
  knows to reconcile the pool.
- No new cryptography is involved. It uses the same XChaCha20-Poly1305 pool
  codec.

## Tests

`Tests/HanzalaomatorCoreTests/V2FixedCapacityPoolTests.swift` checks:

- The sorted list of file sizes on disk (what someone holding the device sees)
  is identical after every store and release.
- A full bucket falls back to a larger slot, and the vault is full only when
  nothing fits.
- A wrong key or a forged reference changes nothing.
- An interrupted fill resumes and restores the shape.
- Cover names depend on the key, the bucket and the slot.
- The ledger for the largest capacity fits easily in the fixed metadata size.
- The plan depends only on the capacity, stays within it and refuses
  out-of-range values.
- The ledger round-trips through `Codable`.

## How sessions use it

`V2VaultSessionStore.prepareFixedCapacity` turns it on for a new, empty access
path: it records the capacity in the encrypted metadata (`fixedCapacity`),
writes every cover, then marks the fill complete. Imports are refused until
then, and calling it again resumes an interrupted fill.

The ledger lives in the encrypted metadata. A set bit is a free cover. Every
pending transaction names the slot it uses for each object (`coverSlot`,
`coverSlots`), and those slots stay out of the free set until it finishes.
So free covers plus owned objects always equal the plan's slot count, and
metadata validation checks exactly that.

- **Import.** The claim reserves a free slot for each object (the manifest
  and every 4 MiB chunk of a large file). Each object is written padded to its
  slot's bucket, then that slot's cover is removed.
- **Removal.** The claim reserves an empty slot in each object's bucket. Each
  object's cover is written before the object is deleted, and the slots are
  marked free when the removal finalizes.
- **Recovery.** A crash leaves at most one extra object. On the next open,
  recovery follows the reserved slots: it removes the cover of an object that
  was written, or puts back the cover of one that was not, then finishes or
  aborts the transaction as before.
- **During a swap.** While one object is being swapped, the folder briefly
  holds one extra object, and a crash keeps it there until the vault is next
  opened. Someone who copies the folder at that moment sees one more object,
  not how much is stored.
- **Full disk.** A removal checks that the disk can hold the largest cover it
  will write before it starts, so a full disk refuses the removal instead of
  leaving it half done.
- **Metadata.** In a fixed-capacity vault the metadata is always padded to
  1 MiB. When it no longer fits, the vault reports full, like running out of
  slots.

## Not solved yet (next steps)

1. **App.**
   - The capacity is chosen when creating a vault, with a progress view while
     the covers are written.
   - The app shows how full the vault is, from the ledger.
   - It handles "vault full". Growing the vault is a visible change and is not
     offered yet.
   - All new strings need both Arabic and English.
2. **Second access path.** A visible-only vault's unused second metadata anchor
   stays small. Hidden access is out of V1, so this needs no change now.
3. **Timestamps.** The objects that change show new modification times. Someone
   comparing two copies of the device taken at different times can see how
   many objects changed, though not how much is stored. Rewriting a few random
   covers on each change would blur this and needs review.
4. **Cost.**
   - Filling writes the whole capacity once, which takes time and SSD wear,
     especially on an iPhone. That is why the user chooses the size.
   - APFS snapshots, backups and TRIM behaviour still need the same review as
     the rest of v2.
