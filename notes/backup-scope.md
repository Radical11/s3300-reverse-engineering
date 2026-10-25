# Installed backup scope and storage read boundaries

25 October 2026. This source-bound follow-up adds a concrete persistent
calibration-store layout, its relationship to the UI store, a RAM-only geometry
getter and a destructive fallback hidden inside user-partition initialization.
It performs no camera command, target execution, storage access or firmware edit.

The reproducible record is [backup-scope.json](../evidence/backup-scope.json).
The builder checks 43 selected original MIPS instructions with Capstone, two
store-pointer words and every imported instruction in ten retained application
dossiers. Direct Ghidra is separately labelled and is not REA Evidence. All
addresses below belong to the decoded **application**, not the separate updater
whose numerical addresses can overlap.

## UI settings and calibration are different serialized stores

Reader **0x80009cb4** first searches runtime user-partition candidates for magic
`9c b6`. It issues media selector **0**, count **2**, and checks/copies the
**0x1a0-byte UI store** into RAM **0x800032d4**. Its checksum is at **+0x19f**,
equal to the low byte of the sum of offsets **0..0x19d**. The earlier
[settings-checksum investigation](development-contracts.md) establishes the
helper's unusual boundary convention.

The last two covered UI bytes, **+0x19c/+0x19d**, form a little-endian **16-bit
calibration block index**. The loader multiplies that index by the observed
erase-unit sector count and issues a second selector0/count2 read. It expects
magic **`54 78`** and copies a separate **0x24a-byte calibration store** into
RAM **0x80003474**, also returned by getter **0x800093bc**. Its checksum byte is
at **+0x248**, equal to `sum(store[0:0x248]) mod256`; final byte **+0x249** is
excluded. This differs from the UI checksum placement and must not use the UI
formula merely because both stores call helper0x80008f80.

The read helper changes global RAM, logs failures and clears invalid stores.
Its reviewed media calls use the read selector, whose lower route to backend4
is already recorded in `development-contracts.json`. This is a static internal
read path, **not** a verified host-callable backup adapter. Device modes, live
locations, physical limits, ECC normalization and restoration remain unresolved.

## The serialized calibration store is only a subset

Copier **0x807378a4** serializes these byte slices from its supplied calibration
object into the persistent store:

| Source offset | Store offset | Bytes |
| --- | --- | --- |
| 0x000 | 0x004 | 0x48 |
| 0x048 | 0x04c | 0x40 |
| 0x088 | 0x08c | 0x80 |
| 0x240 | 0x10c | 0xb4 |
| 0x2f4 | 0x1c0 | 0x80 |

For example, source **0x108..0x23f** is not serialized by this copier. The
routine copies **0x23c bytes** in total; header, other store fields and checksum
have separate producers. A valid 0x24a-byte record therefore cannot establish
that every installed ColdData, defocus or other calibration resource has been
captured. A complete backup needs their actual installed representation and
coverage evidence as well as this small serialized subset.

## A bounded geometry getter exists; initialization is not passive

Router **0x800e3fd8**, selector0, calls **0x800e2e0c**. The getter obtains the
runtime device-one registry object, reads its partition object at registry
**+0x123c**, and copies fields **+0x310/+0x314** into output words0/1. Its caller
uses those values as a starting block and a block count. Output word2 is
**`1 << (u16(handle+0x11c4) &31)`**, the erase-unit sector multiplier used by
that caller. Output word3 is copied from registry **+0x1238**; its complete
semantics are unresolved. Registry lookup **0x80065c50** takes/releases a runtime
synchronization object. No flash program/erase call occurs in this reviewed
getter, but this does not supply external invocation, live geometry, total flash
capacity or a raw bad-block/ECC mapping.

The surrounding initialization function **0x80009f70** is more dangerous than
its geometry-oriented setup suggests. If read/validation helper0x80009cb4 returns
nonzero, initialization calls **0x80009510**. That routine emits a
`GoodBlock_Num` diagnostic in its caller, but first sends **media selector2,
count1** for every candidate block. The existing router maps selector2 to
**backend8, erase**. Only afterward does selector3/backend6 inspect spare/status
and collect up to four block indices. Even after four are collected, candidate
iterations still reach the erase call before the count check skips collection.
This is not a passive bad-block scan or a safe way to discover settings.

Calibration writer **0x8000994c** likewise performs erase, checksum/copy, program
and readback, with additional erase calls on some failures. Its readback checksum
does not make it a safe validator or establish a complete restore procedure.

## Required backup coverage

| Component | Current state |
| --- | --- |
| Reset/ROM bytes and independent boot chain | Not acquired; required bytes absent from supplied carrier mappings |
| Installed boot header, section map and recovery flags | Not acquired; package header is different evidence |
| Installed code and resource volumes | Original package preserved; exact modified installed bytes not read back |
| UI serialized store | 0x1a0-byte layout known; installed copy not acquired |
| Calibration store and other calibration resources | 0x24a-byte subset layout known; complete installed scope not acquired |
| Physical geometry, bad blocks, spare/ECC and read-failure map | Not acquired; normalized data alone may omit restore metadata |
| Independent recovery content and transport | Not verified |
| User photographs and other exposed files | Ordinary PTP/WPD copies cover only exposed file objects |

A media-file copy is valuable for preserving photographs. It supplies no proof
that hidden flash, calibration, settings, boot sectors or spare/ECC metadata was
copied. Full-backup and executable-trial gates remain false.

## Reproduce and inspect acquired bytes later

```powershell
python tools/map_backup_scope.py --output derived/backup-scope-check.json
python -m unittest discover -s tests -p test_backup_scope.py -v
```

The module exposes pure `inspect_store`, `partition_geometry` and
`calibration_location` helpers. They accept already acquired bytes/observations,
verify header/checksum or decode arithmetic, and explicitly return false for
full-backup, restoration and physical-extent approval. They do not repair bytes,
create access requests or write images. Tests cover the distinct checksum
domains, excluded tail bytes, corrupt headers, incomplete inputs, location
metadata, wrapping arithmetic and unserialized calibration gaps.
