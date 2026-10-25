# Recovery, failures and troubleshooting

## Preserve exposed files now

```powershell
python s3300.py camera-metadata derived/my-camera-metadata.json
python s3300.py backup-files samples/my-camera-file-backup
python s3300.py verify-file-backup samples/my-camera-file-backup
python s3300.py backup-status --verify-files
```

Create new output names; their parents must already exist. The metadata command
uses only standard PTP GetDeviceInfo, storage IDs/info, object handles/info.
`backup-files` additionally uses GetObject, reading each visible file twice and
checking its local copy. Limits are 4,096 objects, 64 MiB per file and 512 MiB
total. An oversized selection stops before any file download. There is no
upload, delete, capture, vendor opcode, mode switch or driver change.

The snapshot retains an object tree in its private manifest and stores copies
under `objects/` with handle-prefixed names. It does not reconstruct a raw card
filesystem or hidden flash. Do not copy these photographs or private manifests
into a source release. An interrupted/changed transfer remains incomplete;
start a new destination for a new acquisition. Killing a timed-out worker does
not prove camera-side cancellation or transport cleanup. Rechecking a local
snapshot contacts no device and performs no restoration.

On 25 October 2026, 49 visible files totaling 170,787,084 bytes passed this
twice-read and local-readback procedure. Boot ROM, installed code, settings,
calibration and spare/ECC data were not acquired. The exact acquisition and
limits are recorded in [file-backup evidence](../../evidence/camera-file-backup-2026-10-25.json).

One GetStorageInfo dataset failed strict decoding because its description had
no declared UTF16 terminator. The fixed 26-byte numeric prefix is decoded
separately; this is exposed storage capacity, not installed flash geometry.
The baseline string serializer does not explain the discrepancy. The raw
dataset and failure are preserved locally rather than silently accepting a
different format. `camera-metadata` returns nonzero with `metadata_partial` if
some datasets cannot be fully parsed, even when the transport reads succeed.

## Inspect acquired settings without writing them

```powershell
python s3300.py inspect-store ui samples/acquired-ui-store.bin
python s3300.py inspect-store calibration samples/acquired-calibration-store.bin
```

These examples require actual acquired bytes; no such installed stores have
been obtained yet. The pure inspector checks the exact 0x1a0/0x24a sizes,
magic and distinct checksum boundaries. It never repairs a checksum, builds a
read request, writes memory or approves restoration. The calibration record
contains selected slices, not every calibration resource. The read-looking
initialization fallback can erase blocks and is excluded from backup access.
See [backup scope](../../notes/backup-scope.md).

The [handoff map](../../notes/updater-handoff.md) also corrects an important
assumption: the normal update menu reaches application-resident burn code and
seeks to carrier offset 0x100000. It does not demonstrate entering the separate
updater ELF or recovery after application startup fails. The separately
recovered ROM jump reaches 0xbfc00664, absent from supplied file-backed maps.

The [application writer follow-up](../../notes/application-write-scope.md)
uses a separate focused Ghidra project for the previously missing callback.
The original project is preserved; the new boundary is caller-seeded and its
type-propagation warning remains visible. Protection can relocate data before
erasing the original block, and the application's bad-block checker can write
spare metadata. The supplied package disables its forced full-erase flag, but
that is not a proof of complete calibration preservation or fixed write bounds.

## Rollback is different from unbootable recovery

Ordinary rollback uses the camera's functioning application and update menu to
install a known prior image. An SD card containing that image does not prove
the camera can recover if it no longer reaches the menu. Unbootable recovery
requires a verified entry independent of the damaged application, known write
scope and a usable restoration process.

Photo backups, prior update files and internal flash/calibration backups are
different artifacts. Record which each package actually contains. The current
NAND monitor lead has a fixed range, omits placeholders after read failures and
does not prove complete flash/ECC/calibration coverage. Its apparent nominal
size is not a measurement of installed geometry.

The user selected a recovery gate for executable trials. Until a software-only
route passes it, continue analysis, SDK compilation and bounded resource work
without treating new code patches as ready for installation. Do not deliberately
corrupt a camera to test whether a guessed recovery path exists.

## What to do when a check fails

| Symptom | Action |
| --- | --- |
| Source hash mismatch | Stop the build; identify the exact original input instead of disabling the check |
| Baseline export changed | Preserve the edit elsewhere; use a fresh baseline rather than overwriting originals |
| Output directory exists | Inspect the existing log/manifest and choose a new output path |
| Packed overflow or missing entropy code | Reduce/rework the edit; never truncate payloads or change allocation implicitly |
| Visible label unchanged | Trace the actual consumer and embedded/FAT copies; do not assume the update changed every resource copy |
| Preview changes but JPEG does not | Trace the saved-still path and active context; report preview-only evidence |
| No USB camera matched | Check physical connection/mode through the established workflow; do not select a different device automatically |
| Camera version v1.1 but trial uncertain | Reconcile observed markers and exact trial history; version alone is insufficient |
| Native analysis item failed | Retain the error and scope; inspect boundaries/mode and resume only with a matching profile |
| Resource camera error | Retain its timing and subsequent observations; do not infer a cause or successful recovery without evidence |

## Readiness and unknowns

Use the current machine-readable ledger and retained evidence, rather than a
stale test count from an old note. Historical notes describe what was known at
the time; the current guide and interface record should identify later
corrections without rewriting the original observation.

An unresolved sensor identity, runtime-only clock table or missing capture
contract is not solved by a generic driver string. Exact chip/RAM/clock facts
may remain inaccessible through software-only access. Keep those values
unknown and expose the blocker explicitly. Do not publish a universal complete
hardware specification on the strength of the searchable atlas.

## Ask a precise development question

Include the source and candidate digests, command, tool versions, expected and
actual behavior, exact error, relevant log/manifest, and a minimal reproducer.
For a camera result, include mode, power state, what physically happened and
whether there is an original saved artifact. Avoid posting private photos or
vendor bytes when a hash, offset and synthetic fixture answer the question.

The matrix follow-up traces command 15 through retained state to register
uploads. The [label map](../../notes/label-contracts.md) traces English record
selection; Amber is now confirmed in Auto mode's Color options. Special effects
has a different Nostalgic sepia entry. Inspect the exact menu route before
treating an unchanged similar name as an activation failure.

The [recovery transport follow-up](../../notes/recovery-transport.md) connects
internal ConfigMem index `0xf1` to the shared state used by GetMem `0xf3` and
traces the application USB queue. Accepted USB requests, safe read limits and
installed-device endpoint mapping remain unverified. Do not use internal
indices as PTP opcodes or construct arbitrary memory requests from this map.
The [USB-mode follow-up](../../notes/usb-mode-contracts.md) correlates the live
one-interface PTP configuration with modes 4/7. Debug mode 6 registers a
different composition and handle aliases. No independent entry into it is
verified. Read descriptors through `python s3300.py camera-usb derived/new-usb.json`
only with the camera connected; this command is read-only and does not switch modes.
The separate updater's own startup is traced, but a reset route that loads it
after an application failure remains unknown.

The [executable placement map](../../notes/executable-contracts.md) identifies
startup-cleared ranges, timer stacks and allocator ownership. A zero-filled
region or unbacked gap is not approved code space. The SDK's synthetic load
address is also outside the application's direct J/JAL reach. Complete cache
publication, safe hooks and software recovery remain required. Generated
pseudocode names remain provisional.

The [reset follow-up](../../notes/reset-recovery.md) narrows the missing link:
the separate MIPS16 loader reads runtime boot-header fields and fingerprints
64 ROM bytes at `0x9fc00900`. Those bytes and the reset vector are absent from
the six supplied ELF mappings. The packaged `0x9fc08000` routine is a power/GPIO
wait path; its address alone does not establish independent recovery. Keep the
separate executable namespaces and MIPS16 mode intact when investigating it.

The [PTP vendor map](../../notes/ptp-vendor-contracts.md) reviews the advertised
vendor operations individually. `9002` can change camera state; `9005`/`9006`
share object-upload handlers; `9003` uses a queued application route. None
establishes a safe memory-backup interface. No additional operation has been
added to the camera allowlist. Full installed backup coverage and an accessible
reset-independent restoration route remain required.

The [USB entry map](../../notes/usb-entry-contracts.md) checks every direct call
to the mode wrapper using both the native index and an independent raw-JAL
scan. The calls select modes 0, 5 or 7. The mode0 test-state lead depends on
calibration data and internal events; the discovered flag writer modifies
`ColdData.bin`. It is a research lead with incomplete integrity/lifecycle
contracts. The mode-switch debug handler already requires debug access, so it
does not solve initial entry or recovery after boot failure.

The [updater write-scope map](../../notes/update-write-scope.md) authenticates
the updater's separate address space. Its seven logical section records and
software protection predicates do not define fixed physical flash extents.
Programming also depends on runtime geometry, existing headers and bad blocks.
The named user-area backup/restore routines relocate data **on the camera**
with erase/program operations. Even a bad-block check can mark a block bad.
None is an approved passive host backup function.

The [external-source review](../../notes/recovery-external-sources-2026-10-25.md)
records the bounded documentation search. Nikon's published normal-update
procedure did not supply the independent reset/recovery contract required
here. The review does not prove that no service route exists.
