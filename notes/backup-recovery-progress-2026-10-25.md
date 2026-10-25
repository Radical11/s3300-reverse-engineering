# Backup and recovery follow-up - 25 October 2026

## Acquired and verified

Normal USB PTP access works through the existing Windows driver. The camera
reports S3300 / COOLPIX S3300 V1.1. The exposed object inventory had 51 entries,
including 49 files. All 49 files, totaling 170,787,084 bytes, were read twice,
copied locally and rechecked by hash. The visible inventory agreed before and
after copying. The private snapshot is under
`samples/camera-files-backup-2026-10-25-run1/`; its public summary is
[camera-file-backup evidence](../evidence/camera-file-backup-2026-10-25.json).

This preserves exposed files. It does not acquire raw card sectors, ROM,
installed firmware, settings, calibration, hidden flash or NAND spare/ECC.
No camera storage writes, vendor operations, debug switch, driver replacement,
update or recovery attempt was performed. The snapshot predates tool-source
hash capture; the operation log is retained and future acquisitions record
their tool hashes.

The strict StorageInfo parser rejected its unterminated description. Its fixed
26-byte prefix reports exposed capacity2,002,452,480bytes; this is not internal
flash capacity. The baseline serializer should include a terminator, so the
disagreement remains visible. A driver transformation or installed-code
difference has not been established. Raw datasets remain private under
`derived/` and in the snapshot manifest.

## What the new maps establish

- [Backup scope](backup-scope.md): distinct0x1a0 UI and0x24a calibration stores,
  their checksum domains and location metadata. The calibration record contains
  selected slices and cannot stand for all calibration resources. An apparent
  good-block initialization fallback can erase blocks.
- [USB contracts](backup-usb-contracts.md): original setup-byte provenance,
  class/vendor event routing, recipient-parity forwarding and standard metadata
  registrations. Current PTP mode still supplies no verified bridge to the
  internal debug memory reader. Arbitrary setup requests are not exposed.
- [Updater handoff](updater-handoff.md): the normal menu update reaches the
  application's burn machinery at package offset0x100000. It does not prove
  separate-updater execution or boot-independent recovery. The application
  reboot helper reaches absent ROM entry0xbfc00664.
- [Application writer](application-write-scope.md): a separate caller-seeded
  Ghidra import recovers the missing writer without changing the retained main
  project. Protected blocks can be relocated and then erased; bad-block checks
  can mark spare metadata. Package flags do not establish all physical writes
  or calibration preservation.

All direct Ghidra analysis is labelled separately from REA Evidence. The focused
writer's type-propagation warning and inferred boundary remain explicit. Each
map retains source hashes, original instruction checks and unresolved items.

## Reusable tools

`camera-metadata`, `backup-files`, `verify-file-backup` and `backup-status` now
use the common CLI. Acquisition accepts only six standard read operations,
bounded parameters and transfer sizes. The dispatch boundary checks the actual
embedded opcode. File snapshots reject changed content, conflicting scope,
missing inventory coverage, duplicate handles, oversized transfers and reused
destinations. Partial results survive interruption and cannot verify as complete.
Worker termination leaves transport cleanup unknown; no reset is attempted.

`inspect-store` validates already acquired UI/calibration bytes. It cannot
obtain, repair, write or restore them. Read the development guide's recovery
chapter before interpreting a valid checksum as anything beyond record validity.

The read-only browser displays recorded backup coverage. It never starts an
acquisition. Run `python s3300.py backup-status --verify-files` to recheck the
private files locally.

## Remaining blocker

Complete backup/recovery still needs a verified bounded host memory/storage
route, installed geometry and representations, full calibration coverage and
reset-independent software entry/restore. The supplied update has no mapped
instructions for the ROM boundary. No reviewed normal PTP operation has been
shown to bridge that gap. A normal update, a file backup and recovered internal
function addresses do not meet the executable-trial recovery gate.

External protocol references used for the host implementation are Microsoft's
[data-to-read command](https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-execute-command-with-data-to-read),
[SendCommand lifecycle](https://learn.microsoft.com/en-us/windows/win32/api/portabledeviceapi/nf-portabledeviceapi-iportabledevice-sendcommand)
and the upstream [libgphoto2 PTP implementation](https://github.com/gphoto/libgphoto2/blob/master/camlibs/ptp2/ptp.c).
The additional bounded recovery search did not establish an applicable primary
recovery procedure; it is not proof that Nikon has none.
