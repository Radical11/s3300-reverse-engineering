# Backup and restoration investigation

Historical static-analysis record. The camera now reports v1.1, and the
GetMem/settings traces have advanced in `state-contracts.md` and
`development-contracts.md`. Complete backup and unbootable software recovery
remain unverified; later UI update success does not close those gaps.

24 October 2026. Source-bound v1.1 static analysis; installed camera remains
v1.0. No debug request, monitor command, marker activation or camera write ran.

`tools/map_restore_path.py` records seven bounded MIPS listings, checks ten
reviewed instructions and binds the NAND-dump monitor handler to its recovered
exception-metadata range. Findings are in `evidence/restore-path.json`.

## Why the existing dump command is not a verified backup

The monitor table record at 0x808983cc names `Nanddn`, describes NAND-to-card
output and points to handler 0x805810c0. The recovered function range is 0x854
bytes. The output path is `I:\DumpNand.txt`.

The reviewed loop starts at sector zero and uses a literal last sector 0xffff:
65,536 requested sectors. A successful read is followed by writes of 512 data
bytes and 16 extra bytes. The nominal all-success output is 34,603,008 bytes,
including 33,554,432 data bytes. These are loop arithmetic, not measured device
capacity or an actual dump size.

On a read failure the routine reports the error, advances the sector and
continues without a placeholder. Subsequent records can therefore lose their
simple sector-to-file-offset correspondence. The reviewed write path also does
not check the write result before progressing. A geometry query exists, but
the loop limit remains fixed. The complete meanings of extra bytes, ECC and
bad-block treatment have not been established.

The routine also changes display/debug state and writes a card file. Its
presence is not a verified passive external backup interface. Console access,
complete flash/calibration coverage and a working write-back procedure remain
unknown. No command was issued.

## USB readback remains a separate investigation

The table at 0x80899658 contains a SetMem/monitor pointer and flags, followed by
a GetMem pointer at 0x80899660. Zero flags have not been assigned a permission
meaning. Reviewed GetMem paths use shared command state and a transfer routine;
the external dispatcher, request number/framing and active interface are still
unresolved. Its correspondence to the installed v1.0 has not been demonstrated.

Neither this code nor the previously advertised vendor operations establishes
a safe flash readback transport. Hardware access is not proven necessary,
either; keep tracing the software path rather than claiming a physical-work
dependency without evidence.

## Consequence for the research candidate

A same-size resource edit with an independently verified checksum advances
repacking. It does not resolve restoration. The current candidate remains
local and is marked **not installable**. Required evidence still includes a
complete backup/calibration scope, actual write ranges, model/version acceptance
on installed v1.0 and an accessible recovery procedure. The official v1.1
download is not the camera's current flash backup.
