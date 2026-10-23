# Application update acceptance and debug-access map

23 October 2026. Static analysis of the independently decoded **v1.1 update**.
The installed camera was previously identified as v1.0; these are not observed
v1.0 RAM contents. No device command was issued during this pass.

## Newly verified additive checksum

Application routine **0x807366d4** opens `I:\FIRMWARE\FIRMWARE.BIN`, seeks to
file offset **0x2c**, and reads four bytes. It then rewinds, reads the file in
32 KiB chunks (with smaller allocation fallbacks), and sums its bytes into a
32-bit accumulator. It subtracts the stored little-endian word and each of
that word's four constituent bytes. Zero means the checksum agrees.

The resulting formula is:

```
LE32(file[0x2c:0x30]) == sum(file[:0x2c] + file[0x30:]) modulo 2^32
```

On the actual supplied source, **stored = calculated = 0x5221fe2a**. This is
independent static-code and actual-file agreement, not a guess based on the
field's appearance. Two application call sites at **0x8061fd90** and
**0x8061fda0** invoke this check before proceeding along the update flow.

This adds a concrete installed-application integrity layer to the conditional
boot MD5 paths documented in `integrity-analysis.md`. It does not establish
that every update acceptance requirement is known or that installing a changed
file is recoverable. The checksum is not an authentication signature.

## Version and marker fields

| File location | Actual value | Verified static use |
| --- | --- | --- |
| +0x28, LE u32 | 0x00010100 | Reader at 0x80736640; offered-version display extracts high 16 bits and bits 8..15, yielding 1 and 1 |
| +0x2c, LE u32 | 0x5221fe2a | Additive checksum above |
| +0x30, LE u32 | 0x4b230146 | Compared against the same constant in routine 0x80736568 when runtime flag 0x808921f1 is nonzero |

The +0x30 comparison is an actual marker gate, but its exact model/product
meaning remains unproven. With an available file handle and that flag, the
routine returns 2 for equality and 1 for mismatch. Its caller at 0x80620fe8
uses those results. The flag and camera menu state must be traced before
claiming the full conditions of this gate.

A separate special full-file path at **0x8063afc4** tests the existence of
`I:\FIRMWARE\FULL_EN.txt`, reads six ASCII bytes from it, parses a decimal
major digit and four hexadecimal digits, and compares that version to the
firmware word at +0x28. It stores availability and equality flags. This is
**not established as the ordinary upgrade/downgrade policy**. No marker file
was created, and no acceptance check was disabled.

The normal path `\FIRMWARE\FIRMWARE.BIN` is copied into the application's
upgrade request at 0x8061fd2c..0x8061fd7c. UI message constants 0x106/0x108 and
several state predicates appear in the containing handler. Their human button
meanings are not yet identified; there is no verified recovery button sequence.

## Advertised USB vendor operations are not dump commands

The decoded application gives concrete call sites for previously advertised
operations:

- **0x9002:** registered at 0x8057ad28 with handler 0x8057db04. Its parameter
  paths may call 0x8063b3bc and alter global/camera state.
- **0x9003:** delegated registration at 0x8057ad38 and a shared opcode handler
  at 0x8057db04. One parameter path writes numerous state bytes.
- **0x9005:** the default handler table installs **0x80781028**, also used for
  standard PTP **0x100c / SendObjectInfo**.
- **0x9006:** the table installs **0x807815a0**, also used for standard PTP
  **0x100d / SendObject**. This handler includes USB receive and file/object
  mutation paths, including a `PtpSendObjectHandler` error diagnostic.

The static handlers rule out treating these values as generic read-only RAM
commands. None was executed.

## Separate debug path worth tracing

A distinct implementation near **0x8079de34** is associated with
`GetMem (Usb)` diagnostics. It reads a shared command structure at
**0x800e113c**, obtains an address and length, constructs a memory alias, and
reaches transfer routine **0x80796070**. A pointer to this handler resides at
**0x80899660**.

Adjacent handler **0x8079d74c**, pointed to at **0x80899658**, handles SetMem
and monitor execution. A branch at **0x8079d93c** calls **0x80027a18** with a
received command buffer. The neighboring code therefore includes both reads
and potentially arbitrary side effects. Presence of a GetMem implementation
does not establish active USB reachability, safe address ranges or compatibility
with the installed firmware.

A static monitor registration at **0x808983cc** associates the description
`Dump NandData to Card` with handler **0x805810c0**. Follow-up reaches writes to
`I:\DumpNand.txt`. This is a useful backup lead, but console access, exact flash
geometry and complete calibration coverage remain unverified. It is not a
confirmed read-only USB backup facility.

Three predicates test `I:\EnableTest.txt`, `I:\EnTestFwMode.txt` and
`I:\EnablePTPAP.txt`. Their complete call-site effects remain unknown. These
files were not created and are not recommended as activation instructions.

## Reproduce and evidence

`tools/map_update_acceptance.py` checks the original source and the validated
analysis ELF hashes, records thirteen bounded MIPS32 listings, verifies the
additive checksum and writes `evidence/update-acceptance.json`. Listings remain
under ignored `derived/update-acceptance-analysis/`.

```powershell
python tools/map_update_acceptance.py --self-test
python tools/map_update_acceptance.py
```

Six synthetic checks cover a valid checksum, changed payload/checksum bytes,
and truncated headers. Existing evidence is protected against overwrite.
The source hash matched before and after the pass.

Recovery, installed-v1.0 backup/calibration coverage, ordinary version policy,
complete model acceptance, actual USB debug transport and safe repacking remain
separate unfinished dependencies. No installable update was produced.
