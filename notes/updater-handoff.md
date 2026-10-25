# Normal update and the missing ROM handoff

25 October 2026. This follow-up resolves where the normal menu-based update
goes, while preserving the separate question of reset-independent recovery.
It reuses retained direct Ghidra exports, independently checks 36 selected
MIPS instructions with Capstone, and byte-checks every imported instruction
in 13 application dossiers. Direct Ghidra is not REA Evidence. No camera
request, CPU execution, flash operation or new candidate was produced.

The reproducible metadata is
[updater-handoff.json](../evidence/updater-handoff.json). Recheck locally with:

```powershell
python tools/map_updater_handoff.py --output derived/updater-handoff-recheck.json
python -m unittest discover -s tests -p test_updater_handoff.py -v
```

## Normal update burns through the running application

The UI handler at **0x8061fc68** accepts events `0x106/0x108`, checks the
candidate through `0x807366d4`, and reaches the card-update wrapper
`0x801f7100` with argument1. The static chain is:

`8061fc68 → 801f7100 → 801eb708 → 803d64f0 → 803dbc00`

The wrapper at `0x803d64f0` separates the low8 source selector, an8-bit field
at source bits15..22 and the low8 finish-mode argument. In this observed UI
call those are source1, field0 and finish mode1. These arguments describe a
mutating flash-update path; they are not an exposed SDK or host command.

The card downloader at **0x803dbc00** opens the selected firmware file, then
seeks to **offset0x100000** before reading the0x40-byte burn header. The exact
setup is `lui a2,0x10` at `0x803dbfac`, with high offset word `a3=0`, then
call `0x8008cd5c` at `0x803dbfb4`. That function is a64-bit FileX-style seek,
not a jump to an ELF entry. The subsequent call at `0x803dbfe4` reads0x40
bytes, and the `0x55aa` marker selects an extra0x80-byte header read.

This is a useful correction to a possible interpretation of the package:
the normal reviewed path does **not** demonstrate executing the separate
updater ELF at carrier0x200. It reaches application-resident burning code.

The original package's header at0x100000 supplies:

| Field | Value | Limit |
| --- | --- | --- |
| Data-byte count | `0x1120000` | Package metadata, not installed capacity |
| Transfer chunk | `0x20000` | Writer input granularity, not erase geometry |
| Media kind | `3` | Selects the NAND-NSR software branch |
| Keep-user-area flag | `1` | Does not prove complete calibration preservation |
| Extension marker | `0x55aa` | Selects extra header data |
| Conditional hash field | `0` | Describes this branch; other checks remain separate |

The package finish-action word is0. In the reviewed finishing helper
`0x803d5e20`, that value selects neither the boot-source handoff branch2 nor
the hardware-reboot branch3. The ROM boundary described below is a separately
recovered application helper, not a claim that this particular package uses it.

`0x803e26b0` prepares a burn handle and installs the writer pointer at+`0x125c`.
For media kind3 the pointer is **0x803d73dc**. `0x803e2a40` initializes media,
checks chunk divisibility by runtime erase-unit bytes, allocates input buffers,
then calls that pointer with the handle and input callbacks. The callback
address is authenticated, but its full body and physical write coverage are
not promoted to a complete contract here. The separate updater's overlapping
addresses are different code and remain separate namespaces.

`0x801f7100` converts exactly return1 from the downloader to success0; other
results become`0xfe`. The UI retries at most three times, with media teardown
and reinitialization between failures. Thus a menu update still depends on
the running application's UI, filesystem, allocator and burn implementation.
Existing successful update observations do not establish recovery when those
parts cannot start.

## Reboot reaches code absent from the supplied mappings

Application helper **0x800a2cec** quiesces drivers, clocks, interrupts, GPIO and
cache state before calling **0x800b5890**. The latter calls `0x800b3a90`, writes
zero to register **0xb0802010**, and jumps through`t1` to **0xbfc00664** with a
merged boot-flag word in`a0`.

Its argument arithmetic is:

`(old & ~(mask | 0x3000)) | (requested & (mask | 0x3000))`

If requested bit`0x800` is set, the helper substitutes the old flags before
the merge. This is a pure description of an observed internal value. It
neither supplies a safe reset call nor tells us how the absent ROM interprets
that value.

The old word comes from **0x8005eaa0**, which reads **0xbfc095fc**, caches it
at **0x8005ee54**, and reuses the cache when it is not`0xffffffff`. The reviewed
helper controls interrupt state around that operation. It does not write the
runtime boot flag word. We have not established the ROM producer of that word
or the boot header at **0xbfc09600**.

All six original ELF carriers were checked independently, including the
observed KSEG alias correspondence. None file-backs the ROM handoff entry at
`0xbfc00664`. This is bounded coverage of the supplied update, not a claim
that the installed camera lacks ROM or a recovery facility.

## What is still needed

The result closes the normal-update route question, but leaves recovery
closed. We still need installed ROM/reset routing, a safe software-only entry,
a bounded host transport, full installed firmware/calibration/settings/ECC
backup coverage, and a restoration procedure available without normal
application startup. No boot-flag setter, button sequence, recovery request or
ROM jump is exposed by this map. Executable trials remain blocked.
