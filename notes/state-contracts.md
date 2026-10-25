# UI state, saved settings and debug dispatch contracts

24 October 2026. Offline static analysis of the authenticated S3300 v1.1
carrier and independently decoded analysis ELF. No camera command or target
execution occurred. The parent investigation uses REA; this report is separately
reproducible local evidence, not a REA Evidence ID or recovered original C.

## UI selection and state ownership

Color Options handler **0x805ac85c** subtracts **0x102**, bounds the result to
35 entries and dispatches through **0x8066dbac**. Events **0x106** and
**0x108** select **0x805ac8a4**, which stores the selected value into
current-view byte **+0x1a** at **0x805ac8cc**, applies it through
**0x807132d0**, then calls menu helper **0x805a7070**. Physical button meanings
are not established by event numbers.

The object addressed through **0x80107188** supplies a count at +0, selection
at +4, related-menu pointers at +0x10/+0x14, callback at +0x18 and entry-array
pointer at +0x24. Reviewed selection helpers use **three-byte entries** and
bit 0 of entry byte +2 as the selection flag. These are internal layout
observations; complete menu ownership and supported registration are unknown.
Generic helper **0x806fbfa8** updates these flags and rendering state; this
alone does not identify a persistence writer.

Current-view pointer **0x808918ac** is dynamic. Selector **0x8071c7ac** computes
**0x80891ec0 + index * 0x38**, with special fixed pointers for some modes.
It also uses indices 8, 9 and 10. Every mode therefore cannot be assumed to
use one fixed object or the same persistence policy.

## Settings are staged into a shared user store

This pass traces beyond the prior RAM-only conclusion. Color selection's
helper tail-calls **0x806fc2a4**. When its related-menu pointer is nonzero,
that transition branches on mode state and stages structures before reaching
**0x80009644**. Getter **0x800093b0** returns RAM address **0x800032d4**.
The contracts below come from checked compiler-unwind-bounded copy routines:

| Internal block | Store-relative range | Copy into store | Copy out |
| --- | --- | --- | --- |
| Setup, including welcome byte | +0x28, 0x4a bytes | 0x807372f8 | 0x807373a4 |
| Four view banks, 0x38 bytes each | +0x76, 0xe0 bytes | 0x80737664 | 0x807375e8 |
| Shared view fields | +0x156, 0x24 bytes | 0x8073782c | Not reviewed here |

Setup menu mode **0x3000** stages the object from **0x80891ebc**. Welcome
selection at object +0x19 consequently reaches **store +0x41**. View menu
mode **0x2100** stages the bank block at **0x80891ec0**. Color-option bytes
for the four serialized banks correspond to **store +0x90, +0xc8, +0x100,
+0x138**. These are derived offsets, not memory reads from the camera.

The strings `B:\UiView.bin` and `B:\UiGeneral.bin` exist. Specifically,
**0x80737664** and **0x807375e8** ignore their filename argument and perform
RAM copies. Filename arguments do not establish actual file persistence.
Routine **0x8071d58c** conditionally copies active-view color byte +0x1a
to shared block **0x80891e88 +9**. Preserve existing view-bank ownership and
shared-state synchronization when adding a selectable effect.

## Media transaction: a real route, with incomplete safety contracts

The transition's call at **0x806fc2f0** reaches **0x80009644** after the
mode-selected staging paths return. That routine:

- Allocates a **0x400-byte** buffer and obtains a media handle/geometry.
- Calls **0x80008f80** with literal argument **0x19f**, stores a byte at
  **store +0x19f**, then copies **0x1a0 bytes** from **0x800032d4** into
  the buffer and calls media router **0x800e408c**.
- Uses operation selectors **2, 1, 0**, then compares returned buffer byte
  +0x19f against a recomputed result; success returns zero.
- Loads its media position from **0x80003258**, increments an error byte on
  failures and returns one on the reviewed failure paths.

Prepare/write/read semantics are an inference from order, buffer directions
and comparison. Physical erase/write extents, NAND geometry, atomicity,
wear policy and checksum coverage are not fully established. The checksum
helper's literal argument is not a validated declarative coverage length;
its loop boundaries need separate tests before constructing a store image.
No power-cycle persistence or standalone safe settings API was demonstrated.
Preserve the existing menu route until these contracts are complete.

## GetMem's table index and receive flag are resolved

Dispatcher **0x80796108** indexes **eight-byte records** from **0x80898ec8**:
handler at +0 and flags at +4. The entry calculation multiplies an index by
eight, establishing these internal indices:

| Table index | Record | Handler |
| --- | --- | --- |
| 0xf2 | 0x80899658 | 0x8079d74c, SetMem/monitor side effects |
| 0xf3 | 0x80899660 | 0x8079de34, GetMem paths |

Flag bit 0 selects whether **0x80795fe0** receives a payload before the
indirect call. Zero flags do **not** mean read permission. The handler receives
low8 subcommand in **a0**, payload-buffer pointer in **a1** and transport
selector in **a2**. The extracted prefix has **244 records**, through 0xf3;
later entries and maximum legal opcode remain unresolved.

For selector one and initial opcode zero, a received header contains a LE16
table index at +0, subcommand byte at +2 and payload beginning at +4.
Callers **0x8078d850**, **0x8078d87c** and **0x80791da4** feed the dispatcher;
the last supplies selector zero. Their receive loops and serial header parser
are retained in listings. This is not a PTP opcode mapping or validated host
invocation recipe.

GetMem mode one reads separate state at **0x800e113c**: address +4 and
length +0x10. It ORs the address with **0x20000000**, prepares memory/cache
state and calls **0x80796070**. Setter **0x80203e54** writes those fields,
showing state population is a distinct interface. An address in the
dispatcher's payload has not been shown to populate that state. Status/timing
updates also occur; GetMem is not established as purely passive.

Remaining gates: startup/activation of these loops, active USB mode/endpoints,
complete state framing, valid memory regions, installed-firmware correspondence
and a verified read-only host interface. No camera requests were sent.
Fixed-range `Nanddn` problems and missing calibration/restore coverage from
[restore-path.md](restore-path.md) remain unresolved.

## Reproduction and evidence boundaries

Run `python tools/map_state_contracts.py` with fresh `--output` and
`--listings` paths if defaults already exist. It checks source SHA-256, ELF
and mapped regions, validates reviewed instructions/table records and refuses
to overwrite evidence. It emits **26 bounded listings** and
`evidence/state-contracts.json`; the JSON records the exact assertion count.

`python -m unittest discover -s tests -p test_state_contracts.py -v` runs
eight focused synthetic tests: record/flag parsing, mapped/aligned handlers,
window bounds, delay-slot decoding and changed/missing instruction rejection.
Full linear decoding does not prove complete control-flow coverage. The source
is hashed again after analysis.

The evidence checklist marks UI layout, settings persistence and GetMem
dispatch **partially answered**, and backup/recovery **unresolved**. No patch,
marker, USB request, card change or firmware update was produced.
