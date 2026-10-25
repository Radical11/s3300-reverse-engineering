# English Color Options label path

25 October 2026. Static lookup checks were followed by a corrected camera
observation: Amber is confirmed in Auto mode's Color options. The earlier
Nostalgic sepia observation came from Special effects, a separate menu. Its
failed label record is retained and superseded. Installed bytes remain
unverified. Static evidence is in
[`label-path-verification.json`](../evidence/label-path-verification.json).
The smaller earlier `label-contracts.json` records the initial host check.

## The menu selects the expected record

Callback **0x805c099c** requests category 0, submenu 4 from descriptor builder
**0x805b7f04**. That builder selects the five halfword text IDs at
**0x8065a6b6**. The generic drawing route passes them through **0x80595f60**,
**0x806fb780**, **0x802436b8**, **0x801f211c** and **0x802c73fc**.

| String ID | Original English text | Embedded code-unit address |
| --- | --- | --- |
| 560 / 0x230 | Standard color | 0x8036e41e |
| 561 / 0x231 | Vivid color | 0x8036e43e |
| 562 / 0x232 | Black-and-white | 0x8036e458 |
| 563 / 0x233 | Sepia | 0x8036e47a |
| 564 / 0x234 | Cyanotype | 0x8036e488 |

Lookup **0x802c73fc** checks requested ID against the loaded header's first ID
and count, then indexes the allocated pointer table. For this English file,
first ID is zero and count is 3,313, including the default record. Thus the
previous patch address and its ordinal are consistent with this menu route.
The icon array is separate and is not a substitute text table.

## Embedded loading and ownership

Loader **0x801f2b14** calls category 12 of **0x8000c300**, passes its returned
pointer and selector through **0x802c0c40**, then invokes **0x802c0d28**.
The English table begins at **0x8036add4** and contains 46,392 bytes. Header
fields specify first ID, record count, maximum record bytes and 16-bit units.
The native parser starts at file offset 20 and includes the default record.
The existing resource codec separately enumerates ordinary records from 1.
Both interpretations agree on every ordinary record's text and byte address.

The dispatcher return value **0x729e** selects the nonzero embedded branch.
It is **not a byte-length clamp in this parser**. The parser uses record count
and serialized lengths. It allocates a header and pointer index; embedded text
pointers continue to reference the source table. A descriptor copy does not
give the caller ownership of those strings. Filesystem fallback remains a
different branch when embedded dispatch returns zero.

## What the host verification establishes

The tool byte-checks 12 retained native dossiers against the authenticated ELF
and checks nine selected instructions. It then runs only the original native
ZST loader and string-ID lookup in Unicorn 2.1.4 with synthetic stack/heap.
Allocation, memset, strcmp and drawing endpoints are explicit bounded host
stubs. Unexpected execution and writes outside synthetic stack/heap are rejected.
This executes no peripheral, firmware startup, filesystem or font rasterizer.

All **3,313 record pointers** agree with an independent parser in each run.
Original text selects Sepia, while replacing only that span selects Amber.
The surrounding four Color Options labels retain their meanings. Out-of-range
IDs are rejected. Using selector 1 instead of 0x729e produces the same parser
selection, corroborating the boolean role of that value.

The actual reviewed local candidate, SHA-256
`d801708b06abbaece3974b2ae0cb9c55ce4154fffc0c132e00b35564ec86ce28`,
was also checked. Two independent decoders reconstruct all 151 blocks /
2,630,016 bytes of its English-containing segment. Only the declared Welcome
and Amber spans differ there; candidate FAT and embedded English copies match.
Running the same two native helpers against that candidate's table selects
Amber at ID 563. This is candidate-byte evidence, not installed-byte evidence.

## Camera route clarification

The six options reported by the user identified Special effects. Its Nostalgic
sepia is original English ID 1154 at 0x803716fa, separate from Color Options
Sepia ID 563. After choosing Auto mode and opening MENU → Color options, the
user confirmed Amber. The static record mapping agrees with the intended
screen. No new firmware update was needed to resolve the apparent rename issue.

Fresh Amber photos corroborate the tint. A first intended-Standard shot was
also tinted, while an explicit Standard → OK repeat now confirms a normal
preview and saved colour photo. Both results are retained. See
[camera verification](camera-verification-2026-10-25.md) and
`evidence/amber-auto-verification-2026-10-25.json` for the latest runtime scope.
Installed-image identity, executable integration and recovery remain separate
questions. No new candidate was produced in this investigation.

```powershell
python tools/map_label_contracts.py --emulate --candidate derived/amber-mono-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin --output derived/new-label-path.json
python -m unittest discover -s tests -p test_label_contracts.py -v
```

`--candidate` and `--emulate` are optional. Without them, the mapper performs
only static authentication and parsing. Existing reports are never overwritten.
