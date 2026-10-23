# Function ranges from exception-unwind metadata

24 October 2026. `tools/map_unwind.py` recovers **5,798 unique, nonoverlapping
function ranges** from a contiguous .eh_frame-style metadata section at
**0x807da7a4..0x808042cc** in the validated application address map. A four-byte
zero terminator follows at 0x808042cc. The section spans **170,792 bytes** and
contains 279 CIEs and 5,798 FDEs; every record is bounded and exactly consumes
the section. This is stronger boundary evidence than prologue guesses.

`evidence/unwind-functions.json` exposes sorted `functions` records with
`start`, `end_exclusive`, `size`, `fde_address`, `cie_address`, and the source
region SHA-256. These fields can be imported directly into a research index.
The sum of covered function-range lengths is **2,267,704 bytes**. This is not
the whole application, and it does not prove every function has metadata.

The parser authenticates the original vendor source, synthetic ELF and every
ELF region. Every recovered start/end is aligned, lies inside a verified
executable region, and has a valid backward reference to a preceding CIE.
Ranges are unique and nonoverlapping when sorted; original FDE record order
is **not globally monotonic**, so it must not be used as address order.

All CIEs use version 1 and have one of three augmentation forms: empty (268),
`zPL` (8), or `zP` (3). None specifies an `R` encoding override, so the FDE
initial location and range use absolute 32-bit native pointers. Personality
and LSDA pointer encodings, where present, are also absolute and bounded by
the supported parser. No unrecognized encoding is silently accepted.

Every CIE header and FDE address field is independently parsed and compared
using pyelftools `DWARFStructs` header layouts. Full `CallFrameInfo` parsing
was not successful on this legacy data: empty augmentation needs explicit
default handling, and a later CFI instruction sequence is rejected. This
tool therefore does **not** claim to validate CFI instruction semantics,
execute an unwind, identify stack-frame states or decode exception tables.
The unsuccessful full-parser attempt is a parser-coverage limit, not proof
that the camera's own metadata is invalid.

The welcome functions provide a useful concrete example. FDE 0x807ed9d0
describes 0x807415c8 with size 0x208, and FDE 0x807ed9f0 describes 0x807417d0
with size 0x210. Both reference CIE 0x807ed9c0. Their address-valued words are
metadata, not evidence of function-pointer dispatch.

Eight synthetic tests cover absolute ranges, CIE references, bounds,
permissions, overlaps, unsorted record order, truncation and signed LEB128.
Reproduce with Python having the existing pyelftools installation:

```powershell
python tools/map_unwind.py
python -m unittest discover -s tests -p test_unwind.py -v
```

Recovered ranges have no original function names. They are static compiler
evidence, not live execution, readiness for hooks, or a flashable modification.
