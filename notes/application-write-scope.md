# Application NAND writer and protection limits

25 October 2026. This extends [updater-handoff](updater-handoff.md). The normal
menu-update path reaches application writer **0x803d73dc**. Its semantics must
not be substituted from the separate updater ELF's overlapping address space.
No camera operation, candidate, flash trial or hardware emulation was performed.

## Recovering the missing function

The retained full application export had no function dossier at0x803d73dc:
one neighboring function ended0x803d73db, and exports resumed at0x803d9fb8.
The callback literal in `0x803e26b0` authenticates the writer entry. A dedicated
new Ghidra project under `derived/application-writer-focus-2026-10-25` imported
the unchanged authenticated analysis ELF, seeded that entry and neighboring
known entries, and exported the focused results without whole-image analysis.

The resulting body is **0x803d73dc..0x803d9fb7**. This is a **caller-seeded,
inferred boundary**, not an authenticated unwind range or recovered original
source. Ghidra completed decompilation with **“Type propagation algorithm not
settling”** retained in the pseudocode. Pointer/integer types and coverage
remain inference. The existing application project and exporter scripts were
not modified. Direct Ghidra output is not REA Evidence.

Reproduce the focused import into a new directory, then authenticate its report:

```powershell
python tools/focus_application_writer.py derived/my-application-writer
python tools/map_application_write_scope.py --focus derived/my-application-writer --output derived/my-application-write-scope.json
python -m unittest discover -s tests -p test_application_write_scope.py -v
```

The mapper checks36 independent Capstone assertions, every imported instruction
in the new writer, and14 retained application dossiers. It authenticates source,
analysis, focused input profile, Ghidra/JDK versions and unchanged exporter
hashes. The reusable metadata is
[application-write-scope.json](../evidence/application-write-scope.json);
vendor pseudocode and the new project remain local under`derived/`.

## Policy flags are not complete physical protection

The application handle supplies runtime erase-unit sectors at+`0x1240`, total
sectors at+`0x1244`, chunk bytes at+`0x1250` and data buffers at+`0x1254/1258`.
The writer calls map builder **0x803e1c28** and operation wrapper **0x80064744**.
Installed physical ranges still depend on geometry, zone mapping, previous
headers, spare metadata, bad blocks and failures.

The seven section records are0x24 bytes each; protected byte+`0x21` comes from
**0x803e17bc**. Its predicates agree with the separately checked updater family:
section3 requires upgrade1 and handle+`0x1270` equal1; section6 requires upgrade1
and zero burn sectors; other sections require nonzero reservation and zero
burn sectors. This agreement is independently checked in the application code.
It does not establish that a named section contains all calibration or settings.

Application block predicate **0x803d65d0** also considers old-header user units.
Helper **0x803d6558** uses old-header first-unit+`0x310`, count+`0x314` and a
nonzero upgrade byte+`0x234`, with inclusive32-bit endpoint
`first+count-1`. That old extent is protected in the block predicate only when
section6's protection flag is1. Other protected sections0..5 use a logical unit
decoded from spare metadata and runtime zone geometry.

A protected unit normally causes the writer to advance to another physical
unit. But the current section's separate record flag+`0x20` equal1 can select
a relocation branch: read the existing data, program and verify it elsewhere,
then erase the original unit. Consequently a protection flag cannot be read as
“no physical writes anywhere in that range.”

A zero section burn count skips its main-body consumption. Header, recovery and
bad-block-table finalization are separate paths and can still erase/program
flash. The full-erase path at handle+`0x1264` equal1 runs before the ordinary
per-block protection scan, below total blocks minus the backup reservation;
failures can additionally mark blocks bad.

## The actual supplied package policy

The supplied burn header at carrier0x100000 sets:

| Field | Observed value |
| --- | --- |
| Upgrade byte in payload header | `1` |
| Handle+`0x1270`, keep-section3 flag | `1` |
| Handle+`0x1264`, full-erase flag | `0` |
| Handle+`0x1272`, pre-burn relocation flag | `0` |
| Handle+`0x1273`, user-placement flag | `0` |

Thus this package does not select the force-full-erase or optional pre-burn
user relocation branch through those flags. This is narrower than a guarantee
that every installed calibration block is preserved: physical geometry, old
contents, other metadata writes and actual camera execution are unobserved here.

## Read and check helpers are not a backup API

Application **BlockIsBad 0x803d6990** reads two geometry-selected spare locations
through **0x803d6520**. If decoded status requests marking, it can call
**BlockMarkBad 0x803d6878**, which programs spare/status metadata through
operation7. This is independently established in the application namespace;
the helper's name does not make it passive.

**0x803d6b30** programs data with operation5, reads it with operation4 and
compares the erase-unit-times512 bytes. **0x803d6c88/0x803d7100** are stateful
user relocation/restore routines that erase/program flash. They do not stream
a full backup to the host. Their selection uses handle+`0x1272/1273`, separate
from the keep-section3 flag at+`0x1270`.

The operation wrapper **0x80064744** selects an alternate backend **0x80062688**
for operation4 when global byte`0x80069905` equals1; otherwise it calls
**0x80063aec**. Returned data can have ECC correction, and spare words are
transformed according to geometry and bus width. A logical read is not yet a
verified raw physical NAND/ECC representation.

Complete installed physical write bounds, calibration preservation, passive
host backup and unbootable software recovery remain false. The next missing
inputs are installed geometry/old boot headers/spare representation and a safe,
bounded host access route. No updater or diagnostic helper is exposed as a
camera-callable function by this map.
