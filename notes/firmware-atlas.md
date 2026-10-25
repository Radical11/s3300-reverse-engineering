# S3300 firmware map and remaining questions

24 October 2026. This investigation followed REA's
`reverse-engineer-anything` skill, including independent subsystem work,
source authentication, reproducible findings and an explicit unknown ledger.
The result is a reusable static map, not a claim that every instruction,
driver or physical hardware limit is understood.

## What is mapped and searchable

The local database is `derived/firmware-atlas-v1.1/atlas.sqlite`.
[Retained coverage metadata](../evidence/firmware-atlas.json) identifies it by
SHA-256. It contains:

| Material | Coverage |
| --- | ---: |
| Authenticated application regions | 8 |
| Compiler-provided function ranges with full linear listings | 5,798 |
| Bytes within those ranges | 2,267,704 |
| Direct call instruction candidates within those ranges | 48,303 |
| Unresolved register-call sites within those ranges | 300 |
| All direct/indirect transfer candidates, including jumps | 51,022 |
| Printable application byte sequences | 26,976 |
| Bounded address-materialization references to those sequences | 19,247 |
| Raw pointer-word candidates to strings/function entries | 8,729 |
| Original symbol records, retaining executable-artifact scope | 1,924 |
| Original executable artifacts inventoried | 6 |

All supplied carrier bytes were already preserved by the unpacked workspace.
This pass adds cross-references and semantic contracts. The function ranges
cover the recovered unwind metadata, not every function in the image. Low-level
code outside that coverage has separately reviewed windows. Some strings,
constants and pointer words may be incidental data. Associations do not rename
functions or declare usable APIs. Indirect dispatch and branch reachability
are not fully resolved. The complete linear listings are assembly, not original C.

```powershell
python s3300.py atlas --subsystem capture --limit 20
python s3300.py atlas --search DirectConvertRawToYuvEx
python s3300.py atlas --address 0x80737664
python s3300.py atlas --address 0x80737664 --assembly
python s3300.py atlas-build derived/my-new-atlas
```

Queries open SQLite read-only and return bounded results; `--limit` defaults
to 20 and caps at 1,000. Address queries include containing function metadata,
incoming/outgoing transfer candidates, diagnostic associations and pointer
references. `--assembly` includes the stored full listing when a known function
contains the address. Other addresses can still have reference results.
Use `--database` for a different generated atlas. Searches are literal text.
The local index is trusted as a generated research artifact; queries check its
source metadata but do not reauthenticate every row. Compare the database hash
with `manifest.json` or rebuild when its provenance is uncertain.

## Recovered contracts

| Area | New concrete result | Still needed |
| --- | --- | --- |
| DRAM | `0x8003c3ac` reads `0xb8002010`; checked selectors 1..6 report 8..256 MiB; allocator initialization consumes this API | Actual register value and free-headroom measurements |
| Clocks | `0x80025198` indexes 56 runtime u32 values at `0x808a5b8c`; clock diagnostics use Hz | Table contents/initialization, clock identities and operating values |
| GPIO | Group table at `0x800a2264`, record stride `0x54`; pin access uses table base+`0xc+4*pin` | Board wiring, mux, valid bounds and ownership |
| RTOS/allocator/DMA | Reviewed semaphore, pool-dispatch and DMA descriptor offsets | Complete statuses, pointer meanings, lifetime and cache contracts |
| Image conversion | Corrected RAW-to-YUV entry `0x80205918`; seven u32 copied from each descriptor | Frame geometry, format, pointer ownership, coherence and completion |
| Colour command | Command 15 retains payload synchronously for ordinary contexts; context `0x90` queues a copied command as `0x1046` | Dirty-state consumer, final hardware application and saved-still context |
| JPEG | Source-bound 420 conversion and alignment checks | Active camera formats and complete conditional guards |
| Menus | Selection-entry layout, Color Options event dispatch and dynamic view-bank selection | Physical event meaning and complete registration/ownership |
| Settings | Setup/view blocks stage into a shared store; transaction `0x80009644` reaches a media router | Physical write bounds, checksum semantics, atomicity, wear and runtime persistence |
| USB/debug | Dispatcher record layout; GetMem/SetMem internal indices `0xf3/0xf2`; receive flag and call arguments | Active endpoints/modes, full state framing and a safe host interface |

Detailed checked instructions, tables, bounded listings and limitations are in
[hardware contracts](hardware-contracts.md), [capture contracts](capture-contracts.md)
and [state contracts](state-contracts.md). Those reports take precedence over
older candidate labels. Specifically, `0x80205924` is an interior address rather
than the recovered RAW-to-YUV entry, the colour-command wrapper is not always
an enqueue operation, and UI settings now have a traced media-transaction lead
beyond the earlier RAM-copy findings.

## Checklist and evidence boundaries

Each subsystem has a searchable inventory. The statuses below refer to semantic
understanding, separately from index coverage:

| Subsystem | Status | Boundary / next evidence |
| --- | --- | --- |
| Container, decoding and resources | Answered for supplied bytes; interpretation partial | Opaque formats and absent logical-volume tail remain explicit |
| Function references and executable scope | Answered for the stated static scan | Functions lacking unwind data, indirect targets and full control flow remain open |
| Sensor | Partial | Compiled driver/capability leads; exact sensor and active register contract unknown |
| Capture | Partial | Entry/descriptor copies recovered; complete saved-photo ABI unknown |
| Image processing | Partial | Gamma and colour retention contracts; active saved-still matrix path unknown |
| JPEG/video | Partial | Reviewed guards plus stock formats; encoder pipeline and runtime budgets incomplete |
| Display/preview | Partial | Resource, DLCD and preview leads; framebuffer geometry/synchronization unknown |
| UI/buttons | Partial | Existing dispatch/selection state; complete events and custom registration unknown |
| Settings | Partial | Store layout and media transaction traced; safe standalone persistence contract unknown |
| Memory | Partial | DRAM selector and allocator leads; installed RAM/free heap unknown |
| RTOS | Partial | Library/context and selected synchronization behavior; scheduler policy incomplete |
| Storage | Partial | FAT extraction and media routes; flash/ECC/calibration geometry unknown |
| USB | Partial | Standard file readback already demonstrated; diagnostic transport remains unverified |
| Power/clocks | Partial | Getter/configuration leads; live frequencies, sequencing and energy unknown |
| Lens/flash | Inventory leads | Existing diagnostic strings/references; actuation/timing/calibration contracts incomplete |
| Update/recovery | Partial; recovery unresolved | Known candidates/install observations do not establish complete backup or restore |
| Debug/profiling | Partial | Counter contracts and dispatch mapped; safe external invocation unresolved |
| Peripherals | Partial | GPIO and high-address candidates; board wiring and full MMIO meanings unknown |
| Resources/audio | Partial | All allocated files extracted; supported codecs understood selectively, playback ownership incomplete |

REA artifact inspection returned Evidence
`ev_1ca5f2044796987f799ba099c30d85699321761a5984e602fb08837e39b236a7`,
authenticating the analysis ELF's identity/inventory. Its full record is in
[`rea-mapping-analysis-artifact-2026-10-24.json`](../evidence/rea-mapping-analysis-artifact-2026-10-24.json).
It does not provide native decompilation or validate these inferred contracts.

The actual REA native-function request failed with `capability_unavailable`:
this installed Windows Ghidra adapter admits PE targets, while this target is
MIPS ELF. Ghidra/JDK are also unconfigured. The returned IDA and Hopper adapters
do not admit this MIPS target. The error is retained in
[`rea-mapping-native-function-2026-10-24.json`](../evidence/rea-mapping-native-function-2026-10-24.json).
The existing Docker Linux engine could not start within its 90-second startup
window. No native decompiler output is claimed. No global REA registration,
approval setting, firmware byte or camera state was changed for this pass.
The atlas and the three subsystem reports are explicitly independent
Python/Capstone findings following the REA workflow.

## Verification and reproduction

All **186 offline tests pass locally**. A second full atlas build produced an
identical database and manifest. All three deeper mappers were rerun into new
local paths; their evidence agrees apart from the expected listing paths.
Tests cover instruction decoding arithmetic, function boundary ownership,
literal searches, clobber/control-transfer limits, malformed table/byte
rejection and evidence/runtime separation. They do not run camera code.

```powershell
python tools/map_hardware_contracts.py --output derived/new-hardware.json --listings derived/new-hardware-listings
python tools/map_capture_contracts.py --output derived/new-capture.json --listings derived/new-capture-listings
python tools/map_state_contracts.py --output derived/new-state.json --listings derived/new-state-listings
python -m unittest discover -s tests -q
```

Choose new output/listing paths. Firmware-derived assembly/databases remain
local under ignored directories; tools, metadata and these reports can be
versioned. No device commands, card writes or new firmware trial occurred.
