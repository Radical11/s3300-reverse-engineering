# Capture, processing and buffer contracts

24 October 2026. Independent offline Capstone findings from hash-authenticated
v1.1 carrier `2c44b1fd...d7a498b` and analysis ELF `15b39f40...42966040`.
These are not retained native REA Evidence and no camera execution occurred.
The new source-bound report is `evidence/capture-contracts.json`; 27 listings
remain local under `derived/capture-contracts/`.

## The colour command is retained, rather than always queued

The existing colour-effect path calls matrix adjustment **0x806ac078** for
numeric contexts **0x40 and 0xb0**, at **0x806ac624/0x806ac62c**. Its matrix
builder **0x806af434** passes a **0x34-byte command 15** to **0x802233e8**, which
calls **0x801fd324**. The earlier description of this wrapper as an unconditional
enqueue omitted an important branch:

| Condition on command+0xc | Observed route and retention |
| --- | --- |
| context != 0x90 | Tailcall **0x8023c7b8**, mark state dirty, copy payload to a retained cache |
| context == 0x90 | Allocate command length, copy the full command and pass it to **0x801f5614**, message **0x1046** |

Command 15 sets bit **0x00100000** of **0x808c1d78** at
**0x8023db0c..0x8023db28**. The normal-path cache slot is
`0x808c1d88 + 4*(74*context_index + 37*bank + command_subindex)`.
For id 15 the subindex is 15. **0x8023c778** maps contexts 0x40/0x50/0xa0/0xb0
to indices 0/1/2/5; other values return 8 and do not enter the ordinary cache
path. These numbers are not yet proven names for still, live view or playback.

**0x80234d4c** allocates/reuses a retained command object through
**0x80192c7c** and copies **0x1c payload bytes** from external command+0x18
to retained object+0x14. Thus this reviewed normal path does not retain the
builder's stack address. It does not prove lifetime of pointers embedded in
other command payloads. In the 0x90 route the receiver's completion/free
contract remains unresolved.

The external command has size at+0, id at+4, secondary id at+8, context at+0xc,
bank at +0x10, and payload at +0x18. The reviewed command 15 copies nine 16-bit
matrix coefficients, two halfword offsets biased by 128, a byte and a signed
halfword extended to a word. Final matrix hardware application and the context
used by an ordinary saved still remain open. A dirty-bit write alone is not
proof that a new matrix reaches a saved JPEG.

## RAW-to-YUV entry and descriptor boundary

The diagnostic-bound `DirectConvertRawToYuvEx` entry is **0x80205918**.
The older candidate **0x80205924** omitted the instructions that preserve
the first pointer and check the first two pointers for null. Treat that older
address as an interior location, not a callable entry.

The reviewed function requires descriptor pointers in **a0/a1** and an options
pointer in **a2**, with options+0xc also required. It copies **seven u32 words**
from each descriptor, offsets 0..0x18, into local structures at sp+0x24 and
sp+0x48. Options+0xc supplies four u16 values copied into another local command.
The additional field accesses and selected calls are recorded in JSON.

This establishes a descriptor-sized copying boundary, **not a usable frame
buffer API**. Width, height, pitch, planes, Bayer order, bit depth, physical
versus virtual addresses, cache maintenance, valid aliasing, underlying-buffer
lifetime and asynchronous completion are unresolved. No API header should
assign these meanings based on neighbouring strings alone. The reviewed block
has no compiler-unwind range; its listing is a bounded analyst window.

## JPEG constraints present in the compiled SDK

These diagnostic strings have concrete instruction references and local
guards. They describe compiled paths, not measured limits or confirmation that
the camera selects every path:

| Constraint | Diagnostic / reference |
| --- | --- |
| The path labelled C13 cannot directly encode 420 input; it requires ICA conversion to 422 and the existing LDC flag | 0x801abf58 / 0x801a4834 |
| Crop top and left must be even for 420 | 0x801ac044 / 0x801a4944 |
| Subimage height must be a multiple of 16 for 420 input or 420 JPEG output | 0x801ac204 / 0x801a6650 |
| JPEG decode to 420 output is unsupported in this path | 0x801ac2a0 / 0x801a6c88 |

At **0x801a4490**, input halfword +2 equal to 1 selects the conversion check;
the check at **0x801a4820** requires input flags +0x68 bit 0x40. The crop guard
checks an odd bit; the subimage guard checks low four bits. Their complete
operand/mode provenance is still partial. The literal C13 label does not
independently identify the physical SoC revision.

## Still versus preview and buffer ownership remain separate questions

The existing gamma path is more precisely constrained: calls at
**0x8024b0c8** and **0x802a5e20** pass classification 0 from
**0x801fe3c0(a0=0)** to **0x801fe17c**. The first call's selection is the
active structure word at **s4+0x3c**; the second is **stack+0x9c**.
The selector reads a cached command pointer from **0x808c1cf8**, choosing its
table at+0x150 when object+8 equals12 and+0x1b0 otherwise. Producers of those
commands and their relation to gamma resource 0 are still unestablished.

The diagnostic `psCapture->bUseSeperateYuvBuffer` is tied to an actual **u8
read at capture-base+0x1b3**, site **0x80309408**. The DNG-specific diagnostic
at **0x80343838**, referenced at **0x803336b8**, requires separate YUV and RAW
buffers. Neither diagnostic proves DNG is exposed on this camera or supplies
the allocation/ownership rules needed for a new image-processing pass.

Tuning-preview IPP and IPU entries are separately tied to diagnostics at
**0x8033bfd0** and **0x8033c650**. Their existence is not evidence that changing
preview changes a stored photograph. Runtime saved-JPEG comparisons remain
necessary after a complete static integration contract is established.

## Reproduce and next gates

`python tools/map_capture_contracts.py` authenticates both artifacts, checks ten
reviewed instruction words, binds 13 diagnostics, scans address-materialization
and direct transfer candidates, and writes six contracts plus 27 listings.
It refuses to overwrite earlier outputs; choose fresh `--output` and
`--listings` paths for repeats. No firmware candidate is generated.

`python -m unittest discover -s tests -p test_capture_contracts.py -v` checks
numeric boundaries/unsigned semantics, changed/truncated instruction rejection,
the real authenticated ELF when present, and static/runtime evidence separation.

Before implementing saved-photo looks, finish the dirty-bit consumer and matrix
upload, tie numeric contexts to the ordinary saved-still state, recover complete
buffer geometry/ownership/cache contracts, and prove a reversible recovery
route. Exact sensor and RAM/clock limits need additional evidence. This pass is
a partial map of six capture questions, not a claim that capture or all firmware
has been fully understood.
