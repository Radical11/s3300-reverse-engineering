# Image frame descriptors and temporary-buffer lifetime

25 October 2026. This pass follows the RAW-to-YUV lead through descriptor
setters, JPEG setup and generic path execution. It uses the authenticated
supplied v1.1 image and nine retained direct Ghidra dossiers. Every instruction
in those selected dossiers is independently compared with the analysis ELF;
35 exact reviewed instruction words and five diagnostic bindings anchor the
contracts. No device command, firmware edit or camera execution occurred.

The machine-readable report is
[`capture-buffers.json`](../evidence/capture-buffers.json). Ghidra pseudocode and
inferred signatures are analysis evidence, separately identified from native
REA Evidence. The model functions in `tools/map_capture_buffers.py` are pure
host transcriptions, not newly safe device interfaces.

## The shared descriptor has seven u32 fields

The previously unidentified 28-byte structure now has stronger field meanings.
JPEG setup **0x801a4490** copies a descriptor beginning at options **+8** into
one of the path's frame slots. Its explicit assertion names
`psImageFrame->uiHeight`, `uiWidth`, `uiFrameWidth` and `uiLeft`, corroborated by
their loaded offsets and the actual comparison. The optional chroma descriptor
starts at JPEG options **+0x24**, with the same seven-word layout.

| Descriptor offset | Width | Recovered role |
| --- | --- | --- |
| +0x00 | u32 | Buffer/address token, copied into path buffer slots |
| +0x04 | u32 | Parent frame width |
| +0x08 | u32 | Parent frame height |
| +0x0c | u32 | ROI left coordinate |
| +0x10 | u32 | ROI top coordinate |
| +0x14 | u32 | ROI width |
| +0x18 | u32 | ROI height |

These are coordinate extents, not established byte pitches. They do not specify
interleaving, plane sizes, sensor bit depth, CPU/device address aliasing or
cache ownership. The data field is not demonstrated to be a CPU-readable RGB8
buffer. No arbitrary pointer is dereferenced by the host descriptor decoder.

JPEG setup rejects zero ROI width or height. The reviewed horizontal bound is
**frame_width >= low32(left + width)**. The addition at **0x801a4564** wraps
without an overflow guard before unsigned comparison at **0x801a4734**. A
syntactically passing guard can therefore describe an invalid wrapped extent.
Vertical containment and physical allocation capacity are not established by
this reviewed guard. For the 420 chroma path, left/top must be even, tested at
**0x801a48ec / 0x801a4930**. This is a path-specific constraint, not a complete
format validation API.

## Descriptor copying does not transfer frame ownership

Generic setter **0x80190a4c**, for path/driver type zero, copies seven words into
**path+8** for selector 7 and **path+0x28** for selector 9. The RAW-to-YUV wrapper
calls those selectors at **0x80205c40 / 0x80205c60**. Selector 8 copies another
descriptor into **path+0x860** and sets byte **+0x87c**.

Only the descriptor words are copied, including its data-address token. The
image bytes are not deep-copied by these setters. A caller must retain the
underlying buffers for the consumer's lifetime; the exact capture ownership
and synchronization contract is still not known.

Geometry setter **0x8018e9f4** has a different zero convention from JPEG setup:
if either ROI dimension is zero, both dimensions fall back to the parent frame
dimensions. Left/top remain copied. Buffer setter **0x8018ff74** separately
stores nonzero address tokens at **path+8, +0x28 and +0x48** and marks bit 0 of
**path+0x68**. That division between pointer and geometry updates is important
when retaining/restoring a temporary path.

## A concrete temporary scale-buffer lifecycle

Helper **0x8018f200** may construct an intermediate frame while scaling. It
sets ROI left/top to zero, derives width/height and requests:

```
low32(width * height * numeric_format_multiplier)
```

The reviewed branch uses numeric multipliers **2 or 3**. Their meaning must not
be promoted into universal bytes-per-pixel or camera-format declarations. The
low-32-bit products at **0x8018f4a8 / 0x8018f4b0** reach allocator
**0x80020980** at **0x8018f4dc**. The result is stored in descriptor+0 at
**0x8018f4e4**. This narrow window has no multiplication-overflow check or
immediate null-result branch. The pure model exposes overflow rather than
silently improving the target's behavior.

Wrapper **0x8018f6e4** calls prepare, **0x801975c8**, run/start
**0x801978f0**, completion helper **0x80197ac8**, then cleanup
**0x8018f184**. The completion helper conditionally calls event wait
**0x800c1014** using timeout state at path **+0xac**, then invokes a
type-specific indirect completion callback. Full event meaning, callback
success, interrupt behavior and DMA cache maintenance remain unproven.

When the temporary path differs from the original, cleanup restores pointers
through **0x8018ff74**, destroys the temporary path through **0x8018e344**,
and frees the temporary descriptor's data token via **0x80020e94** at
**0x8018f1d0**. It then restores geometry through **0x8018e9f4**. Therefore
the intermediate buffer belongs to this lifecycle; a new hook cannot retain
it after cleanup as an extra frame or assume it remains allocated.

Alignment helper **0x80191fd4** separately rounds frame width to a multiple of
16, with height rounded to 8 in mode zero and 16 in mode one; other modes take
a diagnostic rejection. Normal nonoverflowing alignment arithmetic does not
establish the camera's actual output format or maximum dimensions.

## The original wrapper is not an established capture hook

The analyst entry **0x80205918** is still a valid source-bound instruction
window with RAW-to-YUV diagnostics. However, the complete aligned-word scan
across all eight authenticated mapped regions finds **zero J/JAL encodings
targeting it and zero direct aligned pointer words**. The full retained native
application export also has no function dossier at that entry.

This is a bounded negative result. It does not exclude computed addresses,
unaligned data, another resident image or runtime dispatch. It does mean that
the wrapper's existence cannot be used as evidence that ordinary saved-photo
capture calls it. The shared descriptor and generic scale-lifecycle results
are useful independently, but they do not supply an on-camera RGB8 adapter.

## Remaining blockers and reproduction

The missing contracts are the active saved-JPEG caller and its live frame
values; packing, pitch and bit depth; CPU/device address domains; complete
capture allocation/aliasing/lifetime; cache/DMA synchronization; and a safe
executable hook with verified software recovery. These remain explicit in the
report. `safe_capture_adapter_established` and executable-trial readiness are
both **false**.

```powershell
python tools/map_capture_buffers.py --output derived/new-capture-buffers.json
python -m unittest discover -s tests -p test_capture_buffers.py -v
```

The mapper defaults to the preserved unpacked workspace and
`derived/native-analysis-complete`; alternative `--workspace` and `--native`
paths must have matching source identities. Existing evidence is never
overwritten. Tests cover descriptor endianness/size, zero-size conventions,
exact bounds, overflow, context-specific chroma alignment, invalid fields,
changed native bytes and bounded reference scanning.
