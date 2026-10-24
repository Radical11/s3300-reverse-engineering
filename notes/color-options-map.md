# Existing selectable colour effects

24 October 2026. Source-bound static findings, not device execution or REA
Evidence. The new startup-art candidate contains none of the changes discussed
below. `tools/map_color_options.py` reproduces the constants, dispatch-table
checks and seven compiler-unwind-bounded listings.

The existing Color Options handler at **0x805ac85c** stores the selected byte
at **+0x1a** in the structure pointed to by **0x808918ac**, at instruction
**0x805ac8cc**. The diagnostic `nColorEffect:%d;` corroborates the field's role.
The handler passes that selection to **0x807132d0**, alongside existing camera
state. This is a useful existing control route. A store to RAM does not prove
settings persistence or establish a safe standalone persistent-settings API.

The dispatcher has two different outputs. Values 2, 3 and 4 map to white-balance
modes 12, 13 and 17, but separately select effect IDs 4, 3 and 2. The downstream
white-balance setter **0x806d2b60** is explicitly identified by an
`AWB_SetWBMode` diagnostic. Those AWB numbers must not be mistaken for full
creative-look implementations.

The actual effect branch calls **0x806ac4dc**. Its cases for the existing
monochrome/tint modes set the chroma multiplier at **0x80835a10** to zero and
select offset pairs copied to **0x8087b8e4**:

| Effect case | Constant address | Signed 16-bit pair |
| --- | --- | --- |
| Cyanotype lead / ID 2 | 0x80882d20 | +24, 0 |
| Sepia lead / ID 3 | 0x80882d24 | -30, +30 |
| Neutral mono lead / ID 4 | 0x80882d28 | 0, 0 |

**0x806ac078** adjusts the six chroma matrix coefficients using the multiplier
divided by 256, with signed truncation. **0x806af434** builds a 0x34-byte command
with ID 15, nine 16-bit matrix coefficients and the first two offsets biased by
128, and enqueues it through **0x802233e8**. This is a compact existing matrix
and offset mechanism; its cost is preferable to assuming a new full-frame
software pass is needed. Its actual cost on this camera has not been measured.

A narrowly scoped tint experiment could eventually reuse the Sepia control and
constant pair. It would be a tinted monochrome treatment, not the host module's
full-colour Amber Days transform. Preserve Original/Standard color and avoid
changing white-balance algorithms merely to create a look.

Before constructing that experiment, finish command-15 hardware dispatch and
the saved-still versus live-view selection, establish other consumers of these
shared constants and the colour-domain/offset constraints, and confirm the
actual selection values. Then use matched saved JPEGs to determine whether the
look reaches photographs. A changed screen preview alone is insufficient.

These gaps remain explicit in `evidence/color-options-map.json`; no tint patch
has been staged or included in the Pocket Studio identity image.
