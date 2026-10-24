# Gamma format and saved-photo integration gate

24 October 2026. Offline, source-bound Python/Capstone analysis of the original
v1.1 firmware. This is not retained REA Evidence or camera execution. No device
commands, candidate modifications, staging or flashes were performed by this
investigation.

## The 960 bytes are not three RGB curves

The embedded table at **0x80348344**, returned by HCE category 8, has size
**0x3c0 (960)**. Helper **0x8021bc90** selects legacy format **0x6200** from
that exact size, with no version header consumed. It reports 80 words for
the first section. Converter **0x8021bd3c** consequently partitions the resource
into **320 bytes followed by 640 bytes**; it does not iterate three channels.

The legacy expansion paths use little-endian packed base/slope words:

| Resource section | Expanded samples | Resource word selected for input x | Packed fields |
| --- | --- | --- | --- |
| First 80 words | 1024 | x < 64: 64 + floor(x/4); otherwise floor(x/16) | base bits 8..15, slope bits 0..7 |
| Following 160 words | 4096 | x < 4: x; x < 128: 128 + floor(x/4); otherwise floor(x/32) | base bits 8..19, slope bits 0..7 |

For the first section, the within-segment fraction is x mod 4 below 64 and
x mod 16 otherwise. The output is
`(2*base + floor(slope*fraction/128) + 1) >> 1`.
For the second section, the fraction is zero below 4, x mod 4 below 128,
and x mod 32 otherwise. The output is
`((2*base + floor(slope*fraction/128) + 1) >> 1) << 2`.

These formulae transcribe **0x8021c444..0x8021c49c** and
**0x8021be98..0x8021bf14**, respectively. They do not establish sensor/RGB/YUV
domain, channel order or hardware calibration requirements. The full converter
also constructs hardware tables and an inverse table. Its full output has
not been independently emulated.

The embedded table expands to monotone sequences spanning 0..255 and 0..4092.
The filesystem `GammaLut0.bin` produces an identical first expanded sequence,
but a different second sequence (three decreases, maximum 4080). Thus a
371-byte raw difference does not imply three differing colour channels.
Do not replace this resource with three 256-byte RGB LUTs or an ordinary
8-bit tone curve.

## Confirmed static downstream contracts

**0x8021c960** calls the cached loader, copies **256 u32** from the converted
allocation at **+0x194**, and frees that allocation. The length helper
**0x80234a20** returns 0x100 directly. This is a table extraction routine;
the earlier analyst label "channel extraction" did not establish a channel.

**0x801fdd40** constructs an IPP command with id 10, copying the extracted
256-word table to **command + 0x18**. Wrapper **0x801fde2c** requests this
resource-based command for selected mode flags. The aligned J/JAL scan finds
its only direct transfer at **0x807976ac**. This is incomplete static coverage,
not proof that ordinary capture cannot reach it indirectly.

Another path, **0x801fe17c**, selects a cached gamma command through
**0x801fe04c**, copies its table into a cache, then invokes hardware upload
**0x80191c94**. That uploader writes 256 u32 to **0xb60000b8**, then 128 packed
pairs to **0xb6000bbc**, while using the existing synchronization routines.
These MMIO addresses were read from instructions, never accessed on a device.

Calls at **0x8024b0c8** and **0x802a5e20** lead into that cached-table upload
path. Its data producers and the link from resource id zero to the table
selected for an ordinary saved still remain unestablished. A valid gamma
resource replacement could therefore remain inactive during normal shooting.

## Practical decision

No gamma firmware candidate is ready. Before a saved-photo look can use this
path, establish the table producer and active selection for normal still
capture, image domain and calibration constraints, then verify the full
conversion with an independent implementation or target observation. A
matched saved-JPEG comparison must follow before claiming a photograph effect.
Replacing a globally shared table does not supply a selectable Original mode.

The **GammaDDE** resources remain associated with a separate **DLCD** path
(**0x8022a5a4**, selectors 0x33/0x6c). Their simple 256-byte shape is useful for
display experiments, but it does not make them a simpler route to saved-photo
creative looks. Existing capture-effect processing and mode selection remain
a better integration lead than treating display gamma as photographic gamma.

## Reproduction

`python tools/map_gamma_pipeline.py` authenticates the original carrier and
analysis ELF, reconstructs the filesystem resource, expands both resources,
saves ten bounded MIPS32 listings and scans aligned J/JAL encodings. Use fresh
`--output` and `--listings` paths for subsequent runs. Evidence is
`evidence/gamma-pipeline.json`; listings and vendor bytes remain local under
ignored `derived/`.

`python -m unittest discover -s tests -p test_gamma_pipeline.py -v` passes five
tests covering size rejection, section separation, nonuniform boundaries,
slope rounding/reserved-bit masking and MIPS jump target reconstruction.
These validate the host model's stated contract, not camera execution.
