# Saved-JPEG processing and ownership

Status: **partial static contract; no callable capture SDK or camera code trial**.
The source-bound report is [saved-jpeg-path.json](../evidence/saved-jpeg-path.json).
Reproduce it with `python tools/map_saved_jpeg_path.py --output derived/saved-jpeg-path-repeat.json`.
The generator verifies the original firmware hash, authenticates every retained
instruction in 26 direct Ghidra dossiers, checks 34 fixed instruction words and
independently decodes three bounded thread/callback windows. These findings are
direct Ghidra/Capstone analysis, separately labelled from REA Evidence.

## Recovered processing route

`8023a030` forwards event `1042` to pipe 7. The `FileCompressor` thread is created
by `8031e060`; the original-byte window at `8031dfd0` receives that event and calls
`8031d0b4` with its object pointer. That routine has direct calls to StillImage
processor `8031aa5c`. These thread loop instructions were missing from the native
function dossiers, so the report retains their byte hashes and marks their
analyst-selected boundaries explicitly.

The StillImage processor uses a seven-word image descriptor at capture object
`+54`: address, parent width, parent height, left, top, ROI width, ROI height.
Its compression branch supplies that descriptor to ApsJpeg `8032b20c` through
argument structure `+0c`; output data/capacity originate at capture `+a8/+b0`.
Other branches assemble EXIF and thumbnail data via `80310c30` and `803133ec`.
The exact branch taken by an Auto-mode shutter press has not been observed.

JPEG create/go `8032b20c` opens a type-1 path, prepares it with `801975c8`, and
starts it with `801978f0`. It returns before the finish helper waits. Finish
`8032b0fc` calls `80197ac8`, obtains encoded length through `801a400c`, and takes
the corrective `801a40e4` route when the wait fails or the count exceeds capacity.
`8032b1a8` requires a nonzero path, finishes, deletes it through `8018e344`, and
returns its byte count. This is an asynchronous lifecycle, not a plain
in-place image conversion function.

## Format-specific address arithmetic

Later selector tracing in [pixel-layout.md](pixel-layout.md) establishes that
this helper models ApsJpeg argument `+8`, the address-layout selector. JPEG
input kind is a separate field at argument `+4`; both reviewed StillImage call
sites pass kind zero. Do not interpret the helper's selector one as proof of
YUV420 input. The original arithmetic observations below remain valid.

For JPEG selector 0, the input address is rebased by
`2 * (top * parent_width + left)` with 32-bit arithmetic. Selector 1 performs
separate rounded-down row and column terms:
`floor(low32(top*parent_width*3)/2) + floor(low32(left*3)/2)`.
Its chroma address comes from a supplied descriptor or from the rebased image
address plus `align16(low32(parent_width*parent_height))`.

These arithmetic rules identify distinct JPEG input layouts. They do **not**
establish universal RGB/YUV packing, component order, numeric range, stride,
buffer capacity or valid CPU access. In particular, applying the RGB creative
look module to either input is still blocked. The helper and tests deliberately
expose wrapping and separate rounding rather than silently replacing them with
host arithmetic.

Capture allocation `8030c010` aligns dimensions and, in its normal branch,
requests `width*height*2` bytes for capture `+54`. Optional percentage/HDR branches
change allocation and origin. Release `80325f1c` can free the pointer or use a
different pool route before clearing it. Therefore the descriptor is not a
stable frame slot that external code can retain after compression or cleanup.

## How encoded bytes reach a file

ApsSave segment append `8030e2d4` allocates a 32-byte list node and retains data
address/length at node `+8/+0c`. A 56-byte file-property object contains the list
at `+28`. EXIF and encoded image components become segments; the routine does
not deep-copy their data merely by appending them.

The Still server forwards saving events through `8023a05c` to pipe 3. The store
thread window at `8032c1b4` dispatches these arms:

| Event | Route | Consequence |
| --- | --- | --- |
| `1002` | `8032c004` -> `8030ed78` | Prepare, open, write and close a whole file. |
| `1059` | `8030eeb4` | Open shared file state for subsequent chunks. |
| `105a` | `8030ef84`, flags `0c` | Write/consume owned segments with the additional seek-related flag. |
| `105b` | `8030ef84`, flags `04` | Write/consume owned segments. |
| `105c` | `8030f2d8` | Seek the shared file state. |
| `105d` | `8030ef84`, flags `04` | Write/consume final segments and enter completion handling. |

`8030e9e0` iterates segments with callback `8030e7d4`. That callback passes the
file object, segment data address and segment length to filesystem write
`80097418`. Under flag 4, a successful write unlinks and frees **both the segment
data and its list node**. Producer ownership must therefore be transferred
correctly before queueing. A failure records a filesystem status, closes/frees
the file object and marks shared writer state failed; later chunks can be
dropped. A returned software status does not prove power-loss durability.

## Remaining work before a saved-photo hook

The static file pipeline is now substantially mapped. The remaining gates are
the shutter/sensor event producer, the active Auto-mode branch, exact buffer
packing/stride/capacity, and mode-dependent allocation/ownership. Cache/DMA
coherence must be proved at one selected hook while preview and the encoders
are active. Safe placement, the hook calling convention, complete backup and
recovery from an unbootable executable are also required.

No camera requests, firmware patches, capture adapters or executable trials were
performed for this report. Generic JPEG helpers and apparent data pointers are
research entries until those gates pass.
