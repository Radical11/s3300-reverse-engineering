# Camera hardware, stock limits and development gaps

Checked 24 October 2026. The queryable source of truth is
[`hardware/s3300.json`](../hardware/s3300.json): run `python s3300.py limits`,
optionally with `--search` or `--json`. Every entry includes its evidence level,
scope and source references. This is a catalog of known constraints and open
questions, not a claim to have discovered every hardware limit.

Nikon's [Japan specifications](https://nij.nikon.com/products/lineup/compact/s3300/spec.html)
and [Canada specifications](https://en.nikon.ca/p/coolpix-s3300/26311/overview)
were read directly. They establish the published camera modes and physical
features; they do not provide a processor datasheet or memory schematic.
They disagree on maximum aperture (f/3.5 versus f/3.3 at wide angle), so that
item is explicitly unresolved in the catalog.

## Limits have different meanings

| Category | Examples | What we can conclude |
| --- | --- | --- |
| Physical specifications | CCD, fixed lens, lens-shift VR, display | Describe the camera; do not expose driver APIs |
| Stock software modes | JPEG resolution, burst rate, video modes, clip duration | Document shipped behavior; do not prove an absolute hardware ceiling |
| Recovered firmware contracts | MIPS ELF layout, gamma formats, counter buffers | Support static development work within the documented evidence |
| Tool/build constraints | Fixed extents, compressed-block budgets, source hashes | Bound candidate construction, independently of sensor capability |
| Calculated requirements | Full-frame RGB8/16-bit memory costs | Useful arithmetic; do not establish installed RAM or real buffer layouts |
| Unknown capabilities | RAM, clocks, sensor registers, DMA and recovery | Need new evidence before making engineering assumptions |

The approximately 42 MB internal image store is not a RAM specification.
Firmware virtual addresses are not a RAM capacity measurement. The NAND monitor
loop's nominal 32 MiB data span is not a flash geometry measurement. Library
strings do not identify the exact processor. Display dots are not a confirmed
framebuffer geometry.

## Hardware questions that matter for software improvements

| Missing contract | Evidence needed | Features it unlocks |
| --- | --- | --- |
| CPU/SoC identity, clocks and target ABI | Hardware/configuration identification plus validated runtime evidence | Correct cross-compilation and meaningful CPU budgets |
| RAM and allocator headroom | Controller geometry or bounded runtime allocation data | Safe buffer sizes, tiles and caches |
| Sensor and ISP readout/control | Identified sensor interface and active processing command paths | Exposure work, supported image transforms and possible RAW research |
| Saved-photo buffers | Pointer, shape, stride, domain, ownership, coherency and lifetime | Integrating the existing creative-look module |
| Preview/OSD buffers and scheduling | Display format and synchronization contract | Overlays and responsive controls |
| Settings persistence and UI ownership | Stable menu dispatch and storage contract | Selectable looks that survive restart |
| Bounded telemetry access | Proven transport to the recovered profiling APIs | Choosing optimizations from real costs |
| Complete backup and restoration | Flash/calibration scope, readback integrity and a usable restore path | Recoverable iteration on executable changes |

These are research targets, not promises that every proposed feature is
physically feasible. No camera benchmarks, debug commands, register accesses,
new firmware trials or hardware modifications were performed for this catalog.
The existing `Welcome studio` and Pocket Studio artwork observations apply to
their recorded candidates; they do not establish arbitrary patch reliability.
