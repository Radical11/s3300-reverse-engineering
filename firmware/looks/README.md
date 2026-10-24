# Compact creative-look module

Implemented C processing code, **not yet integrated into the S3300 firmware**.
The camera's capture-buffer ABI, colour domain, processor stage and controls
remain unverified. The current native build is x64 MSVC, not target MIPS code.

| ID | Look | Current treatment |
| --- | --- | --- |
| 0 | Original | Immediate bypass; pixel bytes unchanged |
| 1 | Flash Pop | Stronger contrast and brighter colour balance |
| 2 | Amber Days | Lifted blacks and a warm balance |
| 3 | Cool Night | Cooler balance and a restrained shadow curve |
| 4 | Mono Grit | Integer grayscale with a contrast curve and lifted blacks |

Mono Grit is currently tone-only: added grain, vignette, glow and smoothing are
absent. Aesthetic tuning is provisional. These are expressive treatments, not
claims of more recovered image detail or objectively better photographs.

## Runtime design

`s3300_look_row(rgb, pixel_count, look)` modifies a caller-owned interleaved RGB8
row or tile in place. It performs no allocation, floating point, full-frame copy,
OS call or spatial filtering. Three colour looks use three byte-table reads per
pixel. Mono computes `(77*R + 150*G + 29*B + 128) >> 8`, then reads one tone table.
The luminance coefficients approximate code-value luma; they are not a
linear-light luminance measurement or sensor-domain transform.

All tone interpolation, Q8 channel gains and channel offsets are fused when
the tables are generated. The table storage is **2,560 bytes**:
three looks × three channels × 256 entries, plus one 256-entry mono table.
That excludes compiled instructions and future integration/control state.
No three-dimensional LUT or GPU is required by this implementation.

The caller must supply a valid buffer containing at least 3*pixel_count bytes.
Invalid look IDs, null nonempty buffers and count overflow are rejected before
writing. The C API cannot determine whether an arbitrary caller pointer refers
to an adequately sized buffer; the capture adapter must enforce that contract.

Profiles are editable in `profiles.json`. Regenerate the tracked header with:

```powershell
python tools/build_creative_looks.py --generate
```

## Checks and actual host timings

MSVC compiled the module with `/O2 /W4 /WX`. Native lookup and native scalar
implementations agreed with the separate Python reference across a 4,096-pixel
RGB grid and 1,000 deterministic random pixels, for every look including Original.
Guard bytes, invalid arguments, overflow rejection and neutral mono were checked.
The generated header must match the profile definitions exactly.

On an original S3300 JPEG copy, every full-resolution native lookup result
matched the scalar reference by SHA-256. Each timing below is the median of five
kernel-only runs after one warm-up, on this Windows host:

| Look | 4608×3456 lookup ms | 4608×3456 scalar ms | 3264×2448 lookup ms |
| --- | ---: | ---: | ---: |
| Flash Pop | 15.43 | 247.03 | 8.27 |
| Amber Days | 15.06 | 232.82 | 8.30 |
| Cool Night | 15.32 | 256.71 | 8.34 |
| Mono Grit | 22.89 | 115.44 | 11.39 |

Evidence: `evidence/creative-look-host-benchmark.json`, including all repetitions,
maximum times, source/build hashes and output hashes. The input copy was unchanged.
The 8 MP input was resized on the host. Caller buffer preparation, JPEG decoding,
hashing and I/O were excluded from kernel timings.

**These are not camera timings or a comparison against Nikon's stock ISP.** Nikon
already has hardware/resource lookup stages. A faster implementation of our own
scalar look does not establish a faster camera, shot-to-shot gain or battery gain.

Reproduce with a new local directory and an original 4608×3456 S3300 JPEG copy:

```powershell
python tools/benchmark_creative_looks.py samples/original/DSCN0840.JPG derived/another-look-benchmark
python -m unittest discover -s tests -q
```

Native tests require MSVC build tools on Windows, or a C99 `cc`/GCC/Clang host
compiler on Linux. The optional JPEG benchmark also requires Pillow. Proprietary
firmware, compiled test libraries and personal image data remain under Git exclusions.

## Integration work still required

Find the actual still-photo processing domain, buffer layout, stride and ownership;
prefer adapting these small transforms into an existing hardware stage where
possible. Build with a matching MIPS toolchain/ABI, identify verified call sites,
add a selectable control and persistence, and measure capture impact on the camera.
The [embedded-resource finding](../../notes/embedded-resources.md) means filesystem
resource edits alone cannot be assumed to activate these treatments.

The compact lookup approach follows established image-processing practice;
[Jeremy Selan's GPU Gems chapter](https://developer.nvidia.com/gpugems/gpugems2/part-iii-high-quality-rendering/chapter-24-using-lookup-tables-accelerate-color)
explains precomputation, per-channel 1D tables and their cross-channel limitations.
This implementation uses an explicit mono calculation and 1D code-value tables;
it does not implement the chapter's GPU/3D-LUT system or claim a new algorithm.
