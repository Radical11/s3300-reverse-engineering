# S3300 findings and next experiments

Date: 23 October 2026. Status: initial offline reverse engineering and algorithm
prototype; hardware integration remains unresolved.

Continuation: [processing pass 2](processing-pass-2.md) confirms the connected
camera, imports eight original v1.0 JPEGs, evaluates a shadow-lift candidate,
and identifies 463 encoded blocks in the application ELF segments. This adds
detail to the original ELF observations; their compressed payloads are not
ready for direct instruction analysis.

## Scope and identity

The user wants fun custom firmware, prioritising image processing and
efficiency. Their camera reports firmware 1.0. They supplied
`Downloads/F-S3300-V11W.exe`, which we copied locally and extracted with 7-Zip.
No updater executable or extracted camera program was run.

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| F-S3300-V11W.exe | 7,362,200 | `5285c78ff6e6b4619847165df4961ae5420f43f78c23a088d05d419ca2bb98ae` |
| firmware.bin | 19,005,632 | `2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b` |

Nikon's [v1.1 release page](https://downloadcenter.nikonimglib.com/en/download/fw/60.html)
describes a charging fix for an exhausted EN-EL19 battery. It does not promise
image-processing upgrades. The downloaded update is not a full v1.0 backup,
nor proof that calibration, settings or recovery data are preserved in it.

## Executables recovered

`tools/map_firmware.py` used pyelftools to parse headers, program segments,
sections and symbols, then derived bounded file-backed extents. All six are
ELF32 little-endian MIPS executables. Their proposed roles beyond the named
first image remain hypotheses.

| Firmware offset | Carved bytes | Declared entry | Sections | Symbols |
| --- | ---: | --- | ---: | ---: |
| 0x00000200 | 0xc4cde | 0x80010000 | 34 | 1,924 |
| 0x001006c0 | 0x1e98 | 0x81000401 | 8 | 0 |
| 0x001026c0 | 0x107f04 | 0x80000600 | 0 | 0 |
| 0x002202c0 | 0x19d6e8 | 0x80000600 | 0 | 0 |
| 0x003bd9a8 | 0x2051d0 | 0x80000600 | 0 | 0 |
| 0x005c2b78 | 0x13b524 | 0x80000600 | 0 | 0 |

The symbol count includes file, object, undefined and function entries; it is
not 1,924 recovered functions. An additional ELF-magic match at 0x1d0d64 failed
header validation. Carved extents are not update-container partition lengths.

ThreadX and FileX identification strings appear at 0x8e0d4 and 0x9207c.
The image also contains Zoran COACH identifiers and MIPS toolchain metadata.
The `ThreadX LX4180` library string does not establish the actual CPU model,
clock, RAM capacity, or exact COACH generation. The tiny ELF's odd entry and
different flags need ISA-mode investigation; the disassembler used below is
not a MIPS16 decoder.

## Update integrity: one actual path traced

The first ELF contains named `BurnHash*` routines. Capstone decoded the complete
declared byte ranges of 15 selected functions; listings include original
firmware offsets and symbolized direct calls.

`BurnHashManager` at **0x8001b68c**, firmware offset **0xbb04**, receives queue
messages and calls:

- `md5_init` at 0x800443b4;
- `md5_append` at 0x800443f0;
- `md5_finish` at 0x80044534;
- `memcmp` at 0x80085840, with a 16-byte length.

This establishes a statically decoded MD5 comparison path. It does **not**
establish which whole update ranges it covers, where its expected digest comes
from, that every update uses it, or that there are no other checks/signatures.
No checksum fixer or repacker has been produced.

`DebugConsoleMain` at 0x800482c8 reads characters through UART-named routines
and calls `MonitorPreParse`. This supports a debug-console implementation in
this image. Physical pins, electrical levels, enablement and access on this
camera are unknown. Console access has not been demonstrated.

## Resource filesystem recovered

At **0x6fe2c0**, boot/BPB fields and directory/FAT chains establish a FAT16
resource filesystem with OEM `ZORAN`, volume `RESOURCE_A`, 512-byte sectors,
1,024-byte clusters, one FAT and 512 root-directory slots. FAT begins at
0x6fe4c0, root directory at 0x7052c0 and data at 0x7092c0.

The extractor recovered **368 regular files and 7 directories**, totalling
**11,246,707 file bytes**. Every extracted file was hash-checked against its
original cluster bytes; no loops, crosslinks or out-of-carrier allocated file
clusters were found. All allocated data-cluster entries were referenced.

Two caveats are preserved in `evidence/resource-filesystem.json`: the logical
volume extends **2,611,712 bytes beyond the supplied carrier**, and its first
reserved FAT entry encodes the media byte nonstandardly. The live little-endian
chains validate independently. A trimmed free tail is a plausible explanation;
we have extracted all parsed allocated files, not reconstructed a complete
logical volume or device flash.

Useful resources include `GammaDDE1.bin` through `GammaDDE4.bin`,
`GammaLut0.bin`, `Lclut0.bin` through `Lclut2.bin`, `JPG/Startup1.jpg`,
`Wav/Startup1.wav`, and `String/Res_Str_Eng_New.bst`. `Comic.bin` contains a
Comic Sans name and is a font candidate, not evidence of a comic-photo effect.

## Image processing: concrete first target

The four GammaDDE resources each hold 256 bytes. DDE1 equals the identity map
0 through 255 exactly. DDE2/3/4 are monotonic, with output 255 beginning at
inputs 228/202/186. This is strong evidence for tone-mapping-like data, while
the active modes, consumer function and input domain remain unknown.

The 512-byte Lclut files contain 256 little-endian 16-bit entries. Lclut0 equals
16*i; Lclut1 equals 4080-16*i; Lclut2 is monotonic over 0..4095. GammaLut0 is
960 bytes with a different packed-looking layout. These formats are not
interchangeable.

We built an **offline** gentle tonal-lift candidate in `prototype/`: a 256-byte
table, C initializer and complete CSV. Every input was checked for range,
monotonicity and endpoints. This demonstrates a small algorithm artifact; it
does not establish correct camera integration, superior image quality or any
speed/energy gain. Nikon already has lookup-like resources.

The most defensible next image-processing work is:

1. Recover the resource-ID/loader-to-image-pipeline path for the gamma and Lclut
   tables. Determine luminance vs RGB operation, bit depth, range and mode.
2. Compare stock and candidate mappings on original S3300 photographs, including
   skin, shadow noise and bright gradients. Define intended effects before
   judging vendor curves; intentional clipping can be part of an effect.
3. Recover preview-buffer and OSD APIs before attempting zebras, histograms or
   focus peaking. These need code, buffers and timing, not only a resource edit.
4. Investigate denoise only after the sensor/ISP boundaries and RAM budget are
   known. Prefer existing accelerator parameters, small kernels or tiled work.

One 4608x3456 frame takes 31,850,496 bytes in unpacked 16-bit form or 47,775,744
bytes in RGB8, excluding working memory. Those are arithmetic requirements,
not evidence of this camera's installed RAM. Multi-frame or neural algorithms
cannot be assumed practical.

## Efficiency: measurement gate

The image contains `OsSysDumpCpuLoad`, `CpuPerformanceMonitorStart/Read`,
display/sensor frame-rate strings, and raw-to-YUV timing labels. For example,
0x1bbd1c labels the beginning of raw-to-YUV conversion and 0x1bc319 labels the
main-image IPU stage. These are profiling leads; no timings or power readings
have been measured.

First establish stock capture latency, preview FPS, CPU load, memory headroom,
and energy per shot. Then investigate unnecessary copies, polling, redraws and
avoidable processing. Preserve watchdogs, power sequencing, lens timing and
sensor limits; changing them is not an evidenced efficiency improvement.

## Tool evidence and limits

The cached reverse-engineer-anything skill v37 / REA 6.4.0 guided the work.

- REA updater PE resource inventory: `evidence/rea-updater-pe-resources.json`,
  Evidence `ev_3c7aa4703d54757e818a81b2365266723b5d9e5de361ff48212cca1fded32706`.
- REA carved-boot artifact inventory: `evidence/rea-boot-artifact.json`,
  Evidence `ev_38023cc48e95cd2fd0e42b6ce9b36424641180ddfbc2fecc9909c342464731fb`.
  This binds the child's digest/format; its architecture field is unknown.
- ELF/FAT parsing and function decoding are independent Python/pyelftools/
  Capstone findings, not REA decompiler output or runtime Evidence.
- REA's `inspect_firmware_regions` returned `capability_unavailable`: the
  integration requires Linux and caller-supplied Binwalk. No repeated call.
- Native engines are unconfigured. Deep MIPS decompilation is not complete.
  The existing bundled Node 24.22.1 works for CLI use; default Node 25.6.1 is
  outside this REA release's supported range.
- A read-only Codex setup plan is saved. No global registration, skill
  installation, PATH, Node, Java, Ghidra or Hopper change was applied.

## Remaining gates before any camera patch

The exact resource consumer, complete update layout/integrity rules, model and
version acceptance, flash write ranges, v1.0 backup/calibration coverage and a
tested recovery route remain unresolved. No camera was detected by the initial
Windows PnP name check; USB probing and hardware profiling have not happened.

The next native-analysis step needs a MIPS-capable disassembler/decompiler
environment. The next runtime step needs the actual camera and a verified
transport/debug route. Neither is replaced by the offline LUT prototype.

For context only: upstream [libgphoto2](https://raw.githubusercontent.com/gphoto/libgphoto2/master/camlibs/ptp2/library.c)
lists S3300 PTP capture at USB 04b0:032a; the project's
[remote table](https://gphoto.sourceforge.io/doc/remote/) reports limited
configuration and no liveview. CHDK and the inspected
[Nikon Patch model list](https://simeonpilgrim.com/nikon-patch/nikon-patch.html)
do not supply an S3300 firmware solution. Adjacent
[Lytro research](https://github.com/ea/lytro_unlock) is useful methodology,
not compatible firmware or proof of the same hardware.
