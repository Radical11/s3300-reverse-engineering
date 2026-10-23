# Processing pass 2: device samples and encoded application segments

23 October 2026. This continues the initial offline investigation.

## Actual device samples

Windows now detects the S3300 through its existing WPD driver at USB VID 04b0,
PID 032a. Windows Shell exposes `S3300/DCIM/100NIKON`.
Eight photographs were copied into `samples/original/`: DSCN0840, DSCN1136,
DSCN1140, DSCN1144, DSCN1148, DSCN1152, DSCN1156 and DSCN1160.
All eight are 4608x3456 JPEGs whose EXIF reports Nikon COOLPIX S3300 and
`COOLPIX S3300V1.0`. See `evidence/camera-samples.json` for hashes.

The operation requested copying only. No source-file deletion, driver change,
camera settings change, firmware command or flash operation was issued.
The images are private local inputs and are ignored by Git.
After copying, the camera's folder still listed all 26 items and all eight
chosen originals. See `evidence/camera-post-copy-check.json`.

Nested EXIF also exposes a major comparison confound: seven of the eight shots
record **-1.3 EV exposure compensation**; DSCN0840 records 0 EV. Their ISO values
range from 80 to 800. This is the setting at capture time, not a readback of the
camera's current setting. The dark appearance cannot be attributed to a firmware
bug from these samples. A useful stock baseline should include 0 EV captures of
the same scene before attributing a gain to an algorithm. The values are saved
in `experiments/shadow-lift-v1/capture-settings.json`.

## Reproducible processing experiment

`tools/evaluate_tone_curve.py` produced full-resolution lossless PNG derivatives
and before/after comparisons under `experiments/shadow-lift-v1/`.

The candidate is a piecewise linear luminance lift, generated with integer
arithmetic from these anchors:

| Input Y | 0 | 8 | 24 | 64 | 112 | 176 | 224 | 255 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Target Y | 0 | 8 | 34 | 90 | 138 | 186 | 224 | 255 |

It computes an integer RGB8 luminance estimate, obtains a delta from a 256-byte
table, limits that delta to RGB headroom and adds it equally to the channels.
The curve is identity for deep black and luminance 224..255. Maximum lift is
26 code values. RGB headroom limiting can stop a coloured pixel from reaching
the target luminance; this is deliberate and measured separately from the LUT.

All 256 grayscale inputs matched the candidate table. A 4,096-sample RGB grid
passed brightness, lift-bound and high-luminance invariants. The input hashes
were checked again after processing. Every actual sample had **zero changed
pixels whose original estimated luminance was 224 or higher**.

For DSCN1152, image median estimated luminance changes from 69 to 95. The
before/after preview makes the shaded face easier to see, while scene rendering
remains subjective. Lifting dark pixels may reveal more noise; the operation
does not recover clipped data or denoise anything.

`prototype/shadow_lift.h` contains a small row-oriented C design with no
full-frame working buffer. It is **not compiled or tested on this machine**;
the Python/NumPy implementation is the executed reference. No camera ABI,
buffer format, firmware resource ID, integration or energy benefit is claimed.
Nikon already uses LUT-like resources, so small table size does not establish
an improvement over stock firmware.

Applying a curve to an already-developed JPEG is not equivalent to changing a
sensor/ISP-stage table. These results help choose an intended appearance before
firmware integration; they do not validate substituting a GammaDDE resource.

Reproduce into a new directory:

```powershell
python tools/evaluate_tone_curve.py samples/original experiments/new-shadow-test
```

## Encoded application data: corrected interpretation

The original ELF carving was correct, but four program segments contain an
encoded representation rather than immediately usable instruction bytes.
Their declared memory sizes must not be filled by copying the compressed
file payload and calling the rest BSS.

The following framing interpretation was independently inferred and verified
across all four payloads:

| Block field | Encoding |
| --- | --- |
| +0x00 | u32 little endian, observed value 2 |
| +0x04 | u32 declared output length |
| +0x08 | u32 encoded payload length |
| +0x0c | u16 table A byte length |
| +0x0e | u16 table B byte length |
| +0x10 | table A, then table B, then encoded payload |

The next block is exactly `start + 16 + tableA + tableB + payload_length`.

| Segment root offset | Blocks | Encoded bytes | Sum of declared output bytes |
| --- | ---: | ---: | ---: |
| 0x220314 | 151 | 1,693,332 | 2,630,016 |
| 0x3bd9fc | 195 | 2,118,012 | 3,094,784 |
| 0x5c2bec | 86 | 993,716 | 1,601,792 |
| 0x6b55a0 | 31 | 297,724 | 624,000 |

Every block fits its segment. Encoded byte sums consume each ELF `p_filesz`
exactly; output-length sums match each `p_memsz` exactly. This corroborates
the framing but does not independently verify decompressed contents.

`tools/inspect_packed_segments.py` and `evidence/packed-segments.json` retain
the source/destination ranges, table/payload sizes and hashes for all blocks.
Destination addresses describe declared layout, not observed device memory.

The readable primary ELF has a segment-inflater worker at VA 0x800dfcd8,
root offset 0x1e1fc0. Its stream-processing call is at VA 0x800edb74.
The processor routine at VA 0x800ee0d0 feeds words through a memory-mapped
address 0xb9800024. This is a static disassembly observation, not a device write.
`tools/trace_loader.py` saves the source-bound disassembly windows and their
hashes in `evidence/loader-pass-2.json`.

Raw-DEFLATE probes did not yield a validated decode. The tables may be a
hardware-ready Huffman/token representation; the exact entropy decoder remains
unknown. Standard gzip/zlib handling must not be assumed from the word
`Inflater` alone.

## Next firmware step

A bounded Windows WPD COM probe now confirms the live device identifies as
Nikon Corporation / S3300 / **COOLPIX S3300 V1.0**, protocol `MTP: 1.00`.
`tools/query_wpd.py` opens only USB 04b0:032a with `GENERIC_READ`, queries
identity/capabilities and sends only Microsoft's documented introspection
commands 11 and 18. Both returned success. Their results list vendor operation
codes **0x9002, 0x9003, 0x9005, 0x9006** and extension description
`microsoft.com: 1.0;`.

No listed vendor operation was executed, and no raw PTP GetDeviceInfo command,
capture, RAM read, setting change or driver replacement was attempted. The
results are in the local `evidence/wpd-device-info.json`; a COM typing failure
from the first attempt is retained separately. Opcode values are vendor-scoped,
so assigning another camera's names to them would be unsupported. A bounded
aligned-immediate scan in the two readable MIPS32 images found no matching
instruction candidates; encoded application data and MIPS16 remain unsearched.
See `evidence/vendor-opcode-static-candidates.json`.

The local COM dependency and generated typelibs are confined to `tools/vendor`.
The query has a 40-second worker timeout. Documentation:
[Microsoft's opcode introspection command](https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-get-supported-vendor-opcodes)
and [extension-description command](https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-get-vendor-extension-description).

Decode one block against independently checked output constraints, then all
four segments. Only then search the recovered application bytes for resource
IDs and the gamma/colour-table consumer. Alternatively, a genuine runtime dump
of the loaded segments could serve as a decoder oracle, if a suitable read-only
device access method is established.

Update integrity, safe repacking and recovery remain separate unfinished gates.
No custom image is ready to flash. Host-side visual results, compressed-block
framing and static loader observations are recorded separately so they cannot
be mistaken for successful firmware execution.
