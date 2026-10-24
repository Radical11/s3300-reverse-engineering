# Firmware-first implementation status

Updated 24 October 2026. Research baseline: supplied Nikon S3300 v1.1 updater. Installed
camera: observed stock v1.0 before the user-requested experimental update.
After the first trial the user reported v1.1 without the label. After the second
trial the user reports `Welcome studio` in the menu and a readable SD card.
The user subsequently reports normal operation; live USB inventory confirms
v1.1 and readable card storage. The third, [Pocket Studio identity
trial](pocket-studio-trial.md) is now staged, retaining the marker and replacing
startup art. The user now confirms update completion and changed artwork;
repeated restart/capture/playback checks are not separately recorded.

## Current direction and latest checkpoint

The user now prioritizes unpacking first, a custom and playful camera identity,
less intrusive Nikon presentation, efficiency and accessible development. Keep
committing code, tools, findings and tests in reviewable steps. Raw firmware,
decoded vendor bytes and personal photographs remain preserved locally under
the project's existing Git exclusions.

The complete supplied carrier is now preserved in a **lossless unpacked
workspace**. A fresh run reconstructed all 19,005,632 source bytes and repeated
the independent 463-block decoder validation. All 368 resource files are
source-checked; **33 string tables (98,085 records)** and **73 indexed bitmaps**
have reversible JSON exports. An offline SQLite index provides literal searches
and address lookup. This is the extraction milestone for the supplied update;
unknown format semantics and absent logical-volume bytes remain explicit.
See `unpacked-workspace.md`.

Startup image/sound consumers, welcome-menu storage and presentation gates are
mapped in `branding-customization.md`. The stock art and chime occupy only
48,304 bytes. Give users control over presentation and make the camera feel
custom, while separately measuring any startup-to-ready improvement. The full
welcome-choice-to-power-on policy is not yet established.

Nine profiling command records and a six-u32 CPU-counter buffer contract are
recovered in `development-interfaces.md`. Gamma conversion still allocates work
on a raw-cache hit, making it a specific candidate to profile; generated-output
ownership prevents a naive shared-pointer cache. No runtime speed gain or
external debug access is established.

The current suite passes **139 tests**, including native compiled C,
malformed-resource,
roundtrip, metadata, scanner and query cases. The exact source reconstruction,
all resource roundtrips and an actual English-resource CLI export/import also
passed. This verifies offline development tools, not hardware behaviour.

An additional metadata pass recovered **5,798 function ranges** covering
2,267,704 bytes. Those ranges are now searchable in SQLite, and the developer
CLI can export a fully bounded MIPS32 listing for an address inside one. The
startup presentation example resolves to 0x807417d0..0x807419e0 and decoded
completely. These are compiler metadata boundaries, not recovered names or
proof that a patch point is usable. Full CFI interpretation remains incomplete.

The user has deferred the manual shooting comparison in favour of firmware
development. A minimal **offline resource-only candidate** now changes the
English label `Welcome screen` to `Welcome studio`, preserving its length.
Only six source bytes differ including the additive checksum; all six original
ELF files and 367 other resources are unchanged. Fresh FAT extraction and a
separately implemented exact-byte validator passed, and two builds produced the
same hash. See `resource-label-candidate.md`.

This candidate is now staged on the card, with all 19,005,632 bytes read back
over standard PTP and matched exactly. Standard WPD writes worked; its metadata
and resource-read path refused the binary. No card reader or driver replacement
was needed. The user now reports v1.1, but `Welcome studio` is absent. An exact
English-table copy and a differing gamma table were found in the packed
application. A token-preserving block rewriter now builds an offline candidate
for both English copies. The full affected 151-block segment passes production
and independent-zlib decoding with only five intended decoded data bytes
changed. The corrected candidate has now been backed up and verified on the
card through a reader. The user then reported a card error after updating
started, followed by the `Welcome studio` menu label and the card being readable
again. This is user-observed resource activation; update completion was not
independently observed, and restart/capture/playback checks remain pending. See
`usb-flash-trial.md`, `embedded-resources.md` and `reflash-card-trial.md`.

The NAND dump lead was traced
further: its fixed loop omits placeholders on read failures, so its output is
not a verified complete backup. Installed-v1.0/calibration coverage, complete
acceptance, actual write ranges and restoration remain unresolved. The earlier
decoder-only gap has advanced to controlled file construction, while camera
installation remains an unfinished engineering dependency. See `restore-path.md`.

## Completed development infrastructure

- Decoded all four application regions: 463 blocks, 7,950,592 bytes.
- Independently expanded the table graphs into prefix codes, transcoded tokens
  into RFC1951 fixed-Huffman streams and reconstructed output with native zlib.
  All four full outputs, every block hash, literal/match counts, end markers
  and zero-padding boundaries agree with the production decoder.
- Built a synthetic eight-region analysis ELF with original virtual addresses
  and permissions. pyelftools read back every segment and verified its bytes.
  Gaps are preserved; absent RAM is not fabricated. This is not an update file.
- Mapped update descriptor fields and conditional bootloader integrity paths;
  retained source-bound disassembly and exact source hashes.
- Verified the application's additive file checksum at +0x2c against the real
  source, and located its +0x28 version reader and conditional +0x30 marker
  check. Ordinary version policy and installed-v1.0 equivalence remain unknown.
- Located diagnostic references for capture, exposure, gamma/Lclut loading,
  CPU profiling, buttons and menus. Function contracts and runtime entrypoints
  are still investigation work.
- Added a real-observation timing CSV and analyzer that preserves failures and
  slow-end results. The CSV has zero observations, explicitly reported as such.

The software cross-check validates recovered bytes much more strongly than
plausible disassembly alone. An actual memory dump would remain an additional
independent oracle. See `decoder-format.md` and the evidence manifests.

## Concrete corrections from the recovered code

GammaDDE has explicit DLCD diagnostics and an identity-table construction path.
It is strongly associated with display gamma. Replacing it is not an established
way to change saved photos. The actual GammaLut loader already caches resources;
adding a duplicate cache is not a demonstrated optimization. The packed gamma
format requires its converter to be understood before replacement.

CPU-load and capture-timer code exists, but no callable USB/console route or
hardware timings have been demonstrated. Aligned instructions and nearby
prologues are candidate references, not verified patch points.

A separate USB GetMem implementation and a NAND-to-card monitor command are
backup leads. Active transport, request framing, safe ranges, complete backup
coverage and installed-v1.0 correspondence remain unverified. The advertised
vendor opcodes include state-changing and object-receive handlers; none was
executed. See `update-acceptance.md` for source-bound locations.

## Remaining execution gates

| Plan step | Current state | Required next evidence |
| --- | --- | --- |
| Decoder and restoration | Decoder implemented and independently cross-checked; restoration unfinished | Installed v1.0/calibration backup coverage, real write ranges, acceptance rules and accessible recovery route |
| Stock timing + optimization | Measurement tooling ready; no camera timings or optimization | Matched real stage measurements and the largest confirmed bottleneck |
| One selectable look | Image-stage/resource leads recovered; no camera hook | Confirm saved-photo processing domain, format and safe control integration |
| Four looks, quick switching, remembered settings | Four compact native C looks implemented and host-verified; no camera controls/integration | Verified capture-buffer domain, target ABI, button/menu ownership and persistence API/format |
| Fast Snap | Exposure-limit handler candidates found | Verified units/ranges and measured exposure experiments |
| Mystery roll and interval timer | Pending earlier dependencies | Session state, capture lifecycle, bounded scheduling and reliable cancel |
| Grain/vignette/glow/double exposure | Pending profiling/buffer knowledge | Memory ownership, accelerator capabilities and acceptable measured cost |

The intended first looks remain Original, Flash Pop, Amber Days, Cool Night and
Mono Grit. Texture stays intentional; mandatory smoothing and invented detail
are outside the brief. Host previews may tune these looks but cannot satisfy
the acceptance criterion that they operate while shooting on the camera.

`firmware/looks/` now contains real integer-only RGB8 processing code and
reproducible profile tables. Three colour looks use 2,304 table bytes; mono adds
256 bytes. The row API owns no buffers and allocates no heap memory. Original
returns without processing pixels. MSVC native tests and full-resolution JPEG
copy checks compare the LUT against an equivalent scalar implementation and a
Python reference. All outputs agree. Host kernel timings are recorded separately
from camera performance in `evidence/creative-look-host-benchmark.json`. This
module has not been cross-compiled for the camera, inserted into the carrier,
selected by a camera menu, or measured on Nikon hardware.

The minimal update package is now staged and read back through USB. The user
reports v1.1 after the physical menu update; no remote flash command,
version bypass, arbitrary vendor command or hardware modification was performed.
The official v1.1 package is not a backup of installed v1.0 or device calibration.
Software restoration remains unverified; this experimental trial does not close
that dependency or establish a recovery procedure.
