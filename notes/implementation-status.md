# Firmware-first implementation status

Updated 24 October 2026. Research baseline: supplied Nikon S3300 v1.1 updater. Installed
camera: separately observed stock v1.0, left unchanged. Software-only work.

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

The current suite passes **94 unit tests**, including malformed-resource,
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

This candidate has not been uploaded or installed. The NAND dump lead was traced
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
| Four looks, quick switching, remembered settings | Desired look names retained; not on camera | Verified button/menu ownership and persistence API/format |
| Fast Snap | Exposure-limit handler candidates found | Verified units/ranges and measured exposure experiments |
| Mystery roll and interval timer | Pending earlier dependencies | Session state, capture lifecycle, bounded scheduling and reliable cancel |
| Grain/vignette/glow/double exposure | Pending profiling/buffer knowledge | Memory ownership, accelerator capabilities and acceptable measured cost |

The intended first looks remain Original, Flash Pop, Amber Days, Cool Night and
Mono Grit. Texture stays intentional; mandatory smoothing and invented detail
are outside the brief. Host previews may tune these looks but cannot satisfy
the acceptance criterion that they operate while shooting on the camera.

No update package, version bypass, arbitrary vendor command, target execution,
camera flash write or hardware intervention was performed. The official v1.1
package is not a backup of installed v1.0 or device calibration. Physical work
is not yet shown to be required; if software recovery proves inaccessible, that
dependency must be established and recorded before installation.
