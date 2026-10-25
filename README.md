# Nikon COOLPIX S3300 firmware research

First offline investigation: 23 October 2026. The camera originally reported
**v1.0** and now reports **v1.1** after the recorded experimental updates.
The supplied Nikon updater contains **v1.1**; it is not a complete device-flash
or calibration backup, and the version string cannot identify modified bytes.

[Private GitHub repository](https://github.com/Radical11/s3300-firmware-lab) ·
[Progress log](PROGRESS.md) · [Offline test workflow](.github/workflows/tests.yml)

Joining the project? Start with the [team setup and contribution guide](CONTRIBUTING.md).

## Development platform and current readiness

Latest: [backup and recovery follow-up](notes/backup-recovery-progress-2026-10-25.md).
The normal PTP file snapshot preserves49 files/170,787,084bytes. Installed
flash/calibration backup and reset-independent software recovery remain blocked.
Use `backup-status --verify-files` for current local file integrity and component
coverage; this performs no camera access.

The [developer handbook](docs/development/README.md) covers setup, architecture,
feature lookup, resource edits, target modules, candidate checking, camera tests
and recovery. `python s3300.py guide derived/my-guide` builds its searchable
offline edition. `python s3300.py readiness` reports the current gates.

`python s3300.py browse` opens the existing analysis to a read-only localhost
workbench: function/pseudocode search, static callers/callees, research
interfaces and evidence, with separate readiness gates. It verifies the retained
native index and does not unpack, execute firmware or access the camera.

Portable Ghidra 12.1.4/JDK 21 analysis now retains projects and exports native
dossiers. The decoded application has 15,816 discovered function dossiers,
including three initial decompiler failures, one recovered by a focused retry;
the other two remain explicit. An index independently checked
1,369,833 instruction byte sequences against the original analysis image.
These inferred functions and pseudocode do not establish complete semantics.
Use `pseudocode --address 0x80008f80` and `interface --search matrix` through
`s3300.py` to inspect the reusable results.

The [SDK](firmware/sdk/README.md) compiles real integer-only MIPS32r2/o32 code.
Two builds match and 58 synthetic MIPS execution cases pass. Camera placement,
hooks, full buffer ownership and unbootable software recovery remain unverified.
**Executable trials are blocked; the platform is not code-ready.**

25 October follow-up: [label selection](notes/label-contracts.md) is now traced
through the native English loader and ID lookup, including host checks of the
reviewed candidate. The camera now confirms Amber in Auto Color options;
the earlier Nostalgic sepia report came from Special effects. The
[capture-buffer map](notes/capture-buffers.md) identifies descriptor geometry
and a temporary allocation/wait/free lifecycle;
[executable contracts](notes/executable-contracts.md) identify startup, stack
and allocator ownership exclusions; and the
[transport map](notes/recovery-transport.md) connects ConfigMem state to GetMem
and traces application USB dispatch. None establishes a safe executable trial.
New reports and the current readiness ledger preserve the remaining
packing/coherence and recovery gaps. Read-only camera checks subsequently
verified the active PTP USB configuration; no update or debug command ran.

The Amber parameter change is now visible in a saved photo (unclipped Cb/Cr
approximately 110/150). Auto mode's Color options shows **Amber**. The first
new intended-Standard pair remained tinted; an explicit Standard → OK repeat
now retains normal colour in its saved JPEG. Restart, remembered Amber and
playback pass by user report. **The resource-ready milestone now passes.**
See [current runtime evidence](evidence/amber-auto-verification-2026-10-25.json)
and the [camera verification note](notes/camera-verification-2026-10-25.md).
No speed or battery improvement has been measured.

The next [saved-JPEG](notes/saved-jpeg-path.md),
[cache/DMA](notes/cache-dma-contracts.md),
[reset recovery](notes/reset-recovery.md) and
[PTP vendor](notes/ptp-vendor-contracts.md) maps recover more concrete contracts.
They identify asynchronous buffer consumption and the absent reset/ROM inputs
needed to assess recovery. `research-map` rechecks these focused findings using
the retained native analysis; `readiness --json` now includes a feature
[dependency ledger](firmware/sdk/dependencies.json). These advances preserve
the executable recovery block.

The earlier sections below retain the investigation chronology. Current native
analysis, runtime results and matrix-application findings supersede older
unknown/pending statements within their stated scope.

Start development through the [reusable workspace guide](notes/developer-workspace.md).
`python s3300.py init` extracts once or verifies and reuses the existing baseline;
`python s3300.py doctor` checks it without re-extracting. The same CLI provides
search, address lookup, bounded listings and offline patch-plan builds.
`python s3300.py limits` opens the evidence-linked
[hardware/limits catalog](notes/hardware-and-limits.md), including unresolved
CPU, RAM, sensor, buffer and recovery contracts. Original project code and
documentation are [MIT licensed](LICENSE); see [third-party boundaries](THIRD_PARTY.md).

The [firmware atlas and mapping ledger](notes/firmware-atlas.md) adds complete
listings for all 5,798 known function ranges, static call/reference candidates,
17 subsystem inventories and deeper hardware/capture/settings contracts.
Use `python s3300.py atlas --subsystem capture` or
`python s3300.py atlas --address 0x80737664`. Semantic coverage and native REA
provider limitations remain explicit; this is not a fully recovered source tree.

The first [resource-only research candidate](notes/resource-label-candidate.md)
has been built and independently checked offline. It changes one English menu
label and the additive checksum, preserving executable bytes. At the user's
explicit request, the experimental file was staged on the card through USB and
verified by full byte-for-byte readback. The first trial reached v1.1 without
the modified label. A new [embedded-resource pass](notes/embedded-resources.md)
found another English table inside the packed application and implemented a
dual-decoder-checked rewrite of that copy. The second candidate is now backed up
and verified on the card through a reader for the user's requested
[same-version trial](notes/reflash-card-trial.md). The user subsequently reported
**`Welcome studio` in the camera menu**, followed by the SD card being readable
again. This confirms user-observed custom label activation. A reported card
error after updating started remains unexplained; restart, capture, playback
and persistence checks are still pending.
The user subsequently reports normal operation. The next
[Pocket Studio identity trial](notes/pocket-studio-trial.md) is built,
independently checked and staged through the card reader after verified photo
and prior-update backups. It retains the marker and replaces only the startup
picture relative to that prior build. The user now confirms update completion
and changed artwork. [Original artwork](firmware/branding/README.md) is versioned;
vendor firmware and personal photos remain local.
The next [Amber mono experiment](notes/amber-mono-trial.md) has now been built,
independently decoded and staged. It changes the existing Sepia tint and English
label while retaining Pocket Studio. Its saved-photo result is pending; it is
not the full-colour four-look module.
This is not a
validated release: [backup/restoration access](notes/restore-path.md) remains
unresolved. See [the USB trial](notes/usb-flash-trial.md). The manual capture
benchmark is deferred at the user's request.

The camera itself is the product: faster shooting and expressive retro looks.
The firmware-development work now includes a **working application decoder**:
all 463 packed blocks decode into 7,950,592 bytes, independently checked through
a separate prefix-code implementation and native zlib. Both implementations
agree byte-for-byte, including token counts, end markers and padding boundaries.
An analysis-only ELF retains the application virtual addresses for static work.

**No speed improvement or creative shooting mode has been demonstrated.** The
minimal menu-label experiment is the first installation trial. Recovery and
post-update behaviour remain unfinished work; the synthesized analysis ELF is
not a camera update.

Start with [implementation status](notes/implementation-status.md),
[the complete unpacked workspace](notes/unpacked-workspace.md),
[the compact creative-look C module](firmware/looks/README.md),
[the reusable patch-plan builder](notes/patch-plans.md),
[the existing selectable effects map](notes/color-options-map.md),
[the decoder format](notes/decoder-format.md),
[application landmarks](notes/application-landmarks.md), and
[update integrity](notes/integrity-analysis.md), followed by the
[application checksum and acceptance map](notes/update-acceptance.md).
Earlier [findings](notes/findings.md),
[sample comparisons](notes/processing-pass-2.md) and the
[host-only prototype](prototype/README.md) preserve the initial research history.
Their earlier unknown-decoder statements are superseded by this pass.

## Project contents

| Path | Contents |
| --- | --- |
| `sources/` | Original updater copy and 7-Zip-extracted firmware; kept local |
| `derived/v1.1-mapped/` | Six ELF images, symbol/segment map, strings and 15 function listings |
| `derived/resources-v1.1/` | 368 verified resource files from FAT16 |
| `derived/v1.1-decoded/` | Four recovered application regions with per-block evidence |
| `derived/v1.1-independent/` | Independent prefix-code/zlib outputs |
| `derived/v1.1-analysis/` | Verified synthetic ELF and decoder-comparison manifest; analysis only |
| `derived/unpacked-v1.1/` | Lossless carrier parts, fresh decoded files, all resources, editable format exports and SQLite search |
| `evidence/` | Complete REA responses, diagnostics, resource provenance and function analysis |
| `prototype/` | Host-only 256-byte tone-curve candidate, C table, CSV and checked metrics |
| `tools/` | Reproducible mapping, resource extraction, disassembly and prototype scripts |
| `tests/` | Synthetic decoder, independent checker, and timing-analysis checks |
| `benchmarks/` | Empty timing CSV; no hardware measurements have been invented |

The vendor updater was opened as an archive with existing 7-Zip, not executed.
Original and derived vendor bytes are ignored by Git to keep them local.

## Reproduce

Run from this project directory in PowerShell. Mapping and resource extraction
require **new** output paths; prior results are deliberately not overwritten.

```powershell
python tools/map_firmware.py sources/extracted-v1.1/S3300Update/firmware/firmware.bin derived/new-map
python tools/extract_resources.py sources/extracted-v1.1/S3300Update/firmware/firmware.bin --offset 0x6fe2c0 --output derived/new-resources --evidence evidence/new-resource-filesystem.json
python tools/disassemble_boot.py
python tools/prototype_tone_curve.py
```

The new application workflow, after mapping and packed framing are present:

```powershell
python tools/decode_firmware.py --output derived/repeat-decoded --evidence evidence/repeat-decoded.json
python tools/validate_decoded_firmware.py derived/repeat-independent
python tools/build_analysis_image.py derived/repeat-analysis --production derived/repeat-decoded/manifest.json --independent derived/repeat-independent/validation.json
python -m unittest discover -s tests -v
python tools/inspect_update_container.py --self-test
python tools/map_update_acceptance.py --self-test
python tools/analyze_benchmarks.py benchmarks/measurements.csv
```

Use absent paths for repeat runs. The fixed source identity deliberately binds
these tools to the supplied v1.1 image. Do not substitute a v1.0 dump or another
camera model. No command above installs firmware or contacts the camera.

The complete workspace export runs the supported unpackers and independent
validation together, including reversible ZST strings and ZBM index codecs:

```powershell
python tools/unpack_workspace.py derived/another-unpacked-v1.1
python tools/unpack_workspace.py derived/another-unpacked-v1.1 --verify
python tools/query_workspace.py derived/another-unpacked-v1.1/research.sqlite --search 'Welcome screen'
python tools/query_workspace.py derived/another-unpacked-v1.1/research.sqlite --address 0x80741800
python tools/workspace_functions.py derived/another-unpacked-v1.1 --listing 0x80741800 --output derived/welcome-function.asm
```

[Branding/startup consumers](notes/branding-customization.md) and
[profiling/developer interfaces](notes/development-interfaces.md) document the
new customization and efficiency leads. Recovered code/resources are vendor
artifacts; their local extraction does not turn them into open-source software.
The [unwind metadata map](notes/unwind-functions.md) provides 5,798 function
ranges for address lookup and bounded disassembly; original names and complete
function semantics are not recovered.

Python uses the existing pyelftools package; Capstone 5.0.6 was installed only
under `tools/vendor/`. `tools/rea.ps1` runs cached REA 6.4.0 with the app's
existing compatible Node 24.22.1. It changes no global registration or runtime.

REA's skill is being followed from its cached package. Its native-decompiler
engines are unconfigured and its Binwalk firmware workflow requires Linux plus
a caller-supplied Binwalk executable. REA artifact/resource Evidence and the
independent Python/Capstone findings are identified separately in the report.
REA inventory authenticated the synthetic ELF as artifact Evidence
`ev_44622d20bd344afd4b9b97b8aceda0fbac6348f3efc345311e360f331211f1cc`.
Its binary-layout provider also requires Linux x64; that failure is retained
once in `evidence/rea-decoded-analysis-layout.json`. ELF layout was independently
round-tripped through pyelftools. REA inventory does not validate our inferred
decompression semantics or establish runtime behaviour.

The hardened build in `derived/v1.1-analysis-verified/` additionally reparses
original vendor ELF headers directly from the source to authenticate address,
length and permission metadata. It produces the same analysis ELF bytes.
# Current development status

Start with [the current platform status](notes/platform-status-2026-10-25.md)
and [development guide](docs/development/README.md). Run `python s3300.py browse`
to explore retained functions, hardware limits and interface contracts locally.
Resource-ready passes for reviewed Amber changes; executable integration and
reset-independent recovery remain blocked.
