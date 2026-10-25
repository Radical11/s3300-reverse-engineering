# S3300 firmware lab progress

## Backup and recovery checkpoint - 25 October 2026

Preserved 49 normal-PTP files totaling170,787,084 bytes with two camera reads
and local hash verification. Added bounded metadata/file snapshot, local
verification, backup coverage and acquired-store inspection commands. All
installed flash/calibration/reset-recovery gates remain false. Four new maps
cover backup scope, USB setup/metadata, normal update handoff and the actual
application writer. A separate focused Ghidra project preserves the main
project and retains the caller-seeded boundary/type warning. The combined
index now has19,527 functions and53 research interfaces remain non-callable.
See `notes/backup-recovery-progress-2026-10-25.md` for evidence and blockers.

## Current checkpoint

24 October 2026. Research tools and metadata are versioned here. The vendor
firmware, extracted assets, personal camera photographs and device-specific
identity reports remain local under the existing Git exclusions.

Private repository: [Radical11/s3300-firmware-lab](https://github.com/Radical11/s3300-firmware-lab).
The first push was verified against the remote branch. GitHub Actions ran all
94 tests successfully on both Windows and Ubuntu:
[verified test run](https://github.com/Radical11/s3300-firmware-lab/actions/runs/40059969811).

- Supplied v1.1 update unpacked losslessly; 463 packed application blocks
  decoded and independently cross-checked through native zlib.
- 368 allocated resource files extracted and source-checked.
- Reversible JSON codecs for 33 string tables and 73 indexed bitmaps.
- Searchable local workspace and 5,798 compiler-provided function ranges.
- Minimal full-size research candidate changes one English menu label and the
  additive checksum. Six bytes differ; executable images are unchanged.
- Independent exact-byte candidate validation and 94 unit tests passed locally.

Later passes add packed-block rewriting and native algorithm checks; the current
suite passes **122 tests** locally. The [creative-look C module](firmware/looks/README.md)
implements Original plus four looks using 2,560 table bytes and no heap/frame
allocation. It compiled with MSVC and matched independent references, including
full-resolution host runs on an original photo copy. It is not camera-integrated;
no Nikon performance or battery improvement is claimed.

## Experimental installation request

The user has now explicitly requested a flash attempt and GitHub progress
pushes. This authorizes preparing the experimental trial; it does not change
the existing evidence about the candidate. Device acceptance, full backup and
restoration remain unverified. The experimental file was staged on the card and
verified by full USB readback. The user now reports firmware **1.1**, but the
`Welcome studio` label is absent. Custom resource activation is not confirmed.

The initial Explorer check missed the storage. Direct Windows WPD enumeration
found the roughly 2 GB card, reporting read/write access. Standard WPD object
creation made the root `FIRMWARE` folder and committed `FIRMWARE.BIN`, without
overwriting files or altering photographs. Windows then refused metadata and
resource-stream reads for the binary with HRESULT `0x80070032`.

A read-only fallback through the existing WPD driver succeeded using standard
PTP GetStorageIDs, GetObjectHandles, GetObjectInfo and GetObject. It verified the
root folder, filename, parent and size, then downloaded all **19,005,632 bytes**.
Both exact-byte comparison and SHA-256 matched the independently checked local
candidate. See [USB transfer findings](notes/usb-flash-trial.md) and
[complete readback evidence](evidence/wpd-ptp-readback-2026-10-24.json).

A local package is prepared at `derived/experimental-flash-trial-01/` with
`firmware/firmware.bin` and a trial manifest. The independent validator passed
again, and file readback matched SHA-256
`c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312`.
The separate USB readback now establishes card staging; it does not establish
successful custom resource activation. The user subsequently reported v1.1.

Nikon's [official S3300 update guide](https://nikonimglib.com/europe/Firmware/S3300/v1.1/En/ecpx_win_en.html)
documents staging a `firmware/firmware.bin` folder at the memory-card root with
a card reader, followed by the camera's Setup → Firmware version update flow.
That guide covers Nikon's stock updater; it does not validate our altered file.
No formatting, photo deletion, driver changes or unknown vendor commands were
performed. The only card writes were the new update folder and file. Raw vendor
firmware stays local and is not pushed to GitHub. Physical camera controls are
operated by the user; no remote flash command was sent.

## Next evidence to record

The missing label prompted a new [embedded-resource pass](notes/embedded-resources.md).
The application contains a complete copy of the English table, and its static
dispatcher returns that pointer. The embedded gamma table also differs from its
filesystem counterpart. This suggests the first trial changed a fallback copy.

Packed-block rewriting is now implemented and dual-decoder checked. A second
candidate edits both English copies while preserving all framing extents; its
full affected 151-block segment differs in only five decoded data bytes.

The user's latest [reflash request](notes/reflash-card-trial.md) reached verified
**card-reader staging on E:** after USB replacement failed. The old update was
backed up and the corrected image read back exactly from FIRMWARE/FIRMWARE.BIN.
Its SHA-256 is `a222ab366e8f328dc3a3be17b780fa42cba988d3b220487b4fb14a8016a270b4`.
Version remains 1.1. After starting the camera update, the user reported a card
error, then confirmed **`Welcome studio` inside the menu** and that the **SD card
is being read again**. The custom label is therefore active according to the
user's direct observation. The update-completion screen was not reported, and
the cause of the temporary card error is unresolved. Cold restart, photo
capture/playback and settings persistence remain pending. See the
[runtime observation record](evidence/embedded-label-runtime-observation-2026-10-24.json).

See [candidate details](notes/resource-label-candidate.md),
[restoration findings](notes/restore-path.md) and
[the implementation ledger](notes/implementation-status.md).

## Pocket Studio and the next processing hooks

The user reports the camera is working. Live read-only USB enumeration confirms
v1.1 and readable card storage. A reusable fixed-extent patch-plan builder now
reproduces the working marker image exactly and independently validates complete
affected segments, including history-sensitive continuation blocks.

The next [identity trial](notes/pocket-studio-trial.md) retains that marker and
adds original Pocket Studio startup artwork. Two builds match exactly;
independent reconstruction and a fresh 368-file FAT extraction pass. **139 tests
pass locally.** The trial is staged and fully read back from the removable card;
all 30 DCIM files and the old update were backed up and verified first. Artwork
activation is now **confirmed by the user**, who reports the update completed
and the artwork changed. Repeated restart/capture/playback checks remain pending.
The 139-test suite also [passed on Windows and Ubuntu](https://github.com/Radical11/s3300-firmware-lab/actions/runs/40074786898).

## Reusable development workspace

24 October 2026: added `s3300.py` for extract-once initialization, stored-artifact
verification, literal search, address lookup, bounded listings, capability
queries and offline patch builds. Fresh unpacking generates its own map and
uses current local source paths instead of historical absolute paths. A
separate temporary checkout with no prior generated directories completed
extraction and reproduced the known label candidate exactly. Reinitialization
reused the workspace; a modified copied baseline was rejected without overwrite.
All **147 offline tests pass locally**; this new total has not been run in
remote CI by this pass. No camera commands were sent.

The [hardware catalog](notes/hardware-and-limits.md) records known specifications,
stock policies, recovered contracts and explicit unknowns, with per-entry
evidence links. Original project-authored code/docs are now MIT licensed;
vendor bytes remain separate. See the [developer guide](notes/developer-workspace.md)
and [validation record](evidence/developer-workspace-validation.json).

## Broad firmware mapping with the REA workflow

24 October 2026: created a repeatable [firmware atlas](notes/firmware-atlas.md):
all 5,798 known unwind function ranges fully decode, with 48,303 direct-call
instruction candidates, 300 unresolved register calls and 17 subsystem
inventories. Original symbols retain their separate executable scope.
Two atlas builds produced identical databases and manifests.

Deeper [hardware](notes/hardware-contracts.md), [capture](notes/capture-contracts.md)
and [state](notes/state-contracts.md) reports recover DRAM selector/clock/GPIO
contracts, corrected RAW-to-YUV entry and command-retention rules, settings
staging/media transactions and GetMem dispatch structure. All three mappers
agree on repeat runs; **186 offline tests pass locally**. Exact RAM/clocks,
complete frame ABI, active saved-still integration and recovery remain open.

REA supplied artifact identity Evidence. Its native function request explicitly
rejected this MIPS ELF on the installed Windows provider, and the existing
Docker Linux engine did not start within the chosen startup window. Static
Python/Capstone findings are labeled separately from native REA Evidence.
No new device command, firmware trial or global registration change occurred.

## Development platform implementation and camera verification

24 October 2026: portable, official-hash-verified Ghidra 12.1.4/JDK 21 now runs
direct native analysis without changing global Java, REA registration or VMs.
Retained projects cover the decoded application and separate executable images;
packed carrier images remain inventory-only. The application export contains
15,816 discovered function dossiers. Three initially failed decompilation;
one timeout was recovered with a longer focused retry and two engine errors
remain explicit. The native index checks 1,369,833 instruction byte sequences
against the authenticated analysis ELF and includes calls, references and
indirect-transfer records. None of this establishes complete semantics.

The SDK builds real integer-only MIPS32r2/o32 code with a pinned portable
compiler, no unresolved imports and no camera hook. Two builds match exactly;
58 synthetic MIPS execution cases pass. The matrix follow-up now traces
command 15 through retained state, group/slot/factory dispatch and register
uploads, with native/independent instruction corroboration. Complete frame
ownership, placement/hooks and unbootable software recovery remain unresolved.

The CLI now includes native setup/analysis/resume/retry, native indexing and
pseudocode lookup, interface lookup, SDK build, closed candidate validation,
local trial packaging, camera-result recording, readiness, offline guide and
source-only packaging. The 12-chapter handbook has browser-verified navigation,
search, offline diagrams and desktop/mobile layout. A fresh source archive plus
the original firmware passed 11 end-to-end checks, reproduced Amber and SDK
hashes, and passed all 226 tests using existing interpreter/dependency caches.
Two source-only ZIPs are byte-identical. New remote Linux CI was not run.

Live read-only inventory confirms the connected S3300 reports v1.1. The user
reports Amber installation but the English menu remains Sepia after restart.
Two new JPEGs were copied using twice-verified standard PTP reads. The selected
tint image has unclipped Cb/Cr approximately 110/150, consistent with the Amber
offsets; Standard colour remains varied. Restart, remembered mode and playback
pass by user report. The rename remains failed, exact installed bytes are
unknown, no new update ran, and no speed/battery improvement is claimed.

Current acceptance is in `evidence/development-readiness.json`; both complete
resource-ready and code-ready milestones remain false. See
[the handbook](docs/development/README.md),
[implementation validation](evidence/platform-implementation-validation.json)
and [camera verification](evidence/amber-runtime-verification-2026-10-24.json).

## Remaining-contract follow-up — 25 October 2026

Four reproducible source-bound investigations deepen the remaining gates:

- English Color Options IDs 560..564 and the embedded ZST loader now agree
  with an independent record parser. Bounded host execution checks all 3,313
  pointers per run. The reviewed local Amber candidate's FAT/embedded tables
  match and select Amber in native-helper emulation. The camera label failure
  remains unresolved; exact installed bytes and live rendering are unverified.
- The shared seven-u32 image descriptor has geometry roles; JPEG-specific
  guards, shallow retention and a temporary scale allocation/wait/free lifecycle
  are traced. Packing, pitch, domains and active saved-JPEG ownership remain
  incomplete. No direct reference to the original RAW-to-YUV wrapper was found
  in a bounded scan, so it is not promoted to an active hook.
- Startup-cleared ranges, RTOS timer stacks, allocator pool formulas and cache
  operation paths constrain code placement. Zero runs remain unapproved space;
  no placement or complete cache-publication sequence has passed.
- USB setup/queue dispatch and ConfigMem-to-GetMem state are linked. The
  separate updater's own startup is traced. Installed USB acceptance, safe
  readback bounds, actual erase/write geometry and application-independent
  reset recovery remain blocked.

The interface catalog includes these research contracts with camera_callable
false. All 258 offline tests pass. See the four new research notes and
`evidence/contract-followup-validation-2026-10-25.json`. Current Windows PnP
inventory finds no attached S3300; a read-only reconnect request is pending.
No camera commands, new candidate, flashing, driver changes or public release
occurred. Resource-ready and code-ready remain false.

New [gamma-format](notes/gamma-pipeline.md) and
[Color Options](notes/color-options-map.md) findings narrow the next saved-photo
integration work. They are source-bound static findings, not demonstrated
photographic or speed changes. No such processing patch was included here.


## Resource-ready camera acceptance — 25 October 2026

The camera reconnected successfully through its existing WPD driver. Read-only
identity, PTP object inventory and standard hub descriptor reads passed. The
live USB 2.0 configuration has one Still Image interface and endpoints 01/81/82.
The new source-authenticated USB-mode map correlates it with PTP modes 4/7;
mode 6 registers different debug/storage handles and interfaces. Independent
debug activation, bounded flash readback and reset recovery remain unverified.

The apparent Amber rename failure was a menu-route mismatch. The six reported
choices identify Special effects, whose Nostalgic sepia is a separate string.
After selecting Auto mode -> MENU -> Color options, the user confirmed Amber.
Welcome studio is also present. The earlier failed label record is superseded
without deletion; no new update was needed.

Fresh DSCN1186/1187 both have constant Amber chroma around Cb110/Cr150; the
first intended-Standard observation therefore failed. An explicit Standard
color -> OK repeat produced DSCN1188, normal preview by user report and varied
saved-photo chroma (Cb mean134.13 SD14.79 / Cr mean126.91 SD9.47). That later
pass supersedes the earlier bypass failure without inventing its cause. All
three JPEGs were read twice, compared and verified after local copying.
Restart, remembered Amber and playback pass by user report.

Resource-ready now passes all six reviewed checks. Code-ready, normal rollback,
complete backup and unbootable recovery remain unverified. No firmware update,
driver change, debug request, memory read or performance claim occurred. See
`evidence/amber-auto-verification-2026-10-25.json`,
`evidence/camera-usb-verification-2026-10-25.json`,
`notes/camera-verification-2026-10-25.md` and the current readiness ledger.

## Code-ready contract pass — 25 October 2026

Added reproducible saved-JPEG, cache/DMA, reset/recovery, PTP-vendor and USB-entry
maps, with focused tests and original notes. The saved-photo path now follows
FileCompressor event1042 through JPEG start/wait/destruction and EXIF assembly
to asynchronous storage. Writer flag4 frees encoded segment data and list nodes;
the active shutter producer, exact pixel packing and live ownership remain open.

The tiny MIPS16 loader depends on absent ROM bytes/reset routing. All direct
USB mode-wrapper calls were cross-checked against an independent JAL scan;
modes0/5/7 appear, while mode0's test-state lead depends on calibration data and
internal events. PTP vendor9002 changes state and9005/9006 share object-upload
handlers. No safe memory-backup or reset-independent recovery route passed.

The PTP initializer's full host-emulation attempt failed at an authenticated
backward branch. That failure is retained explicitly. A narrower original-code
insertion/lookup/packet-handler run passes using synthetic state and a stubbed
state-changing endpoint. It does not verify live registration or peripherals.

`s3300.py research-map` reuses retained native analysis, binds source/tool/script
identities and can reject stale reports with `--verify-existing`. The structured
interface catalog and offline guide now include these findings. An explicit
feature dependency ledger keeps unresolved contracts visible in readiness.
Resource-ready remains true; code-ready and executable trials remain blocked.
No camera operation, new candidate, flash, calibration write or mode switch
occurred during this pass. No camera performance improvement is claimed.

## Capture, menu and updater closure pass — 25 October 2026

Added scanner/debounce/input routing, UI-to-still/JPEG queue routing, distinct
JPEG input/layout selectors and DMA pitch, existing menu lifecycle, and updater
write-scope maps. The runtime UI/capture-state object at808918a0 is explicitly
separate from the persistent38-byte view bank at808918ac. Source checks and
focused tests preserve live-state, component-order and ownership gaps.

The existing Color Options menu has a static five-entry object. Dynamic lists
use one shared allocation slot; parent return can stage/persist settings even
without committing the newly previewed color. Updater user-area backup/restore
and some bad-block checks can write flash. These findings prevent unsafe
assumptions; they do not promote a camera adapter or recovery gate.

Added a localhost browser workbench with hardware limits, interface research,
function/pseudocode search, resolved calls, unresolved transfers and evidence.
It verifies retained database identity, preserves separate readiness gates and
exposes no firmware/camera operation. Vendor-derived listings remain local.
The interface catalog now contains42 entries with explicit executable
namespaces. Ordinary source and SDK development can continue; code-ready
remains false pending installed backup/recovery and live hook contracts.
## 25 October 2026 - combined research workbench acceptance

Added the combined artifact index and browser namespace selection: 19,526
functions across application/updater/tiny-loader/primary, with three packed
carriers explicitly inventory-only. All 42 recovered interface records carry
image scope and remain non-callable. Ten focused contract maps were recomputed
against authenticated inputs. The current 395-test workspace suite and
desktop/mobile guide/workbench checks pass, including a null-address matching
regression found during browser verification. See
`notes/platform-status-2026-10-25.md` for the new shutter, JPEG input, menu and
updater findings and the remaining live integration/recovery gates.
