# Amber: first saved-photo tint experiment

24 October 2026. The user reports the Pocket Studio build is working after the
requested restart/shoot/playback checks. Exact repetition counts and an
independently observed hardware test are not recorded.

## Stock samples and integration evidence

The first card scan found seven new full-colour photos, DSCN1170–1176. After
the user requested another check, six additional files DSCN1177–1182 were
present. Both batches were copied and rechecked against the source; the photos
remain private under ignored `samples/`. There were no photo writes or deletes.

Full-resolution analysis finds DSCN1179 has exactly equal decoded R/G/B
channels, with Cb/Cr means of 128/128 and zero chroma deviation. DSCN1177 has a
strong monochrome tint: excluding RGB values near clipping, decoded Cb/Cr means
are exactly **98/157**, consistent with the stock -30/+30 pair after JPEG
colour-conversion rounding. This supports the existing Sepia path reaching
saved photographs. Mode labels are not inferred solely from filenames or EXIF
saturation; other files remain unassigned. Different exposures/subjects prevent
using this set as a speed or image-quality benchmark.

`tools/analyze_color_samples.py` records full-resolution RGB equality and
YCbCr histograms, with explicit empty-mask handling and no source mutation.
`evidence/stock-color-sample-chroma.json` contains summaries/hashes only.

The [Color Options map](color-options-map.md) established a separate tint effect
branch from the AWB branch. Follow-up static windows show command wrapper
**0x802233e8 → 0x801fd324 → 0x8023c7b8**. For command ID 15, the dispatcher
reaches **0x8023db0c**, sets bit **0x00100000** at **0x808c1d78**, and returns
to the cache-handling path. Mode helper **0x8023c778** maps 0x40/0x50/0xa0/0xb0
to indices 0/1/2/5. These are analyst-window observations, not complete hardware
dispatch coverage. Actual effect activation still requires a saved-JPEG test.

## Deliberately narrow change

**Amber** replaces the existing English **Sepia** option and its constant tint.
It is a gentler warm **monochrome** treatment, not the full-colour Amber Days C
prototype or a four-look release. The existing grayscale effect, matrix path,
controls and white-balance selection remain in use.

| Data | Before | Candidate |
| --- | --- | --- |
| English label, FAT and embedded | Sepia | Amber |
| Signed offset pair at 0x80882d24 | -30, +30 | -18, +22 |
| Welcome marker | Welcome studio | Preserved |
| Startup art | Pocket Studio | Preserved |

Both new tint offsets lie between the stock neutral and Sepia values. This
does not establish every shared consumer or calibration assumption. No machine
instructions, buffers, allocation, exposure, lens sequence, watchdog, JPEG
quality, speed control or settings writer is changed. There is no additional
processing pass; no measured speed or battery gain is claimed.

## Build and validation

Candidate size: **19,005,632 bytes**. SHA-256:

```
d801708b06abbaece3974b2ae0cb9c55ce4154fffc0c132e00b35564ec86ce28
```

`tools/build_amber_trial.py` reproduces a closed five-edit plan from the original
v1.1 image and versioned Pocket Studio art. Two builds match exactly. The patch
builder verifies complete segments through both decoders. The independent
validator separately transcodes **182 blocks / 3,254,016 decoded bytes**, checks
only the exact declared string/tint changes, and reconstructs the complete
carrier relative to the working identity image. Both prefix tables and block
extents are retained. Packed block 146 has 600 padding bits remaining; tint
block 22 has 112. These are validated original allocations, not relocated data.

All 367 non-English resource files are unchanged from the working identity
image. A fresh FAT extraction validates all 368 allocated files; the original
logical-volume-tail limitation remains. Version/product/download descriptor
are unchanged. See `evidence/amber-mono-independent-validation.json`.

```powershell
python tools/build_amber_trial.py derived/new-amber-build
python tools/validate_amber_trial.py derived/new-amber-build/NOT-INSTALLABLE-patch-plan.research.bin --evidence evidence/new-amber-validation.json
python tools/analyze_color_samples.py samples/color-options-stock-02 --evidence evidence/new-stock-chroma.json
```

## Card staging and pending camera result

Before staging, all **43 DCIM files (149,602,989 bytes)** were backed up and
rechecked; the working identity update was backed up separately. The registered
`amber-mono` payload was staged on removable FAT E:, flushed and fully read
back, with exact candidate bytes/hash. No card formatting, repair or photo
writes occurred. This is a photo/update-file backup, not internal NAND recovery.

The user was asked to use the normal camera-menu update, confirm Amber replaces
Sepia, take Amber and Standard color shots, and reconnect the card. The current
evidence establishes **staging only**. Menu activation, preview, saved-photo
tint, restarts and remembered selection remain pending for this build. Do not
describe Amber as a demonstrated on-camera feature before those observations.

Compare the saved Amber chroma to the prior Sepia sample, allowing documented
conversion/clipping effects. Check Standard color still produces normal colour,
and check restart/playback and existing setting behavior. Keep adverse results
in the ledger; restoration remains unverified.
