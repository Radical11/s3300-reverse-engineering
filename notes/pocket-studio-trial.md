# Pocket Studio identity trial

24 October 2026. The user reports the prior custom-label camera is working.
A live read-only USB inventory confirms COOLPIX S3300 V1.1, card capacity
2,002,452,480 bytes and a readable DCIM root. No write or raw vendor command
was issued over USB in this pass.

This trial retains the working `Welcome studio` marker in both English copies
and replaces `JPG/Startup1.jpg` with original Pocket Studio art. Sound, shooting
algorithms, gamma tables, white balance and Color Options are unchanged.

Candidate: 19,005,632 bytes, SHA-256:

```
8f742b9a699b276a001827721fab4bd50e578372a582acc020ba1caa6e75754c
```

The reusable [patch-plan builder](patch-plans.md) reproduced the prior working
label candidate exactly before building this image. A second identity build
also produced identical bytes. Both decoders verified the affected 151-block
segment. The only difference from the prior marker candidate is the startup
JPEG payload and additive checksum; application/loader bytes are identical.
The independent exact-reconstruction validator checked that distinction and
all 367 other resources. A fresh FAT extraction validated all 368 allocated
files, with unchanged directory metadata and file allocations. The original
logical-volume-tail limitation remains; it has not been interpreted as a
complete volume or recovery image.

The JPEG retains the exact original 24,210-byte length, dimensions, baseline
frame, sampling and marker sequence. Two asset builds produced identical JPEG
bytes. Host JPEG acceptance still does not prove the camera decoder accepts it.
See `evidence/pocket-studio-identity-validation.json` and `startup-assets.md`.

## Card staging

The first reader check showed only internal drives. After the user reseated
the reader, Windows exposed the expected removable FAT card as E:. The existing
update had the prior embedded-label hash `a222ab36...a270b4`.

Before replacement, all **30 DCIM files (104,069,129 bytes)** were copied to
ignored local storage and checked against both the copies and a fresh source
read. The previous update file was separately backed up and fully verified.
The new candidate was written to an exclusive temporary card file, flushed,
read back, renamed over the known prior update, and fully read back again.
All 19,005,632 bytes matched. No formatting, filesystem repair or photo writes
were performed. This is a photo/update-file backup, not an internal NAND or
calibration backup.

`evidence/pocket-studio-card-staging-2026-10-24.json` records successful staging.
The user was given the normal camera-menu update flow and asked to select the
existing COOLPIX welcome option to test preview/startup. No remote flash
command was sent. Completion, artwork activation and post-update operation
remain pending until reported by the user.

## Reproduce locally

Use fresh directories. Original Nikon carrier and decoded workspace remain
required local inputs; they are not redistributed.

```powershell
python tools/build_startup_asset.py derived/new-pocket-art
python tools/build_identity_trial.py derived/new-pocket-art/Startup1.jpg derived/new-pocket-trial
python tools/validate_startup_trial.py --evidence evidence/new-pocket-validation.json
python -m unittest discover -s tests -q
```

The fixed validation CLI targets the reviewed candidate path in the trial
registry; a rebuild elsewhere must first compare exactly against that file.
The closed card staging registry includes this exact hash as `pocket-studio`;
arbitrary patch-plan outputs are not staged automatically.

## Next functional work

The [gamma pass](gamma-pipeline.md) found that the 960-byte table contains
packed base/slope sections rather than three RGB curves. Its normal saved-still
selection is still unresolved. The [Color Options pass](color-options-map.md)
recovered existing menu state and matrix/offset command construction for mono
tints, a more focused lead for a selectable photographic experiment. Neither
is included in this identity trial. No camera speed or battery gain is claimed.
