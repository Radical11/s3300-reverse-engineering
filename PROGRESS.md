# S3300 firmware lab progress

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

## Experimental installation request

The user has now explicitly requested a flash attempt and GitHub progress
pushes. This authorizes preparing the experimental trial; it does not change
the existing evidence about the candidate. Device acceptance, full backup and
restoration remain unverified. The experimental file is now on the card and
verified by full USB readback. The user reports the v1.1 update is in progress;
completion and the modified menu label have not yet been confirmed.

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
successful firmware installation.

Nikon's [official S3300 update guide](https://nikonimglib.com/europe/Firmware/S3300/v1.1/En/ecpx_win_en.html)
documents staging a `firmware/firmware.bin` folder at the memory-card root with
a card reader, followed by the camera's Setup → Firmware version update flow.
That guide covers Nikon's stock updater; it does not validate our altered file.
No formatting, photo deletion, driver changes or unknown vendor commands were
performed. The only card writes were the new update folder and file. Raw vendor
firmware stays local and is not pushed to GitHub. Physical camera controls are
operated by the user; no remote flash command was sent.

## Next evidence to record

Record the completion message, post-update version and English `Welcome studio`
label, then ordinary startup, menu use, playback and capture. The user has
reported that updating to v1.1 has started. Do not infer completion or custom
resource activation from the version number, file copy or checksum alone.

See [candidate details](notes/resource-label-candidate.md),
[restoration findings](notes/restore-path.md) and
[the implementation ledger](notes/implementation-status.md).
