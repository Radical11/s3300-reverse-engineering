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
restoration remain unverified. No candidate has been uploaded or flashed.

The camera was initially absent and subsequently appeared as an S3300 WPD
device over USB. The read-only Explorer namespace check exposed no child
storage folders, and the only mounted filesystem drives were the computer's
fixed C: and D: volumes. No writable card root has been established through
this connection. A card reader is the documented staging route. Normal camera
firmware confirmation also requires someone to operate its physical controls.

A local package is prepared at `derived/experimental-flash-trial-01/` with
`firmware/firmware.bin` and a trial manifest. The independent validator passed
again, and file readback matched SHA-256
`c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312`.
This is a prepared local package, not evidence of card staging or installation.

Nikon's [official S3300 update guide](https://nikonimglib.com/europe/Firmware/S3300/v1.1/En/ecpx_win_en.html)
documents staging a `firmware/firmware.bin` folder at the memory-card root with
a card reader, followed by the camera's Setup → Firmware version update flow.
That guide covers Nikon's stock updater; it does not validate our altered file.
No card formatting, card writes, driver changes or unknown vendor commands
have been performed. The raw package stays local and is not pushed to GitHub.

## Next evidence to record

Record the actual card/connection, staged-file hash and observed camera update
dialog before describing the candidate as accepted. If an experimental update
is completed, verify the reported version and intended label, then ordinary
startup, menu use, playback and capture. Do not infer successful installation
from a file copy or a checksum alone.

See [candidate details](notes/resource-label-candidate.md),
[restoration findings](notes/restore-path.md) and
[the implementation ledger](notes/implementation-status.md).
