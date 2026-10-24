# S3300 firmware lab progress

## Current checkpoint

24 October 2026. Research tools and metadata are versioned here. The vendor
firmware, extracted assets, personal camera photographs and device-specific
identity reports remain local under the existing Git exclusions.

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

The camera was not detected during the latest connection check. A physical
connection or SD-card reader is needed before staging. Normal camera firmware
confirmation also requires someone to operate its physical controls.

Nikon's [official S3300 update guide](https://nikonimglib.com/europe/Firmware/S3300/v1.1/En/ecpx_win_en.html)
documents staging a `firmware/firmware.bin` folder at the memory-card root with
a card reader, followed by the camera's Setup → Firmware version update flow.
That guide covers Nikon's stock updater; it does not validate our altered file.
No card formatting, update staging, driver changes or unknown vendor commands
have been performed.

## Next evidence to record

Record the actual card/connection, staged-file hash and observed camera update
dialog before describing the candidate as accepted. If an experimental update
is completed, verify the reported version and intended label, then ordinary
startup, menu use, playback and capture. Do not infer successful installation
from a file copy or a checksum alone.

See [candidate details](notes/resource-label-candidate.md),
[restoration findings](notes/restore-path.md) and
[the implementation ledger](notes/implementation-status.md).
