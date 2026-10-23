# Nikon COOLPIX S3300 firmware research

First offline investigation: 23 October 2026. The camera reports **v1.0**.
The supplied Nikon updater contains **v1.1**; this research does not describe a
dump of the camera's installed v1.0 firmware.

The requested priority is custom image-processing features and efficiency.
We recovered executable images, symbols, resources and a concrete tone-curve
prototype. **There is no flashable custom firmware or demonstrated on-camera
performance improvement yet.** The camera has not been modified.

Read [the findings](notes/findings.md), then [the processing prototype](prototype/README.md).
The next pass includes [real-camera comparisons and encoded-segment mapping](notes/processing-pass-2.md).

## Project contents

| Path | Contents |
| --- | --- |
| `sources/` | Original updater copy and 7-Zip-extracted firmware; kept local |
| `derived/v1.1-mapped/` | Six ELF images, symbol/segment map, strings and 15 function listings |
| `derived/resources-v1.1/` | 368 verified resource files from FAT16 |
| `evidence/` | Complete REA responses, diagnostics, resource provenance and function analysis |
| `prototype/` | Host-only 256-byte tone-curve candidate, C table, CSV and checked metrics |
| `tools/` | Reproducible mapping, resource extraction, disassembly and prototype scripts |

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

Python uses the existing pyelftools package; Capstone 5.0.6 was installed only
under `tools/vendor/`. `tools/rea.ps1` runs cached REA 6.4.0 with the app's
existing compatible Node 24.22.1. It changes no global registration or runtime.

REA's skill is being followed from its cached package. Its native-decompiler
engines are unconfigured and its Binwalk firmware workflow requires Linux plus
a caller-supplied Binwalk executable. REA artifact/resource Evidence and the
independent Python/Capstone findings are identified separately in the report.
