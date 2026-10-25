# Start here

The camera runs compiled MIPS software. We have the original supplied v1.1
update, tools that decode it, a searchable map and a growing collection of
recovered interfaces. We also have our own editable tools and creative-look C
source. We do not have Nikon's original source tree or a complete hardware
design.

## What a normal development session looks like

1. Check the baseline and current readiness.
2. Find the resource or interface responsible for one intended change.
3. Edit a copy or our source, never the preserved baseline.
4. Build into a new local output directory.
5. Run byte-level and semantic checks appropriate to that change.
6. Prepare an exact reviewed trial only when its dependent contracts pass.
7. Record what happened on the camera against the candidate hash.

```powershell
python s3300.py doctor
python s3300.py readiness --json
python s3300.py limits --search capture
python s3300.py atlas --subsystem capture --limit 10
python s3300.py test
```

Run these commands from the repository root. In a fresh virtual environment,
replace `python` with `.\.venv\Scripts\python.exe`.

## Two different readiness milestones

| Milestone | Required evidence |
| --- | --- |
| Resource-ready | Reproducible text/artwork/processing-data changes, independent candidate validation and the relevant camera observations |
| Code-ready | Target compilation, a verified executable hook and frame/state contracts, usable software recovery and a demonstrated selectable feature |

As of 25 October, resource-ready passes for the supported, reviewed changes.
Amber is visible in Auto Color options, reaches saved photographs, and retains
Standard colour as a verified bypass. Restart, playback and remembered selection
also pass. Code-ready remains blocked; this does not make arbitrary code or
resource edits ready to install.

The generated handbook includes the latest available readiness ledger. A
blocked code-ready milestone does not prevent host work or already-supported
resource experiments. It does prevent treating unverified executable changes
as camera-ready. Resource/data edits also need a scoped trial review; they do
not inherit safety merely because an earlier label worked.

## Choose the right kind of change

Text and artwork use resource codecs. A colour parameter such as Amber uses a
specific recovered data path. New algorithms use our C source and an eventual
camera adapter. A faster image algorithm is not useful if the camera spends
most of its time focusing or writing the card: measure first.

Keep an Original or Standard colour option available. Change one behavior at
a time so a saved photograph or timing difference can be attributed to it.

## Words used throughout this guide

| Term | Meaning here |
| --- | --- |
| Carrier | The complete supplied `firmware.bin`, including headers, packed payloads, resources, gaps and slack |
| Baseline | A preserved, hash-authenticated input used for one comparison |
| Candidate | A newly built research image; the name does not establish installability |
| Contract | The checked assumptions a caller and callee must share: arguments, format, ownership, synchronization and effects |
| Hook | A verified place and method for transferring execution into our code and returning correctly |
| Evidence | A retained observation tied to an artifact, method, tool and scope |
| Recovery | A usable route back when normal application startup is broken, not merely an update file on an SD card |

Our tools, tests, documentation and original source are MIT licensed. Vendor
firmware, extracted fonts/artwork/language data, personal photos and third-party
tools retain their separate ownership. See [license boundaries](../../THIRD_PARTY.md).
