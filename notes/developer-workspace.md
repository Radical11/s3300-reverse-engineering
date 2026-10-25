# S3300 development workspace

The supplied v1.1 update is already unpacked in full. The development entry
point is now `python s3300.py`. It reuses that baseline across sessions rather
than carving resources or decompressing the application for each change.

The goal is an open development kit around recovered firmware. Our original
tools, tests, documentation and creative-look code have an MIT license. Nikon's
executables and resources remain local inputs under their existing ownership;
see [license boundaries](../THIRD_PARTY.md). A public source checkout can rebuild
the local workspace from a matching original update. This change does not
publish the repository or change its visibility.

## Set up once

Use Python 3.13. A fresh checkout needs its own dependencies and the original
Nikon v1.1 update, extracted as an archive with 7-Zip. Put `firmware.bin` at
`sources/extracted-v1.1/S3300Update/firmware/firmware.bin` relative to the project.
The accepted SHA-256 is:

```
2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b
```

In PowerShell, from the project root:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe s3300.py init
.\.venv\Scripts\python.exe s3300.py doctor
```

The current machine can use its existing `python` and project-local Capstone.
The examples below use `python` to keep commands short.

`init` creates `derived/unpacked-v1.1-indexed/` only when absent. If it exists,
it checks and reuses it. A partial or changed baseline fails with an error;
it is never silently replaced. A repeat extraction needs a new directory:

```powershell
python s3300.py --workspace derived/my-fresh-baseline init
```

Fresh extraction generates its own ELF map and passes the local source path
explicitly to both decoder validation and analysis construction. Historical
absolute paths in evidence are provenance, not dependencies on another
developer's checkout. Relocated stored decoder files are verified by their
workspace-relative locations.

## Work from the baseline

```powershell
python s3300.py limits
python s3300.py limits --search ram
python s3300.py limits --json
python s3300.py search 'Welcome screen'
python s3300.py search GAMMALUT
python s3300.py address 0x80741800
python s3300.py listing 0x80741800 derived/my-welcome-function.asm
python s3300.py build derived/my-plan.json derived/my-candidate
python s3300.py test
```

For the broader code/reference map, use `python s3300.py atlas --subsystem capture`
or `python s3300.py atlas --address 0x80737664 --assembly`. The
[atlas guide](firmware-atlas.md) records coverage, deeper contracts and remaining
questions. Rebuild into a new directory with `s3300.py atlas-build derived/new-atlas`;
select its database with `atlas --database derived/new-atlas/atlas.sqlite`.

Global `--workspace` goes before the command and selects the baseline used by
search, address lookup, listing, verification and candidate construction.
Candidate construction still uses the original project source plus the
hash-bound framing/filesystem evidence. Output must be a new directory under
`derived/`. The candidate builder performs no device transfer or update.

The [patch-plan contract](patch-plans.md) documents same-size FAT replacements
and decoded virtual spans. Changes are bound by original and replacement
hashes. Fixed allocation, compressed payload budgets and available entropy
codes constrain what can be built; arbitrary C code is not automatically
insertable. Keep related changes together in an explicit plan, including the
existing custom label when it must be retained.

Use `tools/resource_formats.py` for editable strings and indexed bitmaps.
Copy baseline JSON exports into a separate ignored experiment directory before
editing. Baseline `resources/` and `resource-editable/` remain exact originals;
doctor rejects altered exports. Patches and original source stay separate.

`doctor` checks dependency versions, the original source, exact carrier
reassembly, the authenticated analysis ELF, both stored decoder outputs, all
368 resources and 106 editable roundtrips. It also checks SQLite integrity,
source identity and table counts. It does not independently validate every
database row, rerun both decoders, or establish camera behavior. Use a fresh
`init` output when a full extraction/decoder replay is wanted.

## What still needs investigation

The [hardware and limits guide](hardware-and-limits.md) and
[`hardware/s3300.json`](../hardware/s3300.json) distinguish manufacturer
specifications, static contracts, host checks, user observations and unknowns.
Unknown values stay null; stock frame rates are not asserted as silicon limits.

All supplied bytes can be unpacked once. Original C source, undocumented
driver contracts, physical RAM and full flash contents cannot be obtained
merely by decompressing the update. Future feature work will still need
focused analysis of the relevant subsystem. Save each recovered contract,
address, evidence source and limitation in the shared catalog/notes so that
later work starts from it.

The next useful contracts are saved-photo buffer ownership/domain, menu and
settings integration, a target build/hook ABI, measured memory/timing budgets,
and reliable backup/restoration. Existing drivers remain the integration
baseline. The recovered code is not a complete source-buildable replacement
firmware, and no optimization has yet been measured on this camera.

## Validation record

All 147 offline tests pass locally. A separate temporary checkout containing
the tools, required metadata and original firmware, with no prior generated
directories, successfully built the full workspace and passed doctor. Its
second init reused the baseline; searches, address lookup and a bounded listing
worked. The CLI rebuilt the prior label candidate byte-for-byte and both
decoders agreed on the full affected segment. Deliberately changing a copied
baseline resource caused init to fail without overwriting it. This test used
the existing interpreter/dependencies; it was not a clean OS installation.
See [retained validation metadata](../evidence/developer-workspace-validation.json).
