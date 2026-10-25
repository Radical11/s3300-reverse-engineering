# Working on the S3300 firmware lab

The current shared baseline is the default branch, `codex/s3300-firmware-research`.
Start from the [developer handbook](docs/development/README.md) and
[latest backup/recovery findings](notes/backup-recovery-progress-2026-10-25.md).
Our code and documentation are MIT licensed; the [third-party boundaries](THIRD_PARTY.md)
explain which inputs and generated artifacts must stay local.

## Clone and run the offline tools

Repository access is required because this repository is private.

```sh
git clone --branch codex/s3300-firmware-research https://github.com/Radical11/s3300-firmware-lab.git
cd s3300-firmware-lab
python -m venv .venv
```

Use Python 3.13. On Windows, run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe s3300.py guide derived/team-guide
.\.venv\Scripts\python.exe s3300.py browse
```

On Linux, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`.
The ordinary test suite, guide and interface catalog work without a camera or
Nikon firmware. Tests that require private native exports explicitly skip when
those exports are absent. A fresh clone has no local function database or photo
backup; the browser displays that limitation instead of pretending to have them.

Open `derived/team-guide/index.html` for the searchable offline handbook. The
browser command prints a localhost URL and offers read-only views. It performs
no camera operations.

## Add your own authenticated firmware input

Follow [setup](docs/development/02-setup.md) to obtain and extract the original
Nikon v1.1 updater locally. The expected input is:

```text
sources/extracted-v1.1/S3300Update/firmware/firmware.bin
SHA-256: 2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b
```

Then run:

```sh
python s3300.py init
python s3300.py doctor
python s3300.py readiness
python s3300.py interface --search recovery
```

Use the virtual environment's Python for these commands too. The source input,
installed camera state and generated candidate are separate identities; a v1.1
version string does not prove byte equality. Never substitute another model or
edit source headers to make an input pass validation.

Expensive analysis is reusable. Preserve local Ghidra projects and exports,
then use the index and research-map commands documented in the handbook.
Reused results must match their source hashes, tool versions and analysis
profiles. Do not copy another machine's paths into a report and call it a new
analysis. Source newline changes can also change verifier/exporter fingerprints;
regenerate a matching report rather than removing a stale-input check.

## Choose a bounded research task

Useful independent work includes:

- Backup/recovery: a bounded software read route, installed ROM/reset entry,
  complete calibration coverage, physical geometry and spare/ECC representation.
- Image integration: live component order/range, buffer extent/lifetime,
  synchronization, cache/DMA ownership and an eventual narrow adapter.
- Controls: verified custom menu ownership, persistence, write-failure handling
  and an Original bypass.
- Host tooling: search/navigation, reproducibility, decoder comparisons,
  diagnostics and tests that catch invalid or stale inputs.

Search existing notes and the interface catalog before repeating an analysis.
For each finding, record the exact source/image namespace, address, method,
verified behavior, side effects, confidence and remaining gaps. Direct Ghidra
output must remain separately labelled from REA Evidence. Preserve failed
experiments and contradictory observations.

## Submit changes

Create a branch such as `codex/your-name-backup-contract`, keep its scope small,
run the relevant checks and open a pull request against the default branch.
Describe the resulting behavior, the evidence supporting it and what remains
unknown. Retain source hashes and an exact reproduction command for new maps.

Before pushing, inspect `git diff --cached --stat` and `git diff --cached`.
Keep proprietary firmware/assets, generated vendor pseudocode/databases,
personal photos, device serials, credentials, virtual environments and tool
caches out of Git. Metadata and hashes can be shared when they contain no
private payloads. The ignored `sources/`, `derived/`, `samples/`, `work/` and
`tools/vendor/` directories are local inputs/outputs, not missing source code.

Ordinary builds create local candidates. Camera file backups use explicit
read-only commands; they are not installed-flash backups. Do not add automatic
card transfer, firmware update or unreviewed device operations to a build.

**Executable camera trials remain blocked.** The current file backup and normal
menu update do not establish recovery from an unbootable application. Follow
the closed trial registry and the existing backup/recovery gate; a passing host
test or a newly recovered function address cannot approve a camera trial.
