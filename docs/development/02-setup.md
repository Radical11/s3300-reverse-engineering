# Install and reproduce

## Python and the original input

Use Python 3.13, the version used by project CI. Create a virtual environment so
the pinned analysis packages do not change your global Python installation.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
```

On Windows this also installs pinned `comtypes` for explicit read-only WPD
camera commands. Linux skips that conditional dependency and can run offline
analysis/tests. Camera commands retain the existing Windows driver; the browser
never starts them.

Extract the original Nikon v1.1 updater as an archive with 7-Zip. Place its
firmware at `sources/extracted-v1.1/S3300Update/firmware/firmware.bin`.
Do not run the vendor updater on the computer merely to obtain the file.

The accepted firmware SHA-256 is:

```
2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b
```

A firmware-version string alone is not enough to select an input. Another
model, another version or an installed-flash dump may have a different layout.
The tools intentionally reject it rather than guessing.

## Unpack once and reuse

```powershell
.\.venv\Scripts\python.exe s3300.py init
.\.venv\Scripts\python.exe s3300.py doctor
.\.venv\Scripts\python.exe s3300.py atlas-build derived/my-first-atlas
```

`init` creates the default workspace only if absent. Otherwise it verifies and
reuses it. It does not erase a partial or changed directory. Use a new path
for a fresh extraction:

```powershell
python s3300.py --workspace derived/fresh-baseline init
python s3300.py --workspace derived/fresh-baseline doctor
```

Doctor checks source identity, exact carrier reconstruction, the authenticated
analysis ELF, both stored decoder outputs, all allocated resources and editable
roundtrips. It checks SQLite integrity, source metadata and counts, rather than
proving every indexed row. A fresh extraction reruns both decoding paths.

## Portable native analysis

```powershell
python s3300.py native-setup
python s3300.py native-analyze derived/my-native-analysis --decompile-limit 25
```

The setup installs pinned portable Ghidra and JDK artifacts in the dedicated
tools cache, with official digest checks. It does not change global Java,
Codex registration or an existing VM. The native analysis command records tool
versions and original image identities and keeps its database for reuse.
Use `native-analyze --help` for the selected run's supported limits and resume
option. `--image` selects a particular executable image and `--resume` reuses
only a matching recorded analysis profile. Do not reuse a database with a different source digest or analysis
profile. A retained error is a failed analysis item, not invented pseudocode.

REA provides the investigation workflow and supported artifact evidence. The
installed REA native adapter rejects this target's missing ABI metadata and its
Windows MIPS ELF lane. Direct Ghidra output is therefore labeled independently.
No tool should fabricate ABI sections or change source headers to bypass that
boundary. Ghidra's inferred types and function boundaries remain analysis
results, not Nikon's source declarations.

## Index the completed application export

The existing full run is under `derived/native-analysis-complete`. A directory
with a short smoke export is not interchangeable with that run. Build an index
from a completed, verified application export into a new output directory:

```powershell
python s3300.py native-index derived/native-analysis-complete derived/my-native-index
python s3300.py pseudocode --database derived/my-native-index/native.sqlite --address 0x80737664
python s3300.py pseudocode --database derived/my-native-index/native.sqlite --search Capture --limit 10
```

Without `--database`, pseudocode lookup uses
`derived/native-index-final/native.sqlite`. The indexer checks exported instructions
against the authenticated image and retains decompiler failures separately.
The full application export discovered 15,816 function dossiers, including
three initial decompilation failures. A focused longer retry recovered one;
the other two engine errors remain retained. That count is a Ghidra observation,
not proof that every inferred function is correct or all program semantics are
known. Each separate executable has its own export/status; consult the retained
run manifest rather than assuming the application result covers every image.

## Index all retained executable namespaces

```powershell
python s3300.py artifact-index derived/my-artifact-index --native derived/native-analysis-complete --application-index derived/native-index-final/native.sqlite
python s3300.py artifact-function --database derived/my-artifact-index/native.sqlite --image image-00000200 --address 0x80010dd4
python s3300.py browse --database derived/my-artifact-index/native.sqlite
```

The retained combined index is `derived/artifact-function-index-v1.1/native.sqlite`.
It contains 19,526 functions: 15,816 application, 1,526 updater, 16 tiny loader
and 2,168 primary-image entries. Three packed carriers have inventory records
and zero indexed functions; their decoded code belongs to the application map.
This is a coverage count, not proof of complete semantics. The builder checks
291,105 separate-image instruction records against the original ELF bytes and
reuses the authenticated application index's 1,369,833 checked records.

Each function belongs to one image. For example, `0x80010dd4` is an inferred
application function but `UartClientWrite` in the updater. Select the image
before following calls or interpreting arguments. The tiny loader retains its
MIPS16 entry/mode metadata. Separate executable carriers do not imply that all
of them coexist in installed RAM at their ELF addresses.

The browser prefers the combined index when present and otherwise uses the
application-only index. Both are local generated artifacts, excluded from the
source archive. Rebuild them from the retained matching exports; preserve the
Ghidra projects and exports separately for offline research.

The later backup/recovery pass adds one caller-seeded application writer in a
separate focused project. Reproduce that bounded import with
`python tools/focus_application_writer.py derived/my-writer-focus`.
The [application writer report](../../notes/application-write-scope.md) explains
its boundary and type warning. Its source-bound research map needs this focused
export in addition to the retained main export; it is deliberately excluded
from source-only archives with other vendor-derived listings.

```powershell
python s3300.py artifact-index derived/artifact-function-index-current --application-writer-focus derived/application-writer-focus-2026-10-25
python s3300.py artifact-function --image application --address 0x803d73dc
```

This adds only the authenticated focused writer dossier to the application
namespace, retaining the original combined index. The current index has19,527
functions, including15,817 application entries. The browser and artifact lookup
prefer `derived/artifact-function-index-current` when present. Rebuilding needs
a new directory; a focused export cannot replace an existing entry silently.

## Fresh-checkout acceptance

Keep originals outside the public source archive. On another checkout, install
the pinned packages, place the same hash-matching original input, run `init`,
build an atlas, and rebuild a representative candidate. Compare all declared
output hashes. Run the test suite there too. A directory that works only
because it refers to an earlier developer's absolute paths has failed this
acceptance test.

The public source package must exclude `sources/`, generated vendor-derived
analysis under `derived/`, private samples and local tool caches. The
repository's ignore rules are a useful boundary, not a replacement for checking
the actual contents of an archive before sharing it.
