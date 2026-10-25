# Rebuild and verify the Amber experiment

Amber is a focused saved-photo parameter experiment. It replaces the existing
Sepia label and its signed chroma-offset pair, reusing the stock monochrome
processing path. It is not the full-colour Amber Days algorithm from our C
module.

| Item | Reviewed candidate |
| --- | --- |
| Existing English Sepia label | Amber, in FAT and embedded tables |
| Signed pair at `0x80882d24` | `-30,+30` becomes `-18,+22` |
| Existing Welcome marker | Retained |
| Pocket Studio artwork | Retained |
| Executable instructions and buffer allocation | Unchanged |

## Rebuild the exact reviewed trial

On a fresh checkout, reconstruct the reviewed Pocket Studio base **once**.
Amber's independent carrier validator compares against that exact base so it
can reject unrelated artwork or carrier changes. The original artwork is
included in `firmware/branding`; generated firmware remains local.

```powershell
New-Item -ItemType Directory derived/identity-asset
Copy-Item firmware/branding/pocket-studio.jpg derived/identity-asset/Startup1.jpg
python tools/build_identity_trial.py derived/identity-asset/Startup1.jpg derived/pocket-studio-identity-candidate-01
```

If that generated base already exists, preserve and reuse it. Its required
SHA-256 is `8f742b9a699b276a001827721fab4bd50e578372a582acc020ba1caa6e75754c`.
The builder refuses an existing output directory and the validator rejects a
different base. These steps only create local artifacts; they never transfer
anything to the camera. After `init` and this one-time prerequisite:

```powershell
python tools/build_amber_trial.py derived/my-amber-build
python tools/validate_amber_trial.py derived/my-amber-build/NOT-INSTALLABLE-patch-plan.research.bin --evidence derived/my-amber-validation.json
python s3300.py validate-candidate amber-mono --candidate derived/my-amber-build/NOT-INSTALLABLE-patch-plan.research.bin
```

The reviewed candidate SHA-256 is:

```
d801708b06abbaece3974b2ae0cb9c55ce4154fffc0c132e00b35564ec86ce28
```

The builder deliberately rejects a result that differs from that candidate.
Both complete affected segments must decode through independent paths, and
the validator must confirm only the declared tint/label/identity data changes.
Changing `AMBER_TINT` in the source does not make a new build camera-ready: the
exact expected digest, independent validation and trial review would need to
be updated for the new experiment.

The earlier missing-label report was resolved on 25 October: the user had
observed **Nostalgic sepia in Special effects**, a different entry. After
selecting **Auto mode → MENU → Color options**, the user confirmed **Amber**.
The old failure is retained and superseded in the append-only ledger.

New Auto-mode photos DSCN1186/1187 both have unclipped Cb/Cr near 110/150.
The first was intended as Standard color, so that initial bypass observation
failed. A repeat with **Standard color → OK** produced DSCN1188 with normal
varied chroma, agreeing with the user's normal-colour preview report. The
earlier pair remains recorded without assigning a firmware cause. Full restart,
remembered Amber and new-photo playback also pass by user report.
The resource-ready checks now pass. See
[current camera evidence](../../evidence/amber-auto-verification-2026-10-25.json)
and the [verification note](../../notes/camera-verification-2026-10-25.md).
These observations do not identify every installed byte or measure performance.

## Camera observation sequence

The [label-path follow-up](../../notes/label-contracts.md) now traces the Color
Options text IDs through the embedded loader and ID lookup. ID 563 selects the
patched span. Both the actual reviewed candidate's English copies and bounded
host emulation select Amber. The raw dispatcher value `0x729e` is a nonzero
selector, not a parser length clamp. The later correct-menu observation
corroborates label activation; exact installed bytes remain unverified.

Use the shooting-mode button to select **Auto mode**, press **OK**, then press
**MENU → Color options**. This is the menu with Standard color, Vivid color,
Black-and-white, Amber and Cyanotype. The six-option Special effects menu still
contains Nostalgic sepia. Nikon documents the two stock menus separately on
pages 47 and E29 of the
[reference manual](https://download.nikonimglib.com/archive2/vu9iI00riFfv01k96Qt63uLVv147/S3300RM_EU%28En%2901.pdf).

After the exact build has passed its offline checks and the current camera
state has been identified, use the local trial-package workflow. Capture an
Amber photo and a Standard colour photo of the same static scene with matched
settings. Press OK to apply each colour selection, then check the preview
before taking its photo. Confirm menu text, playback, normal colour in Standard mode, restart
and whether the selected option is remembered. Keep the original JPEGs.

```powershell
python tools/analyze_color_samples.py samples/my-amber-session --evidence derived/my-amber-chroma.json
python s3300.py record-result --help
```

Record a new observation with `record-result TRIAL --check CHECK --outcome
pass|fail|unknown --notes TEXT`, adding `--sample PATH` when an original local
artifact supports it. Use the check names in the help; a check is pass only
after the specific observation exists. Do not add an unknown or synthetic
example merely to exercise the command, because it becomes a real ledger entry.
Retain the source
images' hashes and whether evidence is a direct artifact or a user report.
An automated chroma summary needs interpretation around JPEG rounding,
clipping and the selected image mask. It is not an aesthetic-quality score.

## Why this example matters

It exercises an existing selectable menu mode and image-processing mechanism
without adding another full-frame pass. That is a promising development pattern
for constrained hardware. It does not demonstrate a speed or energy saving:
those require matched camera measurements. It also does not solve executable
hooks, arbitrary RGB processing or unbootable recovery.

Read the [trial research record](../../notes/amber-mono-trial.md) for exact build,
resource and source provenance.
