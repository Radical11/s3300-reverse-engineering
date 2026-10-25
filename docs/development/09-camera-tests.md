# Test on the camera and measure behavior

## Establish what is installed

A version string such as v1.1 cannot distinguish several custom candidates.
Record the observed menu/artwork markers, reported version, last reviewed update
hash and how that association was established. Do not select a causal baseline
from a historical filename alone. Standard USB inventory can describe the
connected device and card; it cannot prove the installed executable bytes.

Copy baseline photos through the known file-read path. Preserve their original
bytes, timestamps and source/backup hashes. Do not write test output into DCIM,
format the card, repair its filesystem or use guessed vendor commands.

## Record each check independently

For a reviewed resource/processing-data trial, check its intended menu or art,
then the relevant saved output. Check Standard/Original behavior, playback,
restart, settings persistence and normal shooting. Record exactly how many
repetitions occurred. A user saying it works is valuable evidence, but it does
not invent an unreported cold-start count or saved-photo comparison.

```powershell
python s3300.py record-result --help
python s3300.py readiness --json
```

Use `record-result TRIAL --check CHECK --outcome pass|fail|unknown --notes TEXT`
for a real new observation, with `--sample PATH` when it supports the check.
Never run synthetic example observations against an actual trial ledger.
Use pass/fail/unknown according to the actual observation and supported check
IDs. An adverse
result stays in the ledger even if a subsequent trial passes. Match all results
to the exact reviewed candidate; do not transfer a label result to another
image.

The photo effect test needs original saved JPEGs, rather than a photo of the
LCD. A colour change can appear in preview while a different pipeline produces
the stored image. For memory or buffer instrumentation, prove the access and
side-effect boundary before using a live transport.

## Measure a performance target

Choose one visible metric: startup-to-ready, autofocus, shutter response,
next-shot readiness or button feedback. Internal processing/card-write timings
need a verified trace or distinguishable endpoint; one busy icon cannot divide
them. A phone video can time visible events using its real frame timestamps
and uncertainty. EXIF timestamps alone cannot separate those stages.

Match scene/light, resolution, exposure/focus/flash mode, card/free space,
battery/power state, temperature and method. Keep cold and warm starts separate.
For initial comparisons retain at least 20 successful observations per condition
and retain failures as well. This minimum does not guarantee statistical power.

The CSV contract is in `benchmarks/measurements.csv`. Its fields include build,
resolution, condition/trial IDs, metric, latency, uncertainty, outcome, evidence
and notes. Valid failure outcomes include crashes, corrupt photos, timeouts and
cancel failures. Use unique trial IDs and analyze:

```powershell
python tools/analyze_benchmarks.py benchmarks/measurements.csv
```

Compare a modified v1.1 build to a genuinely matched v1.1 baseline. A change
between Nikon v1.0 and v1.1 cannot be attributed solely to our patch. Require a
repeatable difference larger than timing uncertainty, unchanged image integrity
and no unacceptable slow-tail regression before claiming an improvement.
Battery or energy savings require separate controlled measurements; a lower
host-kernel time does not demonstrate them.

## Camera controls stay human-operated

When a trial needs a connection change or camera menu action, follow the exact
reviewed trial steps and record completion. Ordinary host build commands do not
issue remote flashes. Do not disconnect power while the camera reports an
update in progress. This guide is software-only and does not include opening
the camera, soldering, probing pads or changing its electrical configuration.
