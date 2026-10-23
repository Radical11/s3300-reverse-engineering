# Camera timing evidence

The camera remains on stock v1.0. The CSV in `benchmarks/measurements.csv` is
deliberately empty. No speed or battery improvement has been measured.

Record separate observations for startup-ready, autofocus, shutter response,
processing, card writing, next-shot readiness and button feedback. A phone
video can establish visible button/indicator/ready events; use its actual frame
timestamps and record frame uncertainty. Do not invent internal processing or
card-writing durations from one visible busy indicator. Those stages need a
verified trace or independently identifiable endpoint. EXIF timestamps alone
cannot separate them.

For each condition, record the scene/light, settings, autofocus and flash mode,
card identity/free space, power state, temperature and measurement method in a
condition note. Use the same condition identifier only when these match. Keep
16 MP and 8 MP trials separate. Warm and cold startup are separate conditions.
Use at least 20 successful trials per preliminary comparison and retain failed,
corrupted, timed-out and cancelled trials. More observations may be needed for
slow-end variability; 20 is not a guarantee. Keep original timing video/traces
and photo-integrity observations under ignored `benchmarks/private/`.

For a modified v1.1 build, use the identical **stock v1.1** build as the causal
baseline after recovery and installation are established. Current stock v1.0
observations are still useful, but differences between Nikon versions cannot
be attributed to our changes. Nothing in this protocol authorizes an update or
requires changing the installed v1.0 during offline analysis.

```powershell
python tools/analyze_benchmarks.py benchmarks/measurements.csv
```

The analyzer rejects duplicate trials and invalid values, keeps failures,
reports median/p95/worst successful latency and refuses comparison across
different conditions or resolutions. It records no automatic acceptance. A
lower median must also exceed timing uncertainty, survive repeated matched
runs and preserve the slow end and image integrity before it becomes a speed
claim. Compare resolutions within the same stock build before proposing a Fast
option. Battery tests require separate observations under controlled workload;
timing reductions alone do not demonstrate battery gains.

Initial static leads are not optimizations: CPU performance monitors may be
inaccessible at runtime, and the gamma resource loader already has a cache.
No instrumentation, cache rewrite, watchdog edit, lens change, clock change or
image-processing bypass has been installed.
