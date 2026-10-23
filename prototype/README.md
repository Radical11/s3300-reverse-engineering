# Tone-curve experiment

This is an offline algorithm prototype, **not a camera firmware patch**.

The S3300 v1.1 resource filesystem contains four 256-byte `GammaDDE` files.
The first is exactly 0 through 255; the others are monotonic mappings with
progressively larger runs of output 255. This supports an 8-bit tone-curve
interpretation. It does not identify their active modes, colour space or input
domain, or prove that an edited table will be accepted.

`gentle_lift_luma8.bin` and `tone_curve.h` demonstrate a mild tonal lift using
a 256-byte lookup table. `tone_curves.csv` compares every input/output pair;
`metrics.json` records exhaustive range, endpoint and monotonicity checks.
For a hypothetical full-range 8-bit input, the candidate reaches white only at
255. Nikon's other tables may deliberately create a stronger effect; these
counts alone do not establish better image quality.

The algorithm can avoid a power/exponent operation per pixel **if integrated
through a suitable existing lookup stage**. Nikon already uses lookup-like
resources, so no speed or energy improvement has been demonstrated.

Before integration: find the actual resource loader and format, identify where
the table acts, establish input/output ranges, measure stock behaviour on real
camera images, resolve update integrity and establish a recovery method. The
960-byte `GammaLut0.bin` is a different packed-looking format and must not be
replaced with this 256-byte table.

Reproduce with `python tools/prototype_tone_curve.py` from the project root.

The next candidate is a band-processed RGB luminance lift tested on eight
original S3300 JPEG copies. See `notes/processing-pass-2.md` and
`tools/evaluate_tone_curve.py`. `shadow_lift.h` is a row-oriented C design;
it has not been compiled or integrated into the camera firmware.
