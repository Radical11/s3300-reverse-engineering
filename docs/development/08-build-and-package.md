# Build, validate and prepare a trial

## Keep artifacts separate

The preserved original is the input. Baseline analysis/resources are immutable
references. Editable copies and feature inputs live in an ignored experiment
directory. Candidate images and validation reports go into a new output
directory. Neither a candidate build nor guide generation contacts the camera.

```powershell
python s3300.py build derived/my-plan.json derived/my-candidate
python s3300.py test
python s3300.py validate-candidate amber-mono --candidate derived/my-amber-build/NOT-INSTALLABLE-patch-plan.research.bin
python s3300.py prepare-trial amber-mono derived/my-amber-package
```

`validate-candidate` selects a reviewed trial validator. `prepare-trial` creates
the local card-layout package only after exact registered-hash and validation
checks. It is not a generic route for staging an arbitrary image. Physical card
staging, verified readback and the camera's update confirmation are later
operations. Use each command's `--help` to inspect its current arguments.

## Budgets enforced by the fixed-extent builder

| Change | Current constraint |
| --- | --- |
| FAT resource | Preserve logical size, allocation chain and directory metadata |
| Decoded virtual span | Preserve extent and bind original/replacement bytes by hashes |
| Packed application | Preserve block framing and payload budgets; available entropy codes constrain encoding |
| Cross-block data | A change can require rewriting subsequent blocks because the 32 KiB history changes |
| Combined feature | Reject overlaps, duplicate edits, missing input hashes and no-op replacements |
| Carrier | Allow only declared payload/resource changes plus the known checksum; retain version/product/download descriptor |

Shorter compressed data is not permission to relocate code or use the remainder
as a new allocator. A packed replacement can fail because its symbols are not
representable by the existing tables even when its decoded size is unchanged.
An overflow must fail rather than truncate a feature.

## Independent validation

The builder's own success is one check. For an admitted camera trial, use a
separate validator that reconstructs the expected changes and decodes the full
affected segments independently. Compare all decoded bytes, intended edit
spans, framing, resource allocation, carrier extent and checksum. Rebuild
twice and compare hashes; retain the exact candidate used for observations.

The supplied update is not a full internal-flash backup. Keeping its hash and
a working prior update file protects provenance but does not establish
calibration coverage or recovery from an unbootable application.

## Keep interruption and errors reviewable

Tools refuse to overwrite existing outputs. An interrupted operation may leave
a partial directory. Do not relabel it a finished build or silently replace it.
Keep its log for diagnosis and choose a new output path, or use a documented
hash/profile-checked resume mechanism for expensive native analysis. Results
must identify failed or skipped functions and missing data.

Run the appropriate tests once the change is stable. Synthetic checks can run
without vendor bytes in public CI. Local input-bound checks need the original
hash-matching image and must keep proprietary output in ignored paths. A
cross-platform test pass verifies the host tooling, not camera operation.

## Share our development source separately

```powershell
python s3300.py package-development derived/development-source.zip
```

This creates a local source-only archive. It does not publish a repository,
change GitHub visibility or bundle proprietary inputs, private photos, extracted
vendor code or local tool caches. Inspect the package manifest and archive
contents before sharing it. A recipient obtains the original update separately
and follows the fresh-checkout setup rather than inheriting our local paths.
Choose a new archive path for a new package.
