# Reproducible fixed-extent patch plans

24 October 2026. `tools/build_patch_candidate.py` generalizes the one-off label
builder into an offline image builder. It supports complete allocated FAT
resources and explicit decoded spans inside packed application segments.

Each plan pins the original v1.1 carrier and both sides of every edit by SHA-256.
Replacement files must be project-relative local files. Resource replacements
retain the exact original file length, cluster chain and directory metadata.
Virtual replacements retain their decoded extent. Overlapping virtual edits,
duplicate resource edits, no-op replacements, missing entropy codes and payload
overflow are rejected. No segment is relocated or enlarged.

The builder authenticates the existing analysis ELF, checks packed segment
locations against the original ELF program headers, and checks all original
block headers, tables and payloads. It re-encodes blocks affected by a patch or
its changed 32 KiB history, then decodes the entire affected segment through
both the production decoder and independent prefix-code/native-zlib path.
Only declared resource chunks, rewritten payloads and the known additive
checksum may differ in the carrier. Version, product marker and download
descriptor are preserved.

## Concrete regression result

A two-patch plan reproduces the already-staged embedded/FAT `Welcome studio`
candidate **byte for byte**, SHA-256:

```
a222ab366e8f328dc3a3be17b780fa42cba988d3b220487b4fb14a8016a270b4
```

The affected 151-block segment again passes both decoders, with five changed
decoded data bytes and 1,861 changed carrier bytes. Local input/replacement files
are under ignored `derived/patch-plan-label-regression-01/`; the rebuilt image
is under `derived/patch-plan-label-regression-build-01/`. The metadata-only
record is `evidence/patch-plan-label-regression.json`.

This ties the reusable tool to a prior real-camera observation without
pretending that a new arbitrary plan inherits that candidate's hardware result.
Seven synthetic regression tests include a two-block case in which changing
the first block requires rewriting an otherwise unmodified continuation block
to preserve its decoded output.

## Plan shape and use

```json
{
  "schema_version": 1,
  "source_sha256": "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b",
  "name": "local-research-experiment",
  "patches": [
    {
      "kind": "resource",
      "path": "JPG/Startup1.jpg",
      "expected_sha256": "<original resource SHA-256>",
      "replacement_file": "derived/my-assets/Startup1.jpg",
      "replacement_sha256": "<replacement SHA-256>"
    }
  ]
}
```

For a virtual span, use `"kind": "virtual"` and an integer `"address"` in
place of `"path"`. The expected hash covers exactly the replacement length.
Create inputs under ignored local directories; do not publish vendor bytes.

```
python tools/build_patch_candidate.py derived/my-plan.json derived/new-candidate
```

Output is deliberately a research image with a manifest. The tool has no USB,
card or flash functionality and does not add outputs to the staging registry.
Source matching, decoder agreement and checksums validate bytes; they do not
establish the intended camera behavior, performance benefit or recovery path.
