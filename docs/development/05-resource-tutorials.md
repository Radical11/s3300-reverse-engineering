# Edit strings, indexed artwork and startup art

## Begin with a no-change roundtrip

Keep `resources/` and `resource-editable/` in the baseline untouched. Copy a JSON
export into a new experiment directory, then import it into a new file. Before
changing anything, compare its SHA-256 with the original resource. That confirms
the exact codec/library path works in your environment.

```powershell
New-Item -ItemType Directory -Path derived/my-text
python tools/resource_formats.py export derived/unpacked-v1.1-indexed/resources/String/Res_Str_Eng_New.bst derived/my-text/english-original.json
python tools/resource_formats.py import derived/my-text/english-original.json derived/my-text/english-roundtrip.bst
Get-FileHash derived/my-text/english-roundtrip.bst -Algorithm SHA256
```

The export is structured data. `code_units` is authoritative for strings;
`text_projection` is a reading aid. Two-byte units use big-endian storage, and
some languages use font glyph identifiers rather than ordinary Unicode.
Serialized ordinals are not universally established runtime UI IDs.

## Make a bounded English text edit

Copy `english-original.json` to `english-edited.json`. Find the intended entry
using its projection and verify the original units. Change only the intended
units, preserving entry order, count and encoded length for a first edit.
Import to `english-edited.bst`, then inspect its exact changed byte spans.

```powershell
Copy-Item derived/my-text/english-original.json derived/my-text/english-edited.json
python tools/resource_formats.py import derived/my-text/english-edited.json derived/my-text/english-edited.bst
Get-FileHash derived/my-text/english-edited.bst -Algorithm SHA256
```

Make the edit between the copy and import commands. The English table exists
both in FAT resources and inside the packed application. The Welcome experiment
showed that changing only one copy can leave the active menu unchanged. Trace
the specific resource consumer and use an explicit combined plan when both
copies are relevant. Do not assume every resource has an embedded copy.

## Build a resource patch plan

The plan below is a template: replace the two hash placeholders with exact
original and edited resource hashes. `replacement_file` is project-relative.

```json
{
  "schema_version": 1,
  "source_sha256": "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b",
  "name": "my-english-resource-experiment",
  "patches": [
    {
      "kind": "resource",
      "path": "String/Res_Str_Eng_New.bst",
      "expected_sha256": "ORIGINAL_RESOURCE_SHA256",
      "replacement_file": "derived/my-text/english-edited.bst",
      "replacement_sha256": "EDITED_RESOURCE_SHA256"
    }
  ]
}
```

Save the completed plan as `derived/my-text/plan.json` and build:

```powershell
python s3300.py build derived/my-text/plan.json derived/my-text-candidate
```

This generic resource-only example does not include the embedded table or
preserve unrelated identity changes automatically. It is a host build tutorial,
not a registered camera trial. The [patch-plan contract](../../notes/patch-plans.md)
describes virtual spans and validation rules.

## Indexed bitmaps

Use the same export/import tool on a ZBM resource. Edit the index rows within
their bit-depth range and preserve dimensions, header and unused row bits.
The grayscale PGM is an index projection. Palette selection, orientation and
UI composition remain separate contracts; a sensible host preview alone does
not prove the camera will display the intended colours.

## Startup art

```powershell
python tools/build_startup_asset.py derived/my-startup-art
python s3300.py build derived/my-startup-art/patch-plan.json derived/my-startup-candidate
```

The existing generator draws our original Pocket Studio geometry and searches
for a natural JPEG encoding with the original logical size. Inspect the SVG,
JPEG, marker/sampling contract and generated plan. The reviewed resource is
24,210 bytes at 640 by 480; these resource dimensions are not proof of the
display's framebuffer geometry. The search may take many encoding attempts and
can fail without emitting a padded substitute.

Changing the generator is editing our source. Keep its design separate from
the preserved vendor image and use tests/format checks on the generated result.
Combine the intended identity/text changes explicitly. A filename or same-size
JPEG alone does not establish the active consumer or update acceptance.
