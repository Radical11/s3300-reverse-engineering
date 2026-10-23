# Unpacked firmware development workspace

24 October 2026. `derived/unpacked-v1.1/` is a fresh, reproducible unpacking of
the supplied v1.1 update. It is local and ignored by Git because it contains
vendor firmware, artwork and language data. Research tools and metadata are
committed. No camera connection or vendor executable was used by this pass.

## Coverage, with the boundaries explicit

| Layer | Extracted and checked |
| --- | --- |
| Complete supplied carrier | 19,005,632 bytes in 14 contiguous pieces; reconstructed in memory and SHA-256 matched |
| Original executable representations | Six ELF files, with extents parsed directly from their original headers |
| Packed application | Fresh decode of 463 blocks into 7,950,592 bytes; separate prefix/zlib implementation matched |
| Address map | Eight-region analysis ELF, independently parsed back and compared; original ELF program headers verified |
| Allocated resources | 368 files, 11,246,707 bytes; each checked against original FAT source chunks |
| String resources | 33 ZST/BST tables, 98,085 length-prefixed records; exact EOF/count and byte-for-byte re-encoding |
| Indexed bitmap resources | 73 ZBM files; exact geometry, index export and byte-for-byte re-encoding |
| Other image/audio containers | 155 JPEGs and 12 PGM images parsed; seven PCM WAV files parsed |
| Search database | 26,976 printable application byte sequences, 1,924 original symbol entries, resources and UI records |
| Compiler-provided function ranges | 5,798 nonoverlapping ranges, covering 2,267,704 bytes; source and unwind headers checked |

Byte coverage is complete for the **supplied file**. The actual FAT volume
declares a further 2,611,712 bytes beyond it. All live allocated files fit; that
missing logical tail was not fabricated. Unknown headers, gaps, file slack and
opaque formats are preserved and identified. Their semantics are not all
recovered. Firmware extraction does not recover Nikon's original C source,
hardware design, installed-v1.0 flash or device calibration.

`carrier-parts/` is a lossless partition, not a redesigned firmware format. It
does not strip checks or produce a custom installer. `--verify` reconstructs
the original in memory; it never writes firmware to a device or an update card.

## Reproduce and search

Run from the repository root. The output directory must be new.

```powershell
python tools/unpack_workspace.py derived/another-unpacked-v1.1
python tools/unpack_workspace.py derived/another-unpacked-v1.1 --verify
python tools/query_workspace.py derived/another-unpacked-v1.1/research.sqlite --search 'Welcome screen'
python tools/query_workspace.py derived/another-unpacked-v1.1/research.sqlite --search GAMMALUT
python tools/query_workspace.py derived/another-unpacked-v1.1/research.sqlite --address 0x8021c7a8
python tools/workspace_functions.py derived/another-unpacked-v1.1 --listing 0x80741800 --output derived/welcome-function.asm
```

The query tool opens SQLite read-only and treats searches as literal text. It
can return exact-address zero-size labels as well as containing symbols.
Application printable strings are byte-pattern candidates, not proof of code
reachability. Original symbols belong to their named ELF artifact; the separate
updater overlaps application virtual addresses and its names must not be
assigned to application code at the same address.

Fresh workspaces include a `functions` table from independently checked
exception-metadata headers. For an older workspace without that table, run
`python tools/workspace_functions.py derived/older-workspace` once to add it.
The tool authenticates the analysis ELF and its actual program headers, then
reparses the range records; it does not trust address labels from loose JSON.
Address searches return a containing range where available. A listing request
accepts an address inside that range and writes the complete bounded MIPS32
decode to a new file, requiring every instruction byte to decode.

No original names, C source, complete control-flow analysis or executable hooks
are implied. Some functions have no recovered unwind metadata. The metadata's
CFI instructions and exception semantics remain outside the parser coverage;
see `unwind-functions.md`.

The command runs the decoder, independent validator, resource extractor and
analysis-ELF builder, retaining their logs. Those dependencies use the existing
source-bound framing and mapping evidence and then authenticate ELF metadata
directly against the supplied source. See `requirements-analysis.txt`; image
verification also uses the existing Pillow package (12.3.0 in this pass).

## Resource editing contracts

The `resource-editable/` folder holds JSON exports for all 33 string tables and
73 indexed bitmaps. Both codecs rebuild every original file byte-for-byte.

```powershell
python tools/resource_formats.py export derived/unpacked-v1.1/resources/String/Res_Str_Eng_New.bst derived/english-edit.json
python tools/resource_formats.py import derived/english-edit.json derived/english-resource-copy.bst
```

ZST preserves the 22-byte header, opaque default region and ordered records.
Each record has a little-endian u16 byte length, code-unit bytes and a zero
terminator. Two-byte code units use big-endian storage. English yields readable
characters; other languages may contain glyph identifiers requiring the
matching font. `code_units` is the editable authoritative field, while
`text_projection` is informational. Serialized ordinals are not yet verified
as runtime UI IDs. The tool rejects entry reordering/count changes.

ZBM preserves its 32-byte header, one- or four-bit indices and unused low row
bits. The PGM exports show index values. Actual colours, palette mapping and
hardware orientation remain unresolved, so these projections cannot validate
an on-camera appearance. The codec rejects inconsistent geometry and indices.

An edited standalone resource still needs validated consumer semantics,
allocation/repacking rules, update acceptance and recovery before installation.
The original files remain unchanged.

## Resource budget and efficiency opportunities

| Directory | Stored file bytes |
| --- | ---: |
| Font | 3,770,120 |
| JPG | 3,528,480 |
| seal | 2,081,149 |
| String | 1,304,243 |
| Bmp | 390,670 |
| Icon | 84,256 |
| Wav | 47,014 |
| Root-level tables/descriptors | 40,775 |

Three groups have duplicate file contents, totalling **84,785 duplicate bytes**.
This is a storage investigation lead, not an automatic deletion list. File
paths, resource IDs, language selection and ownership may require distinct
entries. Fonts and language tables occupy substantial storage but do not prove
a CPU or RAM bottleneck. Reduced storage alone does not imply faster capture.

The startup art and chime together occupy **48,304 bytes**, about 0.25% of the
supplied carrier. The useful customization is control over presentation and
identity; removing those files does not by itself explain a slow camera.

Nikon's [S3300 reference manual, E49](https://download.nikonimglib.com/archive2/vu9iI00riFfv01k96Qt63uLVv147/S3300RM_EU%28En%2901.pdf)
documents **Setup → Welcome screen → None** as a stock way to suppress the
welcome screen, and **Select an image** as a personal-image option. That is
documented stock behaviour, separate from our unfinished full power-on trace;
no setting was changed and no startup improvement measured. See
`evidence/documented-welcome-options.json` for source access and scope.

A more specific processing candidate is repeated gamma conversion despite the
existing raw-resource cache. Its 0x994-byte output and 0x4000-byte scratch
allocation are mapped, and a consumer frees the output. A converted cache needs
an explicit ownership/invalidation design and real invocation/cost measurements.
See `development-interfaces.md` for the APIs and the use-after-free trap.

## Next implementation order

Finish the welcome-setting-to-startup path and persistent-settings contract;
develop a minimal optional welcome presentation; expose a typed, bounded
profiling interface only after its transport is established; measure the
largest bottleneck and make one verified change. In parallel, use the resource
codecs to design compact menus and distinctive looks against confirmed photo
processing stages. Keep the original mode and the existing hardware drivers.

Custom branding, quick controls, an accessible developer workflow and fun
shooting modes remain the product direction. A fully understood codebase,
working custom installer, runtime optimization and tested recovery are still
unfinished work, not consequences of the extraction milestone.
