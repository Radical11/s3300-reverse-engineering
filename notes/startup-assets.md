# Original startup artwork

24 October 2026. The custom English menu label is user-observed on the camera.
That establishes the earlier label trial. The startup artwork below was
subsequently combined with that marker, staged and tested: the user confirms
update completion and changed artwork. See `pocket-studio-trial.md` and the
separate runtime-observation record. The original asset-build manifests retain
their offline status as historical records of when they were created.

`tools/map_startup_assets.py` authenticates the v1.1 carrier and analysis ELF,
reconstructs the allocated FAT files, checks whole-file embedded copies, and
records the reviewed source-bound call sites in `evidence/startup-assets.json`.
These are Python/Capstone static findings, not native REA Evidence.

The JPEG resource is `JPG/Startup1.jpg`: 24,210 bytes, 640 × 480 RGB, baseline
SOF0, 8-bit components, 4:2:2 sampling and one scan. It has no exact whole-file
copy in the mapped application. The path literal at 0x803878f4 is passed to
0x802219e0 at 0x8074171c, 0x80741888 and 0x807419b0. The reviewed call chain
continues through 0x80233cb0, 0x8023393c and 0x80237a34 to 0x80237698. This
supports a filename-based resource hypothesis; it does not establish active
runtime selection. The fourteen-category HCE dispatcher reviewed at 0x8000c300
has no startup JPEG or audio case. Other resource paths/caches are not excluded.

`tools/build_startup_asset.py` draws original POCKET STUDIO artwork from explicit
pixel glyphs and rectangles. No installed font, network image, Nikon artwork
or vendor byte sequence is copied into the tracked design source. It emits an
SVG source, JPEG, manifest and resource patch plan into ignored `derived/`.
The design uses a warm cream background, dark type, orange viewfinder corner
and MAKE A LITTLE MEMORY footer.

The generated JPEG has exactly the original **24,210-byte** logical size. A
bounded deterministic encoding search varies visible fine texture. It does not
add a JPEG comment, unused marker, trailing bytes or arbitrary padding. The
replacement matches the stock frame components, sampling, marker order and
single-scan structure, and Pillow fully decodes it. This preserves the FAT
file size and existing allocation: no directory length, FAT chain, encoded
application block, executable code or update-policy change is needed.

On Pillow 12.3.0 the successful build uses quality 31 and 177,241 textured
pixels after 2,310 encoding attempts. The JPEG SHA-256 is
`d003134ffe03c7f4ceb54bb58219d75c451f0bb16eebf0a4294c8d3bd22a14b4`.
Encoding/library versions can affect bytes; the emitted plan binds the exact
replacement digest. The host preview was visually inspected at 640 × 480.

```powershell
python tools/map_startup_assets.py --output evidence/new-startup-map.json --listings derived/new-startup-map
python tools/build_startup_asset.py derived/new-startup-art
python -m unittest discover -s tests -p test_startup_asset.py -q
```

Use the generated `patch-plan.json` with the separately validated generic
patch builder. The artwork alone does not preserve the earlier label change;
the caller must deliberately combine the independently bound patch plans.
No staging or update command is part of the asset builder. Matching a host
JPEG contract cannot prove acceptance by the camera decoder. After a separate
experimental update, visible startup activation, restarts, shooting and
playback still require on-camera observation. No startup speed, capture speed
or battery improvement is claimed.

The original `Wav/Startup1.wav` is 24,094 bytes: PCM, mono, 16 kHz, signed
16-bit, 12,018 frames (0.751125 seconds). It also has no whole-file exact
embedded match. The asset map records its format; audio playback timing and
consumer behaviour require separate investigation. The initial artwork patch
leaves sounds unchanged.
