# Startup branding and customization map

24 October 2026. Source-bound offline inspection. No camera setting, resource,
firmware or executable instruction has been changed.

The startup art is a small, replaceable-looking presentation asset, not evidence
of firmware bloat. The extracted JPEG is **24,210 bytes**, baseline JPEG with
**640 x 480**, 8-bit, three-component frame metadata. The startup sound is
**24,094 bytes**, mono 16-bit PCM at 16 kHz, **0.751125 seconds** long. A custom
look can replace their presentation without assuming deletion saves meaningful
startup time, RAM or energy.

`tools/map_branding.py` validates the original carrier SHA-256, the analysis
ELF hash and source-bound regions, and the existing extractor's resource
hashes. It exports metadata, 30 selected branding/startup strings and their
static references in `evidence/branding-map.json`, plus 13 bounded MIPS windows
and one raw metadata window
under ignored `derived/branding-analysis/`. Vendor image/audio/string bytes are
kept in ignored local directories.

## Actual presentation paths

The literal `A:\\JPG\\Startup1.jpg` at **0x803878f4** is passed to
**0x802219e0** at **0x8074171c**, **0x80741888** and **0x807419b0**.
That wrapper normalizes integer arguments and calls **0x80233cb0**. This
establishes a consumer connection beyond matching a filename; complete image
decoder contracts and display-buffer lifetime still need tracing.

The analyst-labelled preview candidate at **0x807415c8** returns immediately
when low8(a0) is zero. Otherwise it handles a1=1 and a1=2:

- **1** selects the startup JPEG.
- **2** uses `B:\\IMG00000.jpg`, copied from **0x803878e4**.
- **0** and other values return before either image-display path.

Two callers at **0x806a9a84** and **0x806a9cbc** supply a0=1 and a1 from a UI
state byte at base+0x278. This is evidence for existing conditional preview
behaviour; the initialization and complete relation of that byte to the power-on
selection remain unresolved.

The analyst-labelled presentation candidate at **0x807417d0** preserves the
low byte of a0 and returns at **0x80741800..0x80741820** when it is zero. The
enabled path can wait for a display mode transition before submitting startup
art. The aligned word at **0x807ed9f8** belongs to inferred **exception-unwind
metadata**, not a dispatch table. Its preceding record at **0x807ed9f0** gives
start **0x807417d0**, range **0x210**, and a backward CIE reference to
**0x807ed9c0**. The preceding FDE at **0x807ed9d0** gives preview entry
**0x807415c8**, range **0x208**, and the same CIE. The CIE begins with a
0x0c-byte record length, zero CIE ID, version 1, empty augmentation and MIPS
return register 31. Thus these are stronger function-boundary evidence than
the earlier prologue heuristics, but they do not identify callers or runtime
dispatch. The power-on caller contract remains unresolved.

These are candidate policy points for a later custom welcome implementation,
not patch instructions. Blindly removing a display wait risks presenting into
an unready display and does not constitute an evidenced startup optimization.

## Menu and stock customization evidence

English string-table records contain **Welcome screen**, **None**, **Nikon**,
**Select an image**, **Quick startup** and **Sound settings**. Their ordinal
positions are recorded for reproducibility and are **not claimed as runtime
string IDs**.

`SetupCreatorWelcome` diagnostic at **0x80675618** is referenced by the menu
creator candidate **0x8061c0cc**. Its event candidate **0x8061c18c** handles
events 0x106/0x108 and stores the selected value into byte **+0x19** of the
object pointed to by **0x80891ebc** at **0x8061c1d0**. The readback path at
**0x8061f784..0x8061f79c** reads that same byte back into a selection global.

The follow-up call **0x806fbfa8** updates generic menu selection flags. It
must not be described as a settings persistence writer merely because it
follows a store. No settings serialization, transaction, flash wear behaviour
or safe standalone persistent-setting API is established here.

This code plus the strings supports a real welcome selection UI. To claim
that choosing **None** skips the *power-on* artwork, finish tracing the menu's
runtime value mapping and startup dispatcher argument. The preview path's
zero-value skip is proven statically; the complete user-choice-to-power-on
mapping is still a gate. No camera settings were changed.

The separate `bQuickStartUp` diagnostic at **0x80380a5c** only appears in a
state-dump candidate at **0x806f9c78**. Its presence does not establish a safe
fast-boot flag or an accessible user feature.

## Sound and presentation timing

At **0x8074050c**, `A:\\Wav\\Startup1.wav` from **0x803876fc** is passed to
**0x8020926c** with a1=0. The return value is stored at **0x809f0024**.
The playback candidate **0x80740e50** checks an enable argument and UI/audio
state gates, then passes a stored sound handle to **0x802092b4** and sets an
active-state byte. This is a source-bound load-to-play investigation route.

The sound-option dispatcher **0x807414d8** includes that playback path as one
of seven cases. Some sound routines are shared with capture/button feedback;
removing all Wav resources would affect more than the startup chime.

The menu creator calls scheduler helper **0x800c167c** with 200, and selected
image flows also use 500. These are arguments observed in menu paths, not
measured boot delays, proven milliseconds, or safe removal candidates.

## Custom firmware direction supported by these findings

1. Keep the existing hardware startup sequence. Make the welcome presentation
   optional after its existing setting-to-dispatch mapping is validated.
2. Offer original custom art and an optional short custom chime. Validate new
   JPEG/audio formats and resource boundaries offline; do not overwrite the
   source or assume FAT allocation permits arbitrary replacement sizes.
3. Preserve a zero-presentation mode for users who prefer immediate shooting.
   Measure stock None, stock Nikon and custom-art startup-to-ready separately
   before attributing speed improvements to this change.
4. Replace user-facing names/artwork selectively. Keep compatibility-facing
   Nikon camera model, USB/PTP identifiers, EXIF maker data, update acceptance
   fields and filesystem naming until their consumers and dependencies are
   understood. They serve functions beyond screen branding.

A fully custom visual identity is a feasible target for further integration,
but these results supply neither a flashable modification nor recovery proof.
Actual speed/battery improvements remain unmeasured.
