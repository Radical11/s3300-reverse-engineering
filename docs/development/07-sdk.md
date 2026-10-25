# Write and compile a module

Our C source can be compiled and tested before it is integrated into the
camera. Keep these three achievements separate: host algorithm correctness,
target object correctness and a verified on-camera caller. A compiler passing
does not supply the caller, safe placement or recovery.

## Start with a pure bounded function

The creative-look module implements `s3300_look_row(rgb, pixels, look)` on
caller-owned interleaved RGB8 rows or tiles. It performs no heap allocation,
floating point, OS call or full-frame copy. Original bypasses processing. The
four other treatments are Flash Pop, Amber Days, Cool Night and tone-only Mono
Grit; grain, glow and vignette are not implemented by those names.

The caller must provide at least three writable bytes per pixel. Invalid IDs,
null nonempty buffers and arithmetic overflow are rejected. No ordinary C
function can prove that an arbitrary pointer actually owns that much memory.

Use our reference implementations and guard-byte tests to validate new pure
algorithms. Prefer rows/tiles and bounded integer work. Give each function an
explicit memory domain and ownership contract. A pointer in a decompiler
listing is not enough to meet it.

## Target-build workflow

```powershell
python s3300.py sdk-build derived/my-sdk-build
```

If the dedicated compiler/emulator cache is not ready, use
`python tools/build_sdk.py --check` to inspect it and
`python tools/build_sdk.py --install-toolchain` for the pinned installation.
The direct build tool also accepts `--inspect PATH` to inspect an existing
compiled SDK ELF independently of a new build.

The initial checked build uses pinned Zig 0.13's Clang/LLD and a scoped Unicorn
2.1.4 instruction emulator. It compiles the real five-look source plus pure
contract helpers. Two builds must match byte-for-byte; bounded MIPS emulation
checks pixel results, guards, Original bypass, stack restoration and preserved
registers. The pure helpers decode CPU-counter bytes and classify recovered
numeric command values; they do not call device functions. The settings-store
checksum helper covers offsets 0 through `0x19d`, excluding byte `0x19e` and
the checksum at `0x19f`.

The synthetic link address `0x10000` is chosen for offline validation. It is
not a recovered camera code-placement region. Read the
[SDK reference](../../firmware/sdk/README.md) and
[validation evidence](../../evidence/sdk-validation.json) for actual section
sizes, tool hashes, emulation coverage and remaining gates.

Inspect the build manifest, compiler/target settings, hashes, exported symbols,
sections and relocation report. Rebuild into a second new directory and compare
the declared reproducible artifacts. The build must reject unresolved imports
or unsupported target assumptions rather than silently linking a host library.
Use `sdk-build --help` and `firmware/sdk` for the actual current module API and
toolchain contract.

The primary application headers identify little-endian ELF32 MIPS32r2 with o32
flags. They lack an ABI-flags record, so floating-point conventions must not
be invented. The initial SDK is freestanding and integer-only. Each separate
original executable retains its own declared architecture; do not force the
small loader into the primary application's profile.

## Integration gates before an executable trial

| Gate | Evidence required |
| --- | --- |
| Entry/return ABI | Register roles, stack alignment, callee-saved state and delay-slot behavior |
| Placement | Owned region, alignment, size, mapping, initialization and no overlap with live data |
| Buffer access | Pointer, shape, stride, colour domain, lifetime, cache/DMA state and synchronization |
| Execution context | Thread/interrupt rules, blocking behavior, allocator rules and real-time budget |
| Hook mechanism | Exact overwritten bytes, relocation/trampoline proof and correct return path |
| Controls and persistence | Mode ownership, Original bypass, cancellation and existing settings lifecycle |
| Recovery | Verified software entry and restored coverage when normal application startup is broken |

Known empty-looking bytes are not automatically unused executable space. An
ELF's executable permission flag is not proof that every byte in that region is
a safe code cave. MIPS instructions can use absolute targets, gp-relative data,
branch delay slots and position-sensitive values; a raw byte copy is not a
relocator.

The existing RAW-to-YUV wrapper at `0x80205918` copies seven u32 descriptor
fields. Width, height, planes, pointer ownership and asynchronous completion
remain separate research contracts. The host RGB8 module must not be inserted
there merely because the diagnostic mentions RAW and YUV.

## Prefer an existing accelerator when it fits

The colour matrix/offset path already supplies a compact way to influence
existing effects. Gamma formats are different: the 960-byte GammaLut resource
contains packed base/slope sections, and GammaDDE is associated with a display
path. None is interchangeable with three ordinary 256-byte RGB curves.

Expose only verified interfaces in the SDK. Keep unknown device calls as
research records rather than convenient public wrappers. Build/host work can
continue while integration gates are unresolved; code-ready must remain false
until the entire demonstrated path passes them.

## Use the dependency ledger

`python s3300.py readiness --json` includes `feature_dependencies`: the reviewed
Amber resource experiment, standalone SDK compilation, a selectable saved-photo
module, and a measured optimization. Each lists its required gates and current
blockers. The source ledger is
[dependencies.json](../../firmware/sdk/dependencies.json). It declares
dependencies; authenticated evidence and explicitly held recovery gates determine
their status. Editing a dependency list does not change `code_ready` or permit
an executable trial.

The [saved-JPEG map](../../notes/saved-jpeg-path.md) now follows FileCompressor
event `1042` through StillImage, JPEG start/wait/destruction, EXIF construction
and queued file writes. The capture descriptor belongs to its mode-dependent
capture object. JPEG selectors 0 and 1 compute different input addresses; neither
is established as the RGB8 domain expected by our look module.

Saving is also asynchronous. ApsSave list nodes retain pointers rather than
copying data. Writer flag `4` can free both the encoded data and node after a
successful write. Do not retain or lend an arbitrary buffer across that handoff.
The [cache/DMA map](../../notes/cache-dma-contracts.md) records existing cache
preparation and completion waits, while leaving live cache-line ownership and
general executable publication unresolved.

The later [pixel-layout investigation](../../notes/pixel-layout.md) separates
ApsJpeg's argument `+4` (JPEG input kind) from argument `+8` (address layout).
Both reviewed StillImage call sites pass input-kind zero. The DMA helper uses
parent width, a kind-dependent byte multiplier and explicit word rounding;
component order and numeric range remain unresolved. Do not feed those buffers
to the RGB8 module solely because their allocation is twice the frame area.

The [shutter input](../../notes/shutter-input.md) and
[capture routing](../../notes/shutter-route.md) maps connect scanner, debounce,
logical key events, UI/capture state and still-image queues. Full press can enter
a focus state before capture, and enabled edge masks depend on mode. A static
event number is not an unconditional capture or cancel command. Live scanner
state and selected buffer ownership remain required observations.

The [menu lifecycle](../../notes/menu-lifecycle.md) recovers the existing
five-entry Color Options object, its callbacks and the single global dynamic
entry-list allocation. Entry navigation, preview, choice commit, parent return
and exit are distinct. A cancel-like parent return can still stage and persist
other settings, and the UI does not propagate the settings writer's status.
New controls must preserve these lifecycle/error contracts; extending a label
table alone does not register an executable feature.
