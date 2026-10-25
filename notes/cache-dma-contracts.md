# Cache and DMA handoff contracts

Status: **partial static recovery; no camera-callable SDK adapter**. This narrows
the rules used by two existing image/copy paths. It does not establish ownership
of a live saved-photo buffer or a general executable publication protocol.

The reproducible record is [cache-dma-contracts.json](../evidence/cache-dma-contracts.json),
produced by [map_cache_dma_contracts.py](../tools/map_cache_dma_contracts.py).
The input firmware SHA-256 is
`2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b`;
the authenticated decoded analysis ELF SHA-256 is
`15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040`.
The builder authenticates those inputs, independently checks 33 selected MIPS
instructions with Capstone, and checks all 1,708 instruction records in 18
retained direct Ghidra dossiers against the authenticated ELF. These are direct
Ghidra findings, **not REA Evidence**. No target execution, hardware operation,
camera request or firmware patch occurs in this work.

## Cache functions

| Entry | Small-range CACHE operation | Reviewed input behavior |
| --- | --- | --- |
| `800b43bc` | `10`, I invalidate | Null address or zero length asserts. |
| `800b3a9c` | `11`, D invalidate | Null address or zero length asserts. |
| `800b52e4` | `15`, D writeback/invalidate | Null address **or** zero length selects whole-cache `800b5028`. |
| `800b4614` | `19`, D writeback | No matching null/zero guard in this reviewed entry. |

The address is normalized with `address & dfffffff`. The small-range path
rounds its start down to a runtime cache-line size, computes its end with
32-bit wrapping addition, then uses an unsigned comparison **before** the first
CACHE instruction. `800b5514` branches directly to that comparison. This matters
at boundaries: zero length at an aligned address gives no small-loop operations;
zero length at an unaligned address can still include the preceding line.
Entry guards listed above can prevent this arithmetic loop from being reached.
The model intentionally preserves this distinction and reports overflow,
bounded iteration and cycles instead of treating invalid ranges as safe.

Line geometry comes from EBase-selected runtime context state; it has not been
measured on the camera. `800b256c` selects a separate tag-scanning implementation
when unsigned length reaches the wrapped value of cache capacity times ten.
The small-range model does not model that tag-scanning implementation. Rounding
can affect neighboring bytes, so callers must own the whole affected cache line.
Applying a bit mask to an address does not prove that the address is valid RAM.

`800b22fc` and `800b2364` optionally measure elapsed ticks and publish counters.
They are not a lock around the operation. `800ce880` saves/replaces interrupt
mask bits from Status; calls surrounding tag reads and counter publication do
not prove scheduler exclusion, DMA exclusion or cross-core visibility. No
explicit `sync`, `ehb` or `synci` appears in these 18 selected dossiers. This is
a bounded observation, not a claim that the entire firmware lacks barriers.

## Existing DirectScaleYUVEx path

`802058f8` calls `8020561c`. The latter accepts two operation tags, `4501` and
`0602`, and asserts for other tags. The precise byte packing and colour domain
of the live buffers remain unresolved.

The source address is parameter 1 word 2. If its bit `20000000` is clear,
`8020561c` calls D writeback/invalidate on it with the low 32 bits of
`(word4 >> 1) * word1 * 2`. It then uses `source | 20000000` in the source
descriptor. Output dimensions are rounded down to even values, and the output
range is invalidated at `destination & dfffffff` for the low 32 bits of
`even_width * even_height * 2`. The output descriptor uses
`destination | 20000000`.

The path creates an object through `8018e1d0`, returns zero on creation failure,
otherwise invokes the existing run/wait wrapper `8018f6e4(path, 0)`, preserves
its result, destroys the path with `8018e344`, and returns that result. The
caller supplies both allocations; copying address tokens into descriptors does
not transfer their image bytes or establish their allocation extents. This is
an observed path-specific handoff, not permission for a custom callback to
access any capture buffer.

## Existing FastCopy path

`8005df30(destination, source, length, first_selector, last_selector)` first
invalidates a cached destination, then writes back/invalidates a cached source.
Both resulting address tokens use bit `20000000`. When source and destination
alignment offsets differ, the function falls back to its copy helper. On the
DMA route it copies alignment head/tail bytes with the CPU, acquires a selected
scratchpad mask through `8005d780`, constructs bounded batches of word-address
descriptor pairs, submits them through `8005dc78`, and releases ownership with
`8005d868` after submissions return. The final remainder uses a different
address mask from the full batches; this is not a universal DMA descriptor ABI.

`8005dc78` installs callback `8005db18` and waits through `800c1014` on event
object `808a7588`, mask `40000000`, with timeout argument `ffffffff`. The
callback advances descriptor state and sets that event when its descriptor
count is zero. The wait's return value is not checked; the helper returns one.
That is evidence of an intended synchronous completion sequence, not proof of
success, cancellation safety or safe access by another owner. Hardware-visible
ordering, overlapping buffers, length overflow and selector validity remain
unverified.

## Observed instruction-cache pair

`8005da00` acquires scratchpad ownership. One branch writes back/invalidates
`bfc08000` for `1800` bytes, then invalidates that instruction-cache range. The
other branch copies preserved scratchpad bytes and skips this pair. This
belongs to the `Os/Dma/FastCopy` initialization path. There is no established
module placement, hook, relocation or execute handoff here, so it cannot yet
serve as an SDK code-loader contract.

`80191b6c` supplies another narrow example: its `(flags & e) == 0` branch copies
through cached aliases and writes back/invalidates the destination; another
branch uses uncached descriptors and may invoke whole-cache maintenance. This
reinforces that cache treatment depends on the specific path.

## Remaining gate and reproduction

Executable trials remain blocked. Required facts still include live allocation
extent, full cache-line ownership, buffer packing/colour domain, active JPEG
producer ownership, callback completion/error handling, scheduler/DMA exclusion,
and a verified general code-publication sequence. Recovery remains an independent
required gate.

From the workspace root:

```powershell
python tools/map_cache_dma_contracts.py --output derived/cache-dma-recheck.json
python -m unittest discover -s tests -p test_cache_dma_contracts.py -v
```

Choose a fresh output path; the builder refuses to overwrite an existing report.
Ten focused tests cover alias restrictions, line rounding, pre-tested zero-length
behavior, 32-bit overflow, MIPS variable shift masking, bounded pathological
loops, cache preparation order, invalid inputs, source identity and stale native
bytes. They do not simulate cache hardware, DMA, peripherals or camera execution.
