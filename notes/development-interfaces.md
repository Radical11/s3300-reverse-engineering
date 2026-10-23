# Developer access, profiling and efficiency surfaces

24 October 2026. Offline static audit of the independently validated S3300
v1.1 application. No camera commands, marker files, target execution or firmware
changes were made. These findings advance a developer interface; they do not
establish a usable external transport or a faster camera.

## Actual command records, rather than loose strings

The monitor tables contain sixteen-byte little-endian records:

```
struct command_record {
    uint32_t name_pointer;
    uint32_t argument_help_pointer;
    uint32_t description_pointer;
    uint32_t handler_pointer;
};
```

Nine records were extracted with exact strings and reviewed handler code:

| Command | Record VA | Handler VA | Contract established statically |
| --- | --- | --- | --- |
| cachecostcheck | 0x8042b8dc | 0x8040120c | Cache-operation overhead control; changes test state |
| cpupct | 0x8042b8ec | 0x80400c64 | Synthetic counter stress test, potentially disables interrupts |
| cpupcs | 0x8042b8fc | 0x80400ea8 | Start counters; parses cache selector and interrupt flag |
| cpupcp | 0x8042b90c | 0x80400f90 | Stop counters and conditionally restore interrupt state |
| cpupce | 0x8042b91c | 0x80400fc4 | Reset counters |
| cpupcr | 0x8042b92c | 0x80400ff4 | Read six counter words and print them |
| cpu | 0x8042bba0 | 0x80403468 | Initialize CPU-load monitoring or print short/full statistics |
| ct | 0x8089830c | 0x80580468 | Print capture-timing array; default count 80, skips slots 20..29 |
| ctm | 0x8089851c | 0x805862ec | Start/stop capture timing and optionally execute a command string |

The record layout is corroborated by independent table instances and by each
reviewed handler agreeing with its record's description. The command handler
ABI appears to receive its argument string in `a0`; full monitor-parser and
registration reachability are separate work.

**These names are an inventory, not commands to try on the camera.** No working
console/USB invocation route has been established. In particular, `ct` has no
confirmed count clamp; arbitrary counts could read beyond its timing array.
The `ctm` path can execute a command string for values other than one, so it
must not be exposed as an unrestricted telemetry endpoint.

## CPU counters have a usable internal data contract

Start API **0x800b1fc4** accepts selector `a0` and interrupt flag `a1`. The
command handler bounds the selector to 0..3:

0 = MCPU data cache, 1 = MCPU instruction cache,
2 = SCPU data cache, 3 = SCPU instruction cache.

Flag exactly one takes an interrupt-disable path. Any future observation
interface should start with flag zero, preserving ordinary interrupt behavior.
Counter stop **0x800b2080** restores saved interrupt state when required;
reset **0x800b20b8** changes hardware counter state.

Read API **0x800b20d0** writes six little-endian u32 values to a caller-supplied
**24-byte** buffer. The formatter at **0x80400b28** independently supplies names:

| Buffer offset | Field | Register read in target code |
| --- | --- | --- |
| 0x00 | Hits | 0xb0801068 |
| 0x04 | Misses | 0xb080106c |
| 0x08 | Instructions | 0xb0801060 |
| 0x0c | Prefetch hits | 0xb0801078 |
| 0x10 | Prefetch misses | 0xb080107c |
| 0x14 | Clocks | 0xb0801064 |

These addresses are camera MMIO references, **not host-process addresses**.
No registers were read in this audit. This gives a concrete internal interface
for measuring candidate optimizations once a verified access path exists.

## A specific gamma optimization candidate and its ownership trap

Loader **0x8021c7a8** uses a raw-resource cache at **0x808c4eec**:

- Ten u32 size slots at `base + 4*id`.
- Ten raw-pointer slots at `base + 0x28 + 4*id`.
- Reset routine **0x8021c76c** clears all ten pairs.
- Both a cache hit at **0x8021c804** and a successful miss at **0x8021c8d0**
  call converter **0x8021bd3c**.

The converter allocates a **0x994-byte output** and **0x4000-byte scratch** area,
performs table-format conversion, frees scratch and returns a generated pointer
through the caller's pointer slot at **0x8021c3c0**. The raw cache retains the
original resource pointer. A successful cache hit therefore still incurs
conversion/allocation work: this is a concrete optimization target to profile.

It is not safe simply to retain and share the generated pointer. Downstream
channel extractor **0x8021c960** calls the loader, copies data from generated
result **+0x194**, then frees that generated result at **0x8021ca08**. Reusing
that pointer across consumers without a new ownership policy would introduce
invalid frees or use-after-free.

The next experiment should measure invocation count and converter cost during
mode changes and repeated captures. If that cost matters, introduce a separate
immutable converted cache with correct invalidation and caller-owned copies,
or explicitly update all consumers to reference-counted ownership. Compare
memory cost with saved time. No timing, energy saving or safe patch is claimed.

## USB accessibility: more of the path is now mapped

The source-bound vendor-control listener at **0x807958e0** has a diagnostic
identifying `PtpStandardVendor.c`. It allocates an eight-byte request buffer,
reads standard USB-style fields at offsets 0/1/2/4/6 and routes requests through
application hook **0x80749528**. The hook invokes application filter
**0x8057923c** only when a device-mode query returns **7**.

That filter accepts request code **0x41** and index **4**, then copies a bounded
length from global **0x806599a0**. Other requests/modes return nonzero to generic
handling or stall paths. This is an application-specific control request,
**not a proven GetMem request**.

The earlier GetMem implementation at **0x8079de34** remains present in a
separate handler table at **0x80899660**, adjacent to SetMem/monitor execution
at **0x80899658**. Transfer API **0x80796070** selects between:

- Selector zero: **0x800db0e4** and **0x80795ce0**.
- Selector one: **0x80796424**, using agent lookup **0x8078bdac** and lower USB
  transfer code. Related receive API **0x80795fe0** has matching selector paths.

This advances transport understanding but does not connect a safe external
request to the GetMem handler. Missing pieces are the generic dispatcher,
command numbers and argument sizes, active interface/endpoints and the mode
available in installed v1.0. A future tool should expose an explicit allowlist
of identity/version/status/profile reads with typed lengths; memory writes,
console execution, flash and marker activation remain separate capabilities.

## Reproduction and limits

Run `python tools/map_development_interfaces.py` on a fresh output path. The tool
checks the source SHA-256, validated analysis ELF identity and every mapped
region hash. It extracts records and sixteen complete bounded listings, then
writes `evidence/development-interfaces.json`. Existing outputs are protected
from overwrite. All window bytes decoded, and the source was unchanged.

Eight synthetic parser tests pass:
`python -m unittest discover -s tests -p test_development_interfaces.py -v`.
They cover the record contract and rejection of unmapped/truncated/overlapping
regions, unterminated/nonprintable strings and unaligned handlers.

This audit does not install an optimization, expose a working console, measure
real capture timings or prove recovery. The custom-firmware direction remains
viable research, with these concrete API and ownership findings reducing the
next implementation uncertainty.
