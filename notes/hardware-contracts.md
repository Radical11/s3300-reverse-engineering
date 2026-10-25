# Hardware contracts: authenticated S3300 v1.1 static map

This pass finds reusable hardware entry points and records what remains unknown.
It does **not** establish the complete hardware specification, recover original
C source, or prove that every bundled driver is active on this camera.

The machine-readable ledger is [hardware-contracts.json](../evidence/hardware-contracts.json).
The reproducible mapper is [map_hardware_contracts.py](../tools/map_hardware_contracts.py).
These are independent Python/Capstone findings produced alongside the REA
investigation; they are **not native REA Evidence records**. No camera,
transport, register, target process, or firmware-update action was accessed.

## Identity and coverage

- Original supplied v1.1 firmware SHA-256:
  `2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b`.
- Analysis-only ELF SHA-256:
  `15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040`.
- The mapper reparses and authenticates ELF segment metadata, segment hashes and
  5,798 compiler-unwind ranges before analyzing bytes. The original vendor
  firmware must match its separate hash.
- Inventory: 504 hardware-related string spans, 504 short instruction-syntax
  reference candidates, and 29 hardware command-record candidates.
- High-address access scan: 2,267,704 bytes inside all 5,798 unwind ranges;
  381 short load/store address candidates grouped into 14 distinct 4 KiB banks.
- Fourteen selected hardware/allocator/RTOS windows have bounded Capstone
  listings and byte hashes under `derived/hardware-contracts/`.

The string scan includes mixed code/data, so references are candidates. The
high-address scan deliberately forgets constants across branches, calls, delay
slots, unknown instructions and a twelve-instruction age bound. It misses
indexed, indirect, longer-lived and cross-block addresses. Most low-level OS
code lacks these unwind ranges; reviewed OS windows supply separate evidence.

## Concrete memory and clock findings

The `dramsize` record at `0x8042831c` points to handler `0x803e7238`.
That handler calls `0x8003c3ac`, supplying a pointer for a byte-size result.
The API reads **register `0xb8002010`**, uses its value as an unsigned selector
into the checked seven-entry table at `0x80045cb0`, and implements these cases:

| Selector | Branch target | Software-reported size |
| --- | --- | --- |
| 0 | `0x8003c3e0` | Failure / no size |
| 1 | `0x8003c420` | 8 MiB |
| 2 | `0x8003c43c` | 16 MiB |
| 3 | `0x8003c46c` | 32 MiB |
| 4 | `0x8003c44c` | 64 MiB |
| 5 | `0x8003c45c` | 128 MiB |
| 6 | `0x8003c3e8` | 256 MiB |
| >= 7 | `0x8003c3e0` | Failure / no size |

On cases 1..6 the API returns one and writes the size if `a1` is non-null.
The handler shifts bytes right 20 and prints that MiB value; it also multiplies
that result by eight for Mbit. Optional API outputs include address bases
`0x80000000` and `0xa0000000`. These output addresses are not capacity evidence.

**Installed RAM is still unknown:** no selector value was read. This is a
supported configuration table, not a measurement of this camera. The allocator
initializer at `0x80020804` independently calls this API at `0x80020844`, derives
a pool extent using its returned size and the supplied start address, and
reports `Unknown main DRAM size` on failure. This corroborates the size API's
role without revealing current heap headroom.

Clock getter `0x80025198` accepts an unsigned index below `0x38` and returns a
u32 from **`0x808a5b8c + index*4`**; larger indices return zero. These 56 table
entries are outside the file-backed analysis image. Handler `cguop` at
`0x80405828` has a getter path calling this API and a setter path reporting
requested, reachable and achieved frequency. `cgucfgen` at `0x80405b00` parses
clock ID/frequency/mode and reaches configuration API candidate `0x80025ec8`.
Diagnostics identify frequency units as Hz. Actual operating frequencies,
clock-ID names, table initialization and safe change sequences remain unknown.

## GPIO, allocator, RTOS and DMA contracts

| Subsystem | Recovered anchor / contract | Remaining gap |
| --- | --- | --- |
| GPIO table | `0x800a2264`, stride `0x54`; observed groups 0..10; u32 at record+8 gives register base | Board wiring, mux state and pad identities |
| GPIO pin write | `0x800a16f8`: a0=group, a1=pin, a2=value; writes u32 at `base+0x0c+4*pin`, returns one | No bounds check in this leaf; electrical meaning and allowed values unknown |
| GPIO pin read | `0x800a1728`: a0=group, a1=pin; returns u32 at the same address expression | State/ownership/synchronization outside this leaf |
| GPIO configuration | `0x800a1468` updates enable/configuration state; `0x800a1580` updates direction state and writes cached mask to base+4 | Full pad restrictions and effects require further tracing |
| Allocator dispatch | `0x80020980`; nonzero pool path reads pool+8 and calls its first function pointer, forwarding size and metadata/flags | Default pool, complete allocation/free ABI, failure handling and ownership |
| RTOS semaphore candidate | `0x800c3b18`; object in a0, wait/control in a1; immediate path decrements object+8; diagnostics reference `_tx_semaphore_get` | Complete return statuses, tick units and blocking semantics |
| DMA submission candidate | `0x8005d208`; fills a transaction at context+0x10, calls `0x8005d02c`, optionally calls `0x8005d140` | Field units, buffer domains/lifetime, channel ownership, waits and cache maintenance |

GPIO table register-base pointers for groups 0..10 are respectively:
`0xb0020004`, `0xb0020404`, `0xb0020804`, `0xb0020c04`, `0xb0021004`,
`0xb0021404`, `0xb0021804`, `0xb0021c04`, `0xb0022404`, `0xb0022c04`,
`0xb0023004`. Two 32-byte maps per record are preserved raw in the JSON.
The observed group table does not identify shutter, flash, lens or other board
connections.

Both monitor `gpioset` and monitor `gpioget` call configuration and direction
routines before accessing a pin. **The monitor getter changes state.** A nearby
diagnostic explicitly says the GPIO state is not restored. The mapped commands
are inventory entries, not an interface to invoke blindly.

The DMA window gives a useful structural anchor: it stores incoming a2, a1,
a3, argument5 and argument6 at context+0x18, +0x1c, +0x20, +0x24 and +0x28;
it clears byte+0x2c and copies context byte0 to+0x2d. Argument7 controls the
additional call. Those offsets do not establish whether a field is a source
pointer, destination pointer, byte count, stride or callback.

RTOS diagnostics cover mutex, semaphore, queue and event-flag operations.
Selected RTOS/allocator windows read CP0 register15 select1, mask with `0x3ff`
and compare with one for context selection. This is a software context lead,
not an exact CPU ID or proof of active core count. `ThreadX`, `FileX`, `Zoran`,
`MCPU`, `SCPU`, `ConfigSensorC13.c` and C10/C13 driver paths remain software-family
evidence; the fitted SoC and sensor are unidentified.

## High-address banks and completion boundary

| 4 KiB bank | Access candidates in unwind ranges |
| --- | ---: |
| `0xb0005000` | 10 |
| `0xb0006000` | 3 |
| `0xb0020000` | 142 |
| `0xb0021000` | 43 |
| `0xb0022000` | 124 |
| `0xb0023000` | 2 |
| `0xb0103000` | 38 |
| `0xb0802000` | 1 |
| `0xb1000000` | 2 |
| `0xb1001000` | 1 |
| `0xb2000000` | 4 |
| `0xb2001000` | 2 |
| `0xba000000` | 4 |
| `0xbc000000` | 5 |

GPIO-table pointers corroborate GPIO-related registers in `0xb002xxxx`.
Other bank identities are deliberately unlabeled: high addresses can refer to
MMIO, ROM or other mapped memory. Bank grouping alone does not assign semantics.
Previously reviewed CPU-counter registers at `0xb0801060` and nearby addresses
remain in [development-interfaces.json](../evidence/development-interfaces.json);
their absence from this unwind-only bank list is a coverage limit.

Supported DRAM selector values and selected GPIO leaf behavior are answered
statically. Exact installed RAM, clock state, chip identity, sensor-register
contracts, cache/DMA coherency, board wiring, free heap, interrupt priorities and
complete register semantics remain unresolved. No claim of complete hardware
mapping is made.

Reproduce into **new** paths, preserving the checked-in evidence:

```powershell
python tools/map_hardware_contracts.py --output work/hardware-contracts-recheck.json --listings work/hardware-contracts-recheck
python -m unittest discover -s tests -p test_hardware_contracts.py -v
```

The mapper refuses existing output/listing paths. Thirteen focused tests cover
signed offsets, register clobbers, control-transfer/delay-slot boundaries,
unknown instructions, constant age, zero-register handling, source-hash
enforcement, checked selector-table rejection and output preservation.
