# Experimental S3300 SDK

This is source code that can actually be cross-compiled and executed under a
host MIPS emulator. It is **not integrated into the camera**. The generated
ELF uses address `0x10000` only for verification; that address is not a recovered
free region in the camera. It is never registered as an update/trial payload.

## Build and inspect

From the repository root:

```powershell
python tools/build_sdk.py --install-toolchain
python tools/build_sdk.py --check
python tools/build_sdk.py derived/my-sdk-build
python tools/build_sdk.py --inspect derived/my-sdk-build/sdk-analysis-only.elf
python -m unittest discover -s tests -p test_sdk.py -v
```

The first command installs pinned Zig 0.13.0 (Clang/LLD) and Unicorn 2.1.4 in
the user's `.cache/s3300-native-analysis/toolchain` directory. Downloads have
fixed PyPI wheel URLs and SHA-256 hashes. The installer verifies extracted
members and refuses a modified/partial cache. It does not change global PATH,
Java, Python packages, compiler registration, the camera or a card. Windows
and Linux x86-64 wheel identities are pinned; the local hardware run currently
covers Windows only. Packages retain their own licenses: Zig's distribution
includes its third-party notices, while Unicorn is GPLv2. Nothing here applies
the repository's MIT license to those packages.

The build compiles `firmware/looks/looks.c` and `contracts.c` into ELF32
little-endian MIPS32r2/o32 objects. It uses integer-only soft-float code, no libc,
heap, floating-point operations, stack protector or dynamic loader. The
generated soft-float ABI declaration is a build choice, **not** recovery of the
vendor floating-point ABI: the original firmware has no `.MIPS.abiflags` record.
The vendor application header separately declares MIPS32r2/o32 at carrier
offset `0x1026c0`, flags `0x70001001`; the builder checks its source hash when
the original is available. No vendor header is changed to select an analysis
engine.

Two builds in different directories must produce byte-identical objects and
linked ELF. Independent pyelftools/Capstone inspection checks ISA/ABI fields,
symbols, undefined imports, remaining linked relocations, every executable
instruction, absence of coprocessor/FP operations and absence of runtime `$gp`
use. LLD may emit a reserved GOT and CPIC declaration; the inspected code does
not read `$gp` or depend on a camera global pointer. Object-file relocations
are expected and retained; all are resolved in the analysis-only link.

Output includes the module, full linear assembly listing, both builds and a
manifest binding inputs, compiler commands, tool identity and validation.

## Available pure helpers

| Function | Verified scope | Source contract |
| --- | --- | --- |
| `s3300_look_row` | Existing Original plus four RGB8 transformations, caller-owned row | `firmware/looks/README.md`; no confirmed camera RGB8 adapter |
| `s3300_counter_decode` | Six copied little-endian u32 values from a 24-byte buffer | `notes/development-interfaces.md`; internal counter reader `0x800b20d0` |
| `s3300_command_context_index` | Numeric lookup 0x40/0x50/0xa0/0xb0 → 0/1/2/5, otherwise 8 | `notes/capture-contracts.md`; `0x8023c778` |
| `s3300_command_id_parts` | Unsigned command category/subindex arithmetic | `tools/map_capture_contracts.py`; `0x801fe7f4/0x801fe82c` |
| `s3300_settings_checksum` | Sum store bytes 0..0x19d modulo 256; exclude byte 0x19e and trailer 0x19f | `evidence/development-contracts.json`; helper `0x80008f80` called with N=0x19f |

These helpers operate only on caller-owned local memory and integers. They do
not expose raw register access, vendor-function pointers, command submission,
an allocator, settings writes, USB GetMem or frame-buffer entrypoints. Header
comments state buffer sizes, pointer requirements and rejected inputs. They
do not turn an internal constant or address into a supported public camera API.

## What the host emulator verifies

Unicorn loads only our linked module into synthetic memory. It runs all five
looks against the independent Python RGB8 reference across empty rows, ramps
and deterministic random data. It checks Original bypass, row guards, rejected
NULL/overflow/invalid-look arguments, command arithmetic boundaries, counter
field order and the exact settings-checksum boundary. Each call must return
within an instruction/time budget, preserve the stack and callee-saved
registers, and write only declared outputs or stack memory.

The emulator does not contain Nikon firmware, MMIO, interrupts, cache or DMA
models. Passing these checks establishes the bounded host experiment, not
camera execution, image quality, performance, battery gain or recoverability.

Executable camera trials remain blocked until placement/hooks, cache handling,
the complete saved-photo buffer ABI and software recovery are verified. The
manifest always records those gates as false; changing an environment variable
or building successfully cannot authorize or stage this module.
