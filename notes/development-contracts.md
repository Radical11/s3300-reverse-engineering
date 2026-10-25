# Development contracts: settings integrity and image-command application

This pass deepens the source-bound static map. Its machine-readable report is
[`evidence/development-contracts.json`](../evidence/development-contracts.json).
It uses authenticated original v1.1 carrier bytes and the independently decoded
analysis ELF, checks 26 exact instructions and three dispatch tables, and exports
11 bounded analyst windows. It does not run a camera command, patch firmware or
establish recovery. This is independent Python/Capstone evidence, not native REA
or Ghidra Evidence.

## Settings checksum: the previous length ambiguity is resolved

Helper **0x80008f80** has an unusual boundary convention. For **N >= 1**, its
calculation returns:

```
sum(source[0:N-1]) modulo 65536
```

The slice excludes its end: source offsets **0 through N-2** are summed.
The zero mode ignores the destination argument. Nonzero **low eight bits** of
the mode additionally copy **N+1 bytes**, source offsets **0 through N inclusive**,
while returning the same sum. Mode 0x100 therefore calculates only; 0x101 copies.
This is not an ordinary checksum over N bytes or ordinary memcpy length.

The read-only path decrements N at **0x80009008**, then decrements its source
pointer before each load at **0x80009018**. The backedge compares the address to
the source base and masks the running sum to 16 bits in its delay slot. The
copy path starts by copying source[N] and source[N-1] without summing them,
then accumulates the earlier bytes.

Writer **0x80009644** supplies N=**0x19f** at **0x80009714** and stores the
returned low byte at **store+0x19f** at **0x80009724**. The serialized store is
**0x1a0 bytes**. Its exact checksum formula is consequently:

```
stored_byte_at_0x19f == sum(store[0:0x19e]) modulo 256
```

The covered range is **414 bytes, offsets 0..0x19d inclusive**. Byte **+0x19e**
is outside this sum; its purpose is not resolved. The checksum byte itself is
also excluded. This is separate from the firmware-file additive checksum.

A second, deliberately small integer-instruction interpreter runs the exact
checked routine over **120 synthetic cases**, modeling ordinary branch delay
slots and branch-likely nullification. It agrees with the independent slice/sum
and copy models across boundary lengths, zero/255/random input, and mode values.
It rejects unknown opcodes, out-of-range synthetic memory and nontermination.
This is a bounded model of a pure helper, not hardware or whole-camera emulation.

The host model rejects N<=0 rather than reproducing the target's unsigned
underflow. Null pointers, overlaps and aliases are not a supported public copy
API. Knowing the checksum does not make writing arbitrary settings safe.

## Settings transaction reaches lower-level media operations

The prior selectors **2 → 1 → 0** are now traced through three checked jump
tables and the device-one backend:

| Application selector | Intermediate backend selector | Route |
| --- | --- | --- |
| 2 | 8 | 0x800e408c → 0x800e2d4c → 0x800e2800 → 0x80063aec |
| 1 | 5 | Same chain, write-like buffer direction |
| 0 | 4 | Same chain, read-like buffer direction |

Operation 2 converts the position from global **0x80003258** by dividing it by
**1 << u16(handle+0x11c4)** before passing backend operation 8. It is an
erase-like operation, rather than a proven byte-addressed write. The write/read
calls supply count **2**, using the **0x400-byte buffer** containing the
0x1a0-byte store and zero-filled remainder.

The allocation size and count do not by themselves establish erase-block size,
the live device geometry, physical address, calibration boundaries or power-loss
atomicity. Erase/write/read names remain inferences from the full sequence,
position conversion, buffer directions and post-read checksum check. There is
still no safe general-purpose settings writer exposed by the SDK.

## Image matrix dirty-state consumer is located

The previous map established that command 15 sets dirty bit **0x00100000**.
The consumer is **0x801fbc8c**, which receives a driver pointer in a0, a pointer
to a two-word dirty mask in a1 and a numeric context index as stack argument 6.
At **0x801fc15c..0x801fc16c** it tests that bit and branches to a call of
**0x801fbb3c**, passing cache subindex **15** at **0x801fc5f4**.

The cache address is:

```
0x808c1d88 + 4*(74*context_index + 37*bank + subindex)
```

Contexts **2 and 5** have a context-zero fallback if their selected cache
pointer is null. Selected retained commands reach **0x80192e04**. The caller
at **0x802a8a50**, call site **0x802a8aa4**, passes the global dirty-mask
pointer **0x808c1d78** and numeric context **5**. This is a concrete link from
the global dirty flag into driver command handling. It still does not assign
context 5 the semantic name “ordinary saved still.” The mask's reviewed clear
sites are **0x801fc484/0x801fc488**.

## A further driver-owned command copy precedes hardware application

Receiver **0x80192e04** branches on driver word **+4**:

- Driver type **0** calls **0x8019e724**, which loads driver field **+0x880**
  and tailcalls **0x802e57a8**.
- Driver type **5** stores/reuses command payloads in driver-owned slots. It
  does not establish immediate hardware upload.

Stage **0x802e57a8** requires command ID <37 and uses 12-byte slots at
**driver+0x48+12*command_id**. It allocates/reuses a full command-length copy,
marks slot byte **+9** as **3**, sets driver **+0x324 bit 1**, and writes **4**
to driver **+0x320**. The scheduler and final matrix MMIO consumer are still
unresolved. Call-chain depth alone is not evidence that a new matrix reaches a
saved photograph.

## Executable-modification readiness

The report retains the actual headers for all six original ELF artifacts,
including the missing `.MIPS.abiflags` sections and the tiny loader's separate
flags/entry. No header is changed to satisfy a decompiler profile. Integer-only
compilation can be verified separately, but it does not establish a complete
target ABI for arbitrary existing code or floating-point calls.

No safe executable placement area, hook, capture-buffer lifetime or unbootable
software recovery has been established. Zero-filled gaps are not designated
code caves. Successful resource updates and a normal running-menu rollback
are not evidence of recovery when the application cannot boot. The report's
`development_gates.code_trial_allowed` therefore remains **false**.

## Reproduce

Choose new paths so the retained evidence is preserved:

```powershell
python tools/map_development_contracts.py --output derived/contracts-recheck.json --listings derived/contracts-recheck
python -m unittest discover -s tests -p test_development_contracts.py -v
```

The tool exposes pure host helpers `settings_sum`, `settings_store_checksum`
and a bounded checksum instruction model for testing. They do not read devices
or write a settings image. The JSON keeps each contract's arguments, returns,
side effects, exact sites, inference limits and unresolved dependencies.
