# Command15 matrix application follow-up

24 October 2026. This extends `development-contracts.md` and supersedes its
remaining **static final-matrix application** unknown. It does not resolve the
saved-photo buffer ABI or software recovery. `evidence/matrix-application.json`
binds these findings to original v1.1 source and analysis ELF hashes.

## The positive bridge

The external 0x34-byte command built at **0x806af434** has command ID15 and
subtype15. The prior map proves payload retention, dirty bit0x00100000,
context selection, driver reception and copying to a staged command slot.
The retained command has a 0x14-byte header and length0x30; its payload begins
four bytes earlier than the external command payload. These formats must not
be interchanged.

For the type0 driver path, **0x802e57a8** stages a copy at
`driver+0x48+12*command_id` and sets driver+0x324 bit1. **0x802e8a28** tests that
bit and calls **0x802e69bc** at **0x802e8e58**. The latter walks30 filter groups,
using a bitmap to distinguish shared and per-output passes. Its dispatcher is
the virtual method **0x802d508c**, from vtable **0x802fdd80**.

The dispatch table entry for **group11** points to **0x802d524c**. That block
selects **command slot15** and calls virtual method **0x802d4304**. Its stack
argument5 is group/factory ID11; argument6 is command slot15. The method indexes
the retained command by argument6, and passes argument5 through factory
**0x802f21cc** to **0x802f5ac0**. Factory11 constructs **0x802d2ac8**, whose
vtable is **0x802fdcb8**. The virtual decode method at offset0x24 is
**0x802d5d74**.

This distinction matters: factory15 instead constructs a different filter at
**0x802deb44**, uses base **0xb6000484**, and accepts command32. Numeric group,
factory and command identifiers cannot be treated as interchangeable.

## Decoding and register writes

**0x802d5d74(a0=filter,a1=retained_command)** accepts command15 subtypes0,6,12,13
and15. A supported decode marks object+0x30 dirty and updates its generation
through **0x802df29c**. Success returns0, an unsupported subtype returns6 and an
unsupported command returns7. The alternate command0xab has separate subtype
dispatch and is not exposed as a developer API here.

Subtype15 decoder **0x802d5ccc** makes these copies:

| Retained command | Filter object | Interpretation |
| --- | --- | --- |
| +0x14 through +0x24, nine halfwords | +0x34 through +0x44 | Nine matrix coefficients |
| +0x26 and +0x28 | +0x46 and +0x48 | Two offset fields |
| +0x2c, one word | +0x4c | Auxiliary field, full hardware meaning unresolved |

The two bytes at retained+0x2a/+0x2b are not consumed by this subtype decoder.
Subtype6 has different scaling: coefficients shift left2, offsets become
`offset*8+0x800`, and the auxiliary word becomes0. These transformations must
not be applied to subtype15.

When object+0x30 is nonzero, direct upload **0x802d2c88** writes eleven signed
halfwords, sign-extended to32 bits, to **0xb60000c0 through 0xb60000e8**. The
auxiliary word goes unchanged to **0xb60000fc**. The code writes the fourth
coefficient before the third, but both retain their corresponding addresses.
Alternative method **0x802d2e00** appends the same address/value pairs to a
register-write list. This establishes both direct and queued representations,
not the full asynchronous submission/completion contract.

Constructor **0x802d2ac8** assigns bypass register **0xb60000ec** and values1/0.
Generic method **0x802df300** selects value1 when object+0x28 is zero and value0
otherwise. The public meaning of that bit and safe update timing are not
assumed from the register address.

## Evidence and reproducibility

`tools/map_matrix_application.py` checks13 exact instructions and three table
records against the authenticated image, produces ten local bounded listings,
and compares every imported instruction byte in13 direct-Ghidra dossiers with
that image. The dossiers independently corroborate the earlier settings sum,
settings writer, dirty consumer, cache selection and driver staging, as well
as the new matrix constructor, decoder, scheduler and upload implementations.

Ghidra's inferred signatures are not authoritative calling conventions. Its
initial inventory does not contain the three indirect-dispatch starts
0x802d508c,0x802d4304,0x802f21cc; their listings remain explicitly bounded analyst
windows. The dispatcher arguments were recovered from their actual stack loads
and callsites. Direct Ghidra evidence is labelled separately from REA Evidence.

```powershell
python -m unittest discover -s tests -p test_matrix_application.py
python tools/map_matrix_application.py --output derived/matrix-check.json --listings derived/matrix-check-listings
```

Existing evidence/listing destinations are refused. Native metadata must match
the analysis ELF hash and MIPS little-endian architecture; differing imported
instruction bytes or incomplete decompilation fail the run. Native listings
contain vendor code and remain local under `derived/`.

The pure host helper `subtype15_register_values` demonstrates the recovered
layout and signed extension. It never touches MMIO, a camera, firmware files or
settings. Its tests cover signed boundaries, separate offsets/auxiliary word,
ignored alignment bytes and rejection of the external command format.

## Remaining gates

The static chain now reaches actual register values. The identity of the active
numeric context on an ordinary saved still, buffer colour domain/ownership,
cache/DMA rules and asynchronous list completion remain separate contracts.
Runtime sample findings maintained by the camera trial records must be used to
assess installed behavior; this static report asserts no installation identity.

Ordinary firmware rollback requires a running application. The presence of boot
downloaders, monitor commands or GetMem code does not establish recovery after
an unbootable executable patch. Actual update erase/write ranges, complete
backup/calibration coverage, ECC/bad-block handling and an accessible tested
restoration route remain unresolved. Executable placement, hooks and code trials
remain blocked. No camera commands or executable patches were issued here.
