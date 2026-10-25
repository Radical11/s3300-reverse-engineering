# Reset and recovery independence

25 October 2026. This offline follow-up authenticates the separate updater,
tiny loader and primary ELF against their exact slices in the original v1.1
carrier. It extends `recovery-transport.md`; it issues no camera command and
does not authorize executable trials. Reproduce with:

```powershell
python tools/map_reset_recovery.py --output derived/reset-recovery-check.json
python -m unittest discover -s tests -p test_reset_recovery.py
```

`evidence/reset-recovery.json` keeps each image in its own address namespace,
including entry, flags, file-backed ranges, native dossier hashes and imported
instruction-byte verification. The same numeric address can mean different
code in different executables. Direct Ghidra findings are separate from REA
Evidence. MIPS16 assertions compare exact original instruction bytes and the
retained Ghidra decode; no independent MIPS16 decoder or CPU execution is
claimed.

## What the tiny loader actually establishes

The tiny ELF at carrier **0x1006c0** has odd entry **0x81000401**. Ghidra
decodes MIPS16 instructions beginning at **0x81000400**. Its literal at
**0x81000420** supplies stack **0x81002f28**; the next literal calls
**0x81000949**, preserving the instruction-mode bit.

Routine **0x81000948** reads fields at runtime **0xbfc09600+0xc/+0x10/+0x20**,
initializes low-level hardware, and invokes loader **0x81000ad1**. That loader
reads a 0x34-byte ELF header, uses `e_phoff`, `e_phentsize` and `e_phnum`, then
reads nonempty `PT_LOAD` file data. It returns the ELF entry at header+0x18;
the caller calls that returned address and loops forever if it returns.

This is a loader path within the supplied tiny executable. No authenticated
caller from the hardware reset vector to this tiny ELF was recovered. The
runtime boot header is not a verified installed-flash backup. Its exact live
values and physical provenance remain unknown.

Destination handling is unusual and must not become a placement whitelist:

| `p_vaddr` condition in 0x81000ad0 | Observed action |
| --- | --- |
| 0xbfc00000 through 0xbfc07fff inclusive | Skip |
| `(address & 0xbfc00000) == 0xbfc00000` after that check | Stage, later copy to `address & 0x9000ffff` |
| `(address & 0x90000000) == 0x90000000` | Stage, later copy to the same token |
| Otherwise | Read directly to `address | 0x20000000` |

Staged records form a linked list and are copied afterward through tiny memcpy
**0x81000429**. Only `p_filesz` is copied in this reviewed path. Complete
validation, zero-fill policy, memory ownership, target entry ABI and error
recovery are not established. The pure helper tests boundary behavior without
operating hardware.

## The critical absent ROM dependency

Routine **0x81000644** sums exactly 64 bytes at **0x9fc00900**, modulo 256.
A sum of 0xf7 produces selector 0x13a0; 0x29 produces 0x13a1; any other sum
is returned directly. The caller accepts only those two selectors and loops
forever otherwise. This is a weak selector, not an authenticated ROM hash or
proof of the physical chip model.

Neither those 64 fingerprint bytes nor the reset vector at **0xbfc00000** is
file-backed in any of the six original ELF carriers. Coverage was checked
using the KSEG alias low-29-bit correspondence separately for every image.
This is a bounded statement about the supplied ELF mappings, not proof that
the camera lacks ROM or a recovery facility.

The primary ELF does contain **0x9fc08000..0x9fc092eb**, but its reviewed entry
is a GPIO/status wait routine called by **0x9fc08860**. That caller quiesces
application hardware/cache, changes clock state, waits, restores state and
returns. Being packaged at a ROM-shaped address does not prove immutable ROM
or independent reset recovery. The supplied primary ELF itself enters at
**0x80000600**.

## The remaining gate

The separate updater at carrier **0x200**, entry **0x80010000**, contains
`BurnMain`, live geometry handling and recovery-section routines. Its existence
does not connect the absent reset path to a usable host transport. The
package's RecoverArea flag bit31 is clear, and installed recovery contents are
unknown. The normal application USB debug dispatcher also depends on the
application starting successfully.

Executable trials remain blocked until all of these are established:

- An authenticated installed boot/ROM path that reaches recovery independently
  of the normal application, with accessible software-only activation.
- A matching transport with verified safe operation, address and length bounds.
- Complete installed backup coverage, including calibration/settings and the
  relevant geometry, bad-block and ECC representation.
- A verified restoration procedure that does not require deliberately damaging
  the camera.

No button sequence, vendor request, debug mode switch or memory read is inferred
from these constants. A normal firmware update and an SD-card rollback remain
different from recovery after an unbootable executable patch.
