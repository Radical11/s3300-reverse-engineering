# USB modes, handle slots and the observed PTP configuration

25 October 2026. Static findings from the authenticated v1.1 source, with
separately labelled direct-Ghidra corroboration. No device request, mode switch,
driver change or patch was performed. Runtime observations are maintained in
`evidence/camera-usb-verification-2026-10-25.json`.

## Central conclusion

The reported live configuration has one StillImage interface, class6/subclass1/
protocol1, bulkOUT0x01, bulkIN0x81 and interruptIN0x82. This matches the static
**mode4-or7 PTP descriptor branch**. The static debug startup previously traced
through **0x8078fa3c** is registered by **mode6**, which constructs different
interfaces and aliases different handle slots. Matching transport functions or
endpoint numbers does not establish that mode6's handlers run in PTP mode.

Descriptors alone also do not prove that every vendor request on endpoint0 is
absent. The recovered branch distinction narrows the question; it is not a safe
debug activation recipe or a proof of a universal prohibition.

## Handle registry and mode registration

Getter **0x8078bdac(slot)** calls **0x8077ec3c(0x1a)**. Capability type0x1a returns
`*(u32*)0x80898d6c +0x35c`; the getter reads a word at `+4*slot`. Setter
**0x8078be14** writes the same array. Slot numbers identify registered handles,
not physical USB endpoint addresses. **0x8078bde0** obtains a slot handle and
passes it through **0x80389b94**, which reads its first word for the underlying
controller identifier.

Registration dispatcher **0x807721f8** assigns these aliases:

| Mode | Same supplied handle assigned to slots | Startup |
| --- | --- | --- |
| 4 or7 | 4 and7 | PTP initialization |
| 6 | 6,5 and0 | 0x8078fdbc creates UsbAgent at0x8078fa3c |

The PTP receive/send functions **0x807785c4**, **0x807787a0** and **0x80779318**
use slot4. The debug startup loop uses slot6; the recovered debug receive/send
wrappers use slot0, which mode6 aliases to the same handle. Mode6 also aliases
slot5 for its mass-storage path. This explains the apparent slot mismatch in
the prior transport map without assuming all slots always contain one handle.

## Descriptor construction resolves PTP endpoint encoding

Descriptor switch **0x80772bfc** routes modes4/7 through PTP builder
**0x80778304**. It creates interface0 alt0 class6/subclass1/protocol1 and logical
endpoints2,3,5. Bulk packet size is512 for speed argument1 and64 otherwise;
the interrupt endpoint uses8bytes and interval16.

Generic endpoint builder **0x8038a828** writes the address byte using:

```
address = ((logical & 1) << 7) | (logical >> 1)
```

Thus logical2→0x01,3→0x81,5→0x82, matching the reported live PTP descriptor.
This encoding is backed by shifts, masks, OR and the final byte store in the
authenticated image. It does not promote every abstract transfer selector into
a proven active endpoint: handle registration and mode must agree too.

For mode6, **0x80772bfc** creates a class0 interface0 through **0x8078dc8c**, with
logical2/3, then a class8 mass-storage interface1 through **0x80777448**, with
logical4/5. That composition differs from the single observed class6 interface.
Mode0 has its own debug-interface builder path and startup, which is not covered
by the mode6 activation claim.

## Who selects a mode

Wrapper **0x80771c68** calls **0x8078bd48**, which posts message0x100000 with a
mode byte to queue2. Consumer **0x8077340c** passes it to **0x80773144**, which
rebuilds descriptors through **0x80772d34** and invokes registration
**0x807721f8**. Descriptor metadata is partly loaded from vendor resource files
`A:\UsbDevDesc.BIN` and `A:\UsbModeDesc.BIN`, explaining why a complete raw
descriptor need not appear as a literal byte sequence in executable memory.

The mapper now follows both resource files back through the source directory,
BPB geometry, FAT16 chain, data offsets and exact original hashes. The consumed
six-byte records yield these defaults:

| Resource/row | Source-bound fields consumed by0x80772d34 |
| --- | --- |
| UsbDevDesc.bin | VID0x04b0; configuration attributes0xc0; power byte250; manufacturer string selector1 |
| UsbModeDesc.bin, mode4 | PID0x032a; product string selector3; serial string selector4 |
| UsbModeDesc.bin, mode6 | PID0x2016; product string selector2; serial string selector4 |
| UsbModeDesc.bin, mode7 | PID0x032a; product string selector3; serial string selector4 |

`UsbDevDesc.bin` is6bytes at cluster11175; `UsbModeDesc.bin` is48bytes at
cluster11176 and contains eight six-byte rows. Only fields actually consumed by
the builder are assigned meanings. These defaults reinforce the mode4-or7
comparison, while capability overrides remain active: nonzero capability10/11
can override VID/PID; capability12 supplies bcdDevice; capability0x23 can
override the power-related local byte; capability text can replace resource
string selection. These files are descriptor inputs, not complete USB
descriptors or proof of installed bytes.

The UI routine **0x806398d8**, associated with diagnostic `PtpMode_CardReIn`,
calls the wrapper with mode7 under its state predicates. Diagnostic handler
**0x8079c590** passes a subcommand through the same wrapper, but reaching that
handler is itself dependent on the debug transport. It is not independent
evidence that an ordinary PTP host can select mode6.

The initial default helper **0x8069fcf8** returns0; initialization alone does not
identify the current post-connect mode. No confirmed physical/UI mode6 entry
was recovered in this bounded pass. The live descriptor cannot distinguish4
from7, and no live RAM mode value was read.

## Reproduction and limits

```powershell
python -m unittest discover -s tests -p test_usb_mode_contracts.py
python tools/map_usb_mode_contracts.py --output derived/usb-mode-check.json
```

The map authenticates the original source and analysis ELF, checks nine exact
Capstone instructions, and verifies imported bytes across24 direct-Ghidra
dossiers. Existing output paths are refused. Tests cover endpoint encoding,
mode4/7 equivalence, mode6 aliases and rejection of unsupported comparisons.
Vendor pseudocode remains in the local native cache.

Still unresolved: the exact active mode4 versus7; complete mode ownership and
disconnect lifecycle; vendor setup coexistence elsewhere in PTP; and a verified
physical/software entry into a debug mode. Matching reported firmware version
and descriptors does not prove installed bytes. Debug read reachability,
boot-independent software recovery and executable trials remain unverified.
