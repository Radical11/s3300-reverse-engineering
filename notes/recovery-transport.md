# Debug transport and recovery entry follow-up

25 October 2026. Authenticated v1.1 static analysis; no camera request, firmware
patch, setting change or target execution. The reproducible report is
`evidence/recovery-transport.json`. This extends `state-contracts.md` and
`restore-path.md`, preserving their historical observations.

## GetMem state now has a proven dispatcher producer

Table **0x80898ec8** record **0xf1**, at **0x80899650**, contains handler
**0x8079cd48** and receive flag1. The adjacent records remain0xf2 SetMem/monitor
and0xf3 GetMem. **0x8079cd48** (`OnConfigMemAccess` diagnostic) reads two LE32
words at payload+0/+4. It calls **0x80203e54** with the dispatcher subcommand
low8 as mode and those words as address and length.

Setter **0x80203e54** stores mode at **0x800e113c**, address at+4 and length
at+0x10. It changes additional state for modes2/3/4/5/7. Mode1 of handler
**0x8079de34** reads this same state, ORs address with0x20000000, prepares
memory/cache state at **0x800b52e4** and sends through **0x80796070**. Timing and
status updates also occur. Thus the missing state-population link is resolved
statically: dispatcher→0xf1→setter→state→0xf3. These are internal indices,
not PTP operations or a validated host request recipe.

The ConfigMem handler reads at least eight bytes but the complete input bounds,
valid target address space and safe length constraints are unresolved. GetMem
uses multiple modes with different behavior. The adjacent SetMem/monitor entry
can mutate memory or invoke monitor commands. None is exposed as a supported
workspace camera API.

## The application USB envelope and queue

**0x80796310** receives setup state into **0x808c8568** through **0x8038d90c**
using logical selector0. Its branch reads byte3 as the internal index and byte2
as the subcommand. Bytes6/7 are the little-endian transfer length. In a standard
eight-byte USB setup layout these are the high and low bytes of `wValue` and
the `wLength` field. Accepted request-type/request combinations and validation
before this receiver remain unresolved.

Control loop **0x8078d7b4** dispatches index2 immediately at **0x8078d850**.
Other indices go through **0x8078d768**, which posts two words to queue
**UsbCamCmd at0x808c8530**. **0x8078d718** receives them; queue loop
**0x8078d860** truncates them to bytes and calls dispatcher **0x80796108** at
**0x8078d87c**, with transport selector1.

The following selector values are recovered at the USB abstraction boundary;
they are not yet verified endpoint addresses on the connected camera:

| Path | Static call |
| --- | --- |
| Setup | 0x8038d90c, logical selector0 |
| Ordinary receive | 0x8038d720, selector2 |
| Receive with pending setup length | 0x8038d720, selector0 |
| Ordinary send | 0x8038da28, selector3 |
| Send with pending setup length | 0x8038da28, selector1 |

Receive wrapper **0x80795fe0** defaults to64bytes when its length pointer is
null. **0x8079651c** distinguishes ordinary receive from length-bearing setup
state and its direction bit. The dispatcher allocates0x2000 bytes, but the
setup-driven branch uses a received16-bit length; no complete end-to-end length
or legal-opcode bound was recovered. This is a concrete reason not to convert
the static map directly into arbitrary device requests.

USB startup **0x8078fa3c** reacts to the configured/connect state, opens logical
selectors2..5 and creates `Usb control and vendor` with entry0x8078d7b4.
Conditional queue initialization **0x8078d88c** creates `CmdDispatcher` with
entry0x8078d860. The native index contains exact callback references at
0x8078fd88 and0x8078d908. Startup mode ownership and the matching active camera
configuration still require proof.

## UART is a separate application transport

**0x80771cdc** creates `UartAgent` through **0x80791e0c** only when configuration
helper **0x80000cf4** has bit0x4 set. The UART loop **0x80791d10** passes transport
selector0. Sender **0x80795ce0** rounds the data length up to an even byte count,
sends at most64bytes per block with byte0x02 and a word count, requires byte0x54
acknowledgements, then terminates with0x04. Receiver **0x80795e68** handles
0x02/0x04/0x43 records. This framing does not establish software-only UART
access, and no electrical access was attempted.

Both UART and USB debug loops reside in the ordinary application. Recovering
their framing does not establish availability after that application fails to
boot.

## Updater startup is distinct from reset recovery

The separate ELF at carrier+0x200 is authenticated byte-for-byte. Its entry
**0x80010000** calls `main` **0x8009d64c**, starts the ThreadX kernel, and
**tx_application_define at0x80010b40** creates `Burn Main` at **0x800109c8**.
This proves entry within that updater executable; it does not prove a reset
route can load it after a damaged installed application.

`BurnMain` uses **0xbfc095fc**: bit0x1000 forces source0x1c (USB); otherwise
low8 shifted right3 selects a source. Source3 selects UART, while1/4/6/0xff
select card variants. The meaning of this hardware state on the S3300 and its
software-only activation remain unknown. No button sequence is inferred.

**InitRecoverSection at0x8001a3d0** computes section size/alignment metadata.
Its name does not identify an externally accessible recovery entrypoint.
`BurnNand` **0x80012e84** tests the sign bit of payload header word+0x14 before
the `Recover Area Enabled` branch. The supplied package word at carrier
0x1000c0+0x14 is2, so bit31 is clear. This describes the package request;
installed recovery-area existence or contents are not established.

Actual write ranges depend on runtime geometry and previous headers.
**BurnGetSectionsMap at0x8001a4e8** uses live total sectors at handle+0x1244,
erase-unit sectors at+0x1240 and, for an upgrade, existing boot-header section
records. `BurnNand` also handles bad blocks and recovery metadata. A carrier
offset or section formula cannot substitute for a verified physical erase/write
map and complete calibration backup.

## Reproduce and remaining gap

```powershell
python -m unittest discover -s tests -p test_recovery_transport.py
python tools/map_recovery_transport.py --output derived/recovery-check.json --listings derived/recovery-check-listings
```

The tool checks13 exact Capstone instructions, the six-word f1/f2/f3 table,
three startup callback references from the read-only native index, all imported
instruction bytes in28 direct-Ghidra dossiers, the source identity and the
embedded updater ELF slice. Seven bounded analyst listings remain local under
`derived/`. Decompiler output is explicitly direct Ghidra evidence, separate
from REA Evidence. Missing indirect functions remain bounded listings; inferred
signatures are not promoted to public ABIs. Existing output paths are refused.

Remaining work is specific: prove accepted USB setup fields and active endpoint
mapping against the installed version, identify safe read regions/lengths and
state sequencing, establish complete backup/calibration/ECC scope, recover
actual write ranges, then prove reset-to-recovery access independent of the
application. Ordinary menu rollback remains different from unbootable recovery.
The host-debug-read, complete-backup, unbootable-recovery and executable-trial
gates all remain false.
