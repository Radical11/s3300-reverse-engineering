# Backup USB setup and metadata boundaries

25 October 2026. Authenticated offline follow-up to
[recovery transport](recovery-transport.md), [USB modes](usb-mode-contracts.md)
and [USB entry](usb-entry-contracts.md). This pass sends no camera request,
changes no mode/driver and exposes no host debug adapter. Its source-bound
record is [backup-usb-contracts.json](../evidence/backup-usb-contracts.json).
Direct Ghidra findings remain separate from REA Evidence.

## Original setup bytes now traced to the reader

The controller0 attach function `803908b4` passes the setup-buffer pointer
from runtime state+`18` into `8038b6f4`. The driver stores that pointer at
state+`40` at `8038b948`. On setup interrupt, `8038c8d4..8038c8e0` copies two
original words from controller queue+`28/+2c` into that buffer. The interrupt
then calls state+`140` with handle, logical endpoint0 and the same buffer.

Registration `803907c8..803907d4` installs `8038d4ac` in that callback field
through `8038e3d0(controller0, kind0, callback)`. Reader `8038d90c` eventually
copies the two words from the state+`18` pointer. Thus the eight-byte layout
used by `80796310` is the original setup layout within this static route,
rather than an unexplained normalized command envelope.

The Ghidra dossier for `8038b6f4` marks blocks after a hardware polling loop
unreachable and renders an infinite loop. Original branch instructions retain
conditional exits and the later state+`40` store. Both the decompiler warning
and independent bounded Capstone checks remain visible. The static control
flow does not prove that a physical controller leaves the polling loop.

## Request classes, wakeups and debug forwarding

Callback `8038d4ac` extracts `bmRequestType` bits5..6. For logical endpoint0
with endpoint status1 it selects:

| Setup type | Event / behavior |
| --- | --- |
| Standard0 | Call `8038f080`; if unhandled, event`100` |
| Class1 | Event`400` |
| Vendor2 | Event`200` |
| Reserved3 | No type event |

For a nonready status on logical0 the callback attempts both `200/400` wakeups;
this is not acceptance of a new command. Other logical selectors return.
Signaling additionally depends on the handle's enabled event mask at+`2c`.

Debug reader `80796310` requests flags6, corresponding to wait mask`600`.
After waiting, it checks disconnect state. It then tests **only bit0** of the
original `bmRequestType`: zero forwards setup byte3 as internal command index
and byte2 as subcommand; one calls mass-storage class helper `807769b4` and
loops. The actual predicate is recipient parity, not a complete recipient
allowlist. Neither this reader nor the reviewed class/vendor callback restricts
`bRequest` or `wIndex`.

This bounded absence of checks does not establish that arbitrary requests reach
the installed camera. The reader is associated with the separate application
debug modes; normal PTP descriptors do not establish its registration. An
ordinary PTP command and a USB setup request are different transport operations.

Zero-length forwarded setup records issue a status transfer before dispatch.
For nonzero host-to-device control data, `8079651c` passes the setup's unsigned
16-bit length to receive. Dispatcher `80796108` allocates`2000` bytes, while no
matching`2000`-byte control-length cap is established in this reviewed path.
The single shared setup record also needs an end-to-end lifetime and queue
sequencing contract. These are concrete reasons to keep arbitrary debug
traffic outside the read-only camera interface.

## Standard PTP metadata is not raw-flash access

The original registry initializer `8077f204` assigns local route0/data phase1:

| Standard operation | Handler | Reviewed direct behavior |
| --- | --- | --- |
| GetDeviceInfo`1001` | `8077fe68` | Temporary supported-opcode list, metadata callback`80748f68`, serializer`8077b474`, cleanup, response`2001` |
| GetStorageInfo`1005` | `80782120` | Select storage`10001/20001`, query media/device metadata and capacity, serializer`8077b9d4`, invalid-storage`2008`/no-media`2013` |

No explicit NAND-program or block-erase call appears in the reviewed direct
handler windows. Allocation, runtime queries and response construction do occur.
The complete transitive media-driver side effects and exact installed-byte
correspondence remain outside this check. These metadata operations do not
read boot ROM, calibration, NAND spare/ECC data or a complete installed image.

## The baseline string serializer does include a terminator

StorageInfo serializer `8077b9d4` writes a26-byte numeric prefix. It calls
shared string helper `8077b320` at offset`1a`, then places the volume label at
`1b + 2 * description_count`. For ordinary nonempty ASCII input the helper
masks strlen to low8, stores length+1 as the count byte, zeroes twice that
count, and copies successive ASCII bytes into UTF16LE low-byte positions,
including the terminating NUL.

Therefore ordinary ASCII `S3300` means count6 with a UTF16 NUL under this
baseline helper. An observed count5 followed by unterminated `S3300` is **not
explained by the recovered helper**. Preserve any strict-decoder failure and
decode the fixed numeric prefix separately; do not relax a generic parser to
pretend that the two datasets agree. Installed firmware bytes, input provenance
or a transport transformation would need independent investigation.

This helper also has real length limits: at strlen low8=`255`, length+1 is256,
the stored count wraps to0 and the loop copies at most255 low bytes. At low8=0
it writes an empty string. It is not a general Unicode or arbitrary-length
serialization API.

## Reproduction and remaining backup gate

```powershell
python tools/map_backup_usb_contracts.py --output derived/backup-usb-recheck.json
python -m unittest discover -s tests -p test_backup_usb_contracts.py -v
```

The builder authenticates source and decoded-image identity,47 selected
original instructions, seven bounded windows and all imported instructions in
20 retained application dossiers. Nine tests cover all256 request-type bytes,
nonready wakeups, request/recipient distinctions, disconnect ordering, the
16-bit-versus-allocation boundary, string count truncation and input rejection.
These pure helper tests do not execute USB hardware or prove runtime access.

No safe installed memory-read bridge, complete backup, boot-independent
software recovery or executable-trial gate is promoted. The next required
evidence remains: installed debug-mode reachability; safe read regions, lengths
and state sequencing; complete physical backup representation; and recovery
entry independent of the application.
