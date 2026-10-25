# USB mode entry and the calibration dependency

25 October 2026. Offline authenticated v1.1 analysis. No camera command, mode
switch, setting change or firmware patch was performed. This extends
`usb-mode-contracts.md` and `reset-recovery.md`.

## Complete direct-call boundary

The retained native index has eight call sites in seven functions for mode
wrapper **0x80771c68**. An independent scan of every aligned word in all eight
decoded application regions finds exactly the same eight `JAL` encodings.
Every mode is loaded in the call's delay slot:

| Caller | Call site | Mode | Reviewed context |
| --- | --- | --- | --- |
| 0x8059b99c | 0x8059ba8c | 5 | USB mass-storage creation |
| 0x80638378 | 0x806384e4 | 7 | PictBridge/DPS connection event |
| 0x806398d8 | 0x80639a74 | 7 | PTP card reinsertion |
| 0x806398d8 | 0x80639aa4 | 7 | PTP reconnection branch |
| 0x806a87ac | 0x806a87dc | 0 | Internal Pure HCE initialization |
| 0x806f8e60 | 0x806f9148 | 0 | Startup USB-test-state branch |
| 0x806f93fc | 0x806f9670 | 0 | Internal START_ENTER_TEST_Mode event |
| 0x8073f858 | 0x80740050 | 0 | Connection/event handling with test state |

Thus no direct mode6 call exists within this search boundary. This does not
exclude unresolved indirect transfers, another executable or runtime-generated
calls. All indexed references to lower wrapper **0x8078bd48** were also
reviewed: **0x80771c70** from the public-internal wrapper and **0x8079c598**
from the debug handler. Both preserve only the low byte of the argument.
The lower wrapper posts queue2/message0x100000 with that mode as its argument.

## Mode0 is a separate application debug path

Mode0 must not be conflated with mode6. Registration **0x807721f8** stores
slot0 and starts `UsbAgent` through **0x8078dc04**. Descriptor dispatch
**0x80772bfc** calls **0x8078dc8c**, passing **0x8068be9c**, which returns0.
The resulting class0 interface has the debug transport's bulk endpoints.
Mode6 additionally composes a mass-storage interface, as documented in the
previous map.

The concrete startup dependency is word **0x8000ff8a**. Predicate
**0x80741cd8** returns whether its low nibble differs from8. Startup
**0x806f8e60** stores the inverse result in **0x808921ef**; its mode0 branch
requires that byte to be zero, hence **low nibble !=8**, along with other
runtime guards. The tests explicitly check this polarity. No live value of
this calibration word has been read.

Other internal entry leads are event0xd181 reaching **0x806a87ac**, event0xd112
in **0x806f93fc**, and event0xd001/0x12a processing in **0x8073f858**. These
event numbers are internal dispatch identifiers, not verified user controls or
PTP operations. The mapped functions change display, capture and USB lifecycle
state. None supplies a safe user-facing activation procedure.

## Changing the flag is a calibration write

The sole direct write reference to **0x8000ff8a** in the retained native index
is in **UIDebugMsg 0x8058af54**, case0x32/subcase6. It first reads0x400 bytes
from **`C:\ColdData.bin`**, selects one of several calibration words, changes
the selected low nibble to4 or8, writes the file, and updates persistent
settings/checksum state through **0x807378a4/0x8000994c**. The file literal is
authenticated at **0x8066b550**. Read helper **0x80741d84** and write helper
**0x80741e1c** are included in the corroborated dossiers.

The handler is reached by internal event0x200 with parameter<0x80 in
**0x806a8a2c**. No verified host/public entry to that event was found in this
bounded investigation. Altering `ColdData.bin` would be stateful calibration
modification, with no verified live file format, integrity, rollback or lifetime
contract. It is not exposed as a supported workspace modification or attempted
on the camera.

Debug handler **0x8079c590** occupies internal table record0xd3 at
**0x80899560**, receive flag0. It can request a mode through the lower wrapper,
but requires an already functioning debug dispatcher. This is circular as an
independent entry into that dispatcher and remains application-dependent.

## Reproduce and remaining gate

```powershell
python tools/map_usb_entry_contracts.py --output derived/usb-entry-check.json
python -m unittest discover -s tests -p test_usb_entry_contracts.py
```

The report authenticates source and analysis identity, checks20 direct-Ghidra
dossiers against original instruction bytes, verifies18 selected instructions
with Capstone, compares indexed callers against the independent raw-JAL scan,
and checks all eight delay-slot constants. Generated vendor listings remain
local; this map records original analysis and source references separately from
REA Evidence.

The new lead narrows the unresolved entry problem to internal test/calibration
state and event lifecycle. It does not establish safe mode0 activation, mode6
activation, complete backup or recovery after application boot failure. All
those gates remain false, and executable camera trials remain blocked.
