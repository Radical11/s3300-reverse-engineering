# Recovered interface reference

Use `python s3300.py interface --search TEXT` for current structured entries and
`--id ID` for a specific entry. This chapter is an orientation index. Addresses
describe the authenticated supplied v1.1 image, not a stable universal API or
host pointers. Per-entry provenance and limitations take precedence over a
convenient short name.

| Area | Entry / object | Checked behavior | Integration boundary |
| --- | --- | --- | --- |
| DRAM query | `0x8003c3ac` | Reads selector at `0xb8002010`; cases 1..6 report 8..256 MiB | Actual installed selector unread |
| Clock getter | `0x80025198` | Bounds index below 56; reads runtime table `0x808a5b8c` | Table absent from file-backed map |
| GPIO table | `0x800a2264` | Record stride `0x54`, register base at +8 | Board wiring/mux and valid pin ranges unknown |
| GPIO leaf access | `0x800a16f8` / `0x800a1728` | Uses base+`0xc+4*pin` | Electrical meaning and ownership unknown; monitor getter changes state |
| Allocator dispatch | `0x80020980` | Pool-dependent callback path and metadata | Complete allocation/free/failure ABI unresolved |
| Shared frame descriptor | Seven u32 words | Address token, parent width/height, ROI left/top/width/height | Conditional JPEG pitch recovered; live packing, DMA/cache ownership unresolved |
| RAW-to-YUV wrapper | `0x80205918` | Null checks and descriptor copies | No aligned direct-call/pointer references found in eight mapped regions; active use unproven |
| Command wrapper/router | `0x802233e8` / `0x801fd324` | Context-dependent retained or queued copy | Complete context naming and buffer ownership unresolved |
| Colour matrix builder | `0x806af434` | Builds command 15, size `0x34` | Register application now traced; arbitrary callable integration remains gated |
| Matrix upload | `0x802d2c88` | Factory 11 writes matrix/offset registers `0xb60000c0..0xb60000e8`, auxiliary word `0xb60000fc` | Internal scheduling/ownership must be preserved; no raw SDK call is exposed |
| Colour dirty word | `0x808c1d78` | Command 15 sets bit `0x00100000` | A set bit alone does not establish saved-photo effect |
| Gamma converter | `0x8021bd3c` | Packed legacy gamma conversion | Not a normal RGB8 LUT API; full conversion/domain incomplete |
| Color Options | `0x805ac85c` | Static registration and event dispatch, persistent view byte +`0x1a` | Cancel can persist other state; no verified custom-control adapter |
| Shared user store | `0x800032d4` | Setup +`0x28`, view block +`0x76` staging | Not a supported standalone persistent-settings API |
| Settings checksum | `0x80008f80` helper / store byte +`0x19f` | Store checksum equals sum of offsets 0..`0x19d` modulo 256; byte +`0x19e` excluded | Excluded byte purpose and settings write safety remain unresolved |
| Settings transaction | `0x80009644` | Allocates media buffer, stages/checks store, routes operations | Physical write bounds and power-loss behavior incomplete |
| Debug dispatcher | `0x80796108` | Eight-byte records from `0x80898ec8`; GetMem index `0xf3` | Not a proven PTP invocation recipe |
| ConfigMem producer | `0x8079cd48` / index `0xf1` | Payload address/length passed to state setter `0x80203e54` | Host acceptance, bounds and side effects unresolved |
| GetMem handler | `0x8079de34` | Uses ConfigMem-populated state and transport selector | Installed reachability, safe read scope and boot independence unresolved |
| English text lookup | `0x802c73fc` | Bounds ID, selects pointer indexed by ID minus first ID | Amber confirmed in Auto Color options; Nostalgic sepia is a separate entry |
| USB mode registration | `0x807721f8` | Modes 4/7 PTP aliases differ from mode 6 debug/storage | Live descriptors match PTP; independent debug activation remains unknown |
| Saved-JPEG processor | `0x8031aa5c` | Static shutter route reaches FileCompressor event `1042`, JPEG/EXIF processing | Exact packing and live buffer ownership unresolved |
| JPEG lifecycle | `0x8032b20c` / `0x8032b0fc` / `0x8032b1a8` | Create/start, wait/count, destroy | Asynchronous path; no ordinary RGB8 buffer API |
| Encoded segment writer | `0x8030e7d4` | Writes segment pointer/length; flag `4` frees data and node | Producers must transfer ownership before queueing |
| Cache small-range loop | `0x800b52e4` | Line-rounded D writeback/invalidate, low32 end arithmetic | Runtime line size, ownership and ordering unresolved |
| FastCopy | `0x8005df30` | Cache preparation, scratchpad submission and completion wait | Existing internal path; no verified public DMA adapter |
| Tiny ELF loader | `0x81000ad1` | MIPS16 loader reads program headers and returns entry | Separate namespace; reset vector/required ROM absent from package |
| PTP registry | `0x8077f050` | 256 records, 12 bytes each; local/queued routing | Advertised vendor operations do not establish passive backup access |
| USB test-state predicate | `0x80741cd8` | Calibration low-nibble predicate participates in guarded mode0 entry | Internal events/calibration writer supply no verified safe user-facing activation |
| Shutter scanner | `0x806a02bc` | Normalizes two register expressions before debounce and edge masks | Live wiring/mask/state correlation remains unobserved |
| Capture mode router | `0x80204460` | Maps mode to still-capture selector and queues action | Current UI/capture-state object differs from the persistent view bank |
| JPEG input selectors | `0x801a4490` | Stores input kind and secondary/layout option separately | Layout selector one does not establish 420 input kind |
| JPEG DMA pitch | `0x801a5c40` | Parent-width pitch and block/word rounding | No complete component order, numeric range or live ownership |
| Color Options registration | `0x805af460` | Static five-entry object, callbacks, parent and entry storage | No general dynamic menu-registration adapter |
| Dynamic entry list | `0x806fbab0` | One global allocation slot; old list freed on replacement | Multiple menus cannot assume independent list ownership |
| Updater section policy | `0x8001a07c`, updater namespace | Software predicates over seven logical sections | Separate full-erase/header/bad-block paths still apply |
| Updater user relocation | `0x80012730`, updater namespace | On-device RAM/tail-block relocation | Erases/programs flash; not a passive host backup |

The [hardware](../../notes/hardware-contracts.md),
[capture](../../notes/capture-contracts.md), and
[state](../../notes/state-contracts.md) reports retain the reviewed instructions,
tables and derived offsets. The [gamma report](../../notes/gamma-pipeline.md)
explains why a simple-looking resource cannot be replaced by an arbitrary LUT.
The later [development contracts](../../notes/development-contracts.md) resolve
the precise settings checksum range and trace the image dirty-state consumer
into another driver-owned command copy. The
[matrix application follow-up](../../notes/matrix-application.md) traces group
11, slot 15 and factory 11 through decoding and register upload, with direct
Ghidra corroboration. These advances do not establish a safe arbitrary settings
writer, complete saved-photo buffer ABI or recovery.

The [capture-buffer follow-up](../../notes/capture-buffers.md) adds the shared
descriptor fields, JPEG-specific guards, shallow pointer retention and a
temporary scale-buffer allocation/wait/free sequence. Coordinate width is not
an established byte stride, and numeric multipliers 2/3 are not a universal
format definition. The intermediate buffer is freed by its existing lifecycle;
a hook cannot assume it owns that buffer after cleanup.

The [placement](../../notes/executable-contracts.md),
[transport](../../notes/recovery-transport.md) and
[label](../../notes/label-contracts.md) follow-ups retain additional checked
instructions, native dossier provenance and explicit remaining gates.

## SDK surface versus research surface

Pure host/target transformations can have complete testable C contracts without
calling Nikon code. A research record can be valuable while still incomplete
as a callable device interface. The SDK must expose only the former or an
explicitly verified adapter. Merely listing a device address here does not
promote it to a supported C function pointer.

## Recheck a focused map

Use the retained native databases instead of decompiling the application again:

```powershell
python s3300.py research-map saved-jpeg derived/saved-jpeg-recheck.json
python s3300.py research-map cache-dma derived/cache-dma-recheck.json
python s3300.py research-map reset-recovery derived/reset-recovery-recheck.json
python s3300.py research-map ptp-vendor derived/ptp-vendor-recheck.json
python s3300.py research-map usb-entry derived/usb-entry-recheck.json
python s3300.py research-map shutter-input derived/shutter-input-recheck.json
python s3300.py research-map shutter-route derived/shutter-route-recheck.json
python s3300.py research-map pixel-layout derived/pixel-layout-recheck.json
python s3300.py research-map menu-lifecycle derived/menu-lifecycle-recheck.json
python s3300.py research-map update-write-scope derived/update-write-recheck.json
python s3300.py research-map backup-scope derived/backup-scope-recheck.json
python s3300.py research-map backup-usb derived/backup-usb-recheck.json
python s3300.py research-map updater-handoff derived/updater-handoff-recheck.json
python s3300.py research-map application-write-scope derived/application-write-recheck.json
python s3300.py research-map saved-jpeg derived/saved-jpeg-recheck.json --verify-existing
```

Each builder authenticates the original source, decoded image and selected
native instruction bytes before emitting a metadata report. Choose a fresh
output path. `--verify-existing` recomputes the focused checks, rejects stale or
incompatible results and preserves the existing report. These commands reuse
`derived/native-analysis-complete`; they do not import firmware into Ghidra
again, access USB or build/install an executable patch. The PTP investigation
also records the explicit scope and limitations of host instruction emulation.

CLI reports also bind the native tool versions, exporter script hashes and
focused verifier hashes. Changing those inputs makes an existing CLI report
incompatible with `--verify-existing`; generate a new report and preserve the
older result. Direct per-map scripts remain useful for their original report
format, while the CLI adds this provenance record.

Every future callable adapter should specify exact artifact identity and
instruction mode, arguments/returns, field layouts, valid ranges, ownership and
sync, failure paths, observed callers, side effects and the tests that support
it. Maintain the original operation's lifecycle instead of bypassing locks,
watchdogs, calibration or power sequencing for convenience.
