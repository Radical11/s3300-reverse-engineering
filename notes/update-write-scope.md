# Updater write scope and the backup boundary

25 October 2026. This follow-up authenticates the separate updater ELF at
carrier offset `0x200`. Its address namespace differs from the normal
application even where numeric addresses overlap. It sends no camera request,
executes no updater code, and does not approve an executable trial.

The reproducible record is [update-write-scope.json](../evidence/update-write-scope.json),
produced by [map_update_write_scope.py](../tools/map_update_write_scope.py).
Every imported instruction in 13 retained updater dossiers is compared with
its exact authenticated carrier bytes; 32 selected MIPS instructions receive
independent Capstone assertions. Direct Ghidra findings remain separate from
REA Evidence. The large `BurnNand` dossier has a retained type-propagation
warning, so its inferred C types are not a complete recovered ABI.

## Section records and protection predicates

`BurnGetSectionsMap 8001a4e8` constructs seven records, each `0x24` bytes.
Offsets `+0/+4/+8/+c` contain logical start sector, reserved sectors, burn
sectors and section type. Additional fields support boot-header patching and
flags; `+21` receives `IsSectionProtected`'s result. Do not interpret the
logical start as an installed physical NAND address.

The builder consumes runtime erase-unit sectors at handle `+1240`, total
sectors at `+1244`, zone information and an existing installed header. The
upgrade branch (`new_header+234 == 1`) copies the previous map and requires
the three size fields at `+218/+21c/+220` to match. A full-burn branch derives
a different layout. The media-kind-5 boundary branch adds
`boundary - start % boundary`; even an already aligned start advances one
whole boundary unit. The pure model deliberately preserves this behavior.

`IsSectionProtected 8001a07c` returns:

| Section | Predicate |
| --- | --- |
| 3 | upgrade byte equals 1 and handle `+1270` equals 1 |
| 6 | upgrade byte equals 1 and burn-sector count is zero |
| 0, 1, 2, 4, 5 | reserved-sector count is nonzero and burn-sector count is zero |

These are software map predicates, not hardware write protection. They do not
prove that boot, calibration or settings survive every update. In particular,
the NAND writer has distinct full-erase, header-rewrite, bad-block marking and
user-area relocation paths. A zero burn count skips that section's main body;
it does not make the entire update passive.

`InitRecoverSection 8001a3d0` uses a wrapping 32-bit sum of three recovery
header words, floors the result by runtime sector bytes, then aligns the
sector count to an erase unit with another wrapping addition. Missing handle
or recovery header gives zero sizes. This arithmetic does not recover installed
ROM routing or prove that the package contains a usable independent recovery
area. The supplied package's clear RecoverArea flag is recorded in the earlier
recovery-transport report.

## Actual programming route

`BurnNand 80012e84` consumes update chunks through an input callback. It
selects physical blocks using runtime zone sizes, bad-block status and previous
headers. Its programming branches include normal data, boot headers, recovery
metadata and extended bad-block tables. Handle `+1264 == 1` selects an early
erase loop below the total-block count minus an on-device backup reservation.
The exact physical extents therefore depend on installed geometry, flags,
existing contents and failures; they cannot be listed as fixed camera flash
ranges from the supplied update alone.

The reviewed internal NAND operation numbers are 4 for data read, 5 for data
program, 7 for spare/status program and 8 for block erase. Read data can be
ECC-normalized. `FcuNandOperationEx 8007d668` transforms addressing and spare
metadata according to runtime geometry, so these routines do not expose a
verified raw-flash/ECC image format.

## “User-area backup” writes flash

`NandUserAreaBackup 80012730` is an internal relocation routine. It reads a
selected number of good user blocks into allocated RAM, erases and programs
tail blocks, then writes and verifies marker `01 23 45 67 89 ab cd ef` and a
count. It does not stream a backup to the host. Its allocation is the low 32
bits of `floor(requested_sectors / erase_unit) * erase_unit * 512`.

`NandUserAreaRestore 80012ba8` reads that tail reservation, erases/programs
destination blocks and can erase the tail again afterward. Bad blocks and
retries change selected destinations. Neither operation establishes complete
flash, calibration, spare/ECC or settings backup coverage. Buffer bounds,
tail exhaustion and power-loss restoration are not proved safe.

There is another naming trap: the routine diagnosed as `BlockIsBad`
(`80012370`) can call `BlockMarkBad 80012258` when a returned status flag is 1.
The latter programs spare/status metadata on two geometry-selected pages.
Even that apparently observational check is not an approved read-only API.

`80012510` programs a block, reads it back and compares erase-unit-times-512
bytes. It returns success/failure and can update a RAM status marker. Its
comparison does not turn it into a safe standalone verification request.

## Reproduction and remaining gate

```powershell
python tools/map_update_write_scope.py --output derived/update-write-scope-check.json
python -m unittest discover -s tests -p test_update_write_scope.py -v
```

The ten focused tests cover distinct section predicates, exact-byte flags,
floor-versus-ceil arithmetic, 32-bit wrap, the aligned-boundary special case,
allocation truncation, invalid observations and source rejection. They model
no NAND hardware and execute no camera code.

Complete host backup and recovery remain blocked by safe installed access,
physical geometry and bad-block/ECC representation, verified calibration and
settings coverage, independent reset-to-recovery entry, and a restoration
procedure that can be used without a working application. These stateful
updater routines are research entries, not substitutes for those gates.
