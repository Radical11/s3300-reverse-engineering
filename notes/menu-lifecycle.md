# Existing Color Options lifecycle

25 October 2026. This extends [state-contracts.md](state-contracts.md) with
creation/registration, navigation, entry-array ownership, parent-return and
event-consumption contracts. It is offline static investigation of the supplied
v1.1 image, not a camera-callable registration API or REA Evidence record.

The generator [map_menu_lifecycle.py](../tools/map_menu_lifecycle.py) checks
the original source/decoded-image identity, 38 selected original instruction
words and every imported instruction in 16 retained direct Ghidra dossiers.
The source-bound result is [menu-lifecycle.json](../evidence/menu-lifecycle.json).
No device, menu, settings or firmware operation is executed.

## Creation and exact registration

View-menu entry `805b0200` sets mode `2100`, resets the shared root state at
`809f05b8..809f05e0`, invokes root builder `805ae9b8` and submenu builder
`805af460`, then opens through `806fbc00` or `806fc624` according to state.
The root's Auto-menu handler `805b1558` uses events `106`/`108` to construct
builder case6 and enter a child through `806fc080(ffff)`, subject to guards.

The Color Options object is explicitly constructed in builder case6 when
runtime mode `80891ea8` is neither2 nor3. Those other modes expose different
menu sets; this object is not universally available at root index4.

| Field | Source-checked value |
| --- | --- |
| Static menu object | `809f0550` |
| Root child slot | 4 in this builder branch |
| Entry count | 5 |
| Initial choice | Current-view byte `+1a` |
| Parent `+10` | Root object `809f05b8` |
| Related pointer `+14` | Self, `809f0550` |
| Render callbacks `+18` / `+1c` | `805c099c` |
| Event handler `+20` | `805ac85c` |
| Entry-array pointer `+24` | Static `809f0820`, 15 bytes, stride3 |
| Dynamic flag `+28` | Zero |
| Text IDs | 560,561,562,563,564 |

The builder clears the 15-byte array and marks the entry corresponding to the
saved choice. These are shared static objects, not allocations transferred to
a custom module. Existing valid selection indices are0..4. Generic helpers
do not prove an initial index is within the list before accessing it.

## Opening and entering a child

`806fbc00` changes global current-menu pointer `80107188`, truncates selection
to16bits, skips entries whose third-byte bit1 (`02`) is set, then invokes the
render callback at `+18`. Navigation wraps to zero at count. An all-disabled
cycle stops back at the original disabled entry; it does not return a special
no-selection result.

`806fc080` chooses a child through the current menu's pointer array at `+0c`.
A static parent indexes that array by four times its current choice; a dynamic
parent takes its first pointer. A null child leaves the caller without entering
one. Argument `ffff` chooses backward from the child's last entry until finding
third-byte bit0 (`01`), stopping at zero. A marked disabled entry can therefore
be restored; this is not a general disabled-entry filter or a cancel token.
An explicit choice instead takes the disabled-skip route.

The selection helpers clear/reapply the `01` marker while preserving other
entry bytes. Parent selected values occupy the low five bits of a status byte;
upper three bits survive. These packed status rules and u16 iteration counters
are constraints on generalized menus, not justification for extending this
existing five-entry menu without further lifecycle proof.

## Dynamic entry arrays have separate ownership

`806fbab0` manages one global buffer at `808917fc`. It frees a previous buffer,
clears that global slot, allocates low32 of `count*3`, zeroes it and assigns it
to current-menu `+24` only when the menu's dynamic flag `+28` is nonzero. This
helper allocates the entry list, not an entire menu object.

Allocation failure logs and returns before replacing the current object's entry
pointer. A rollback to the already-freed old list is not established. Callers
cannot assume that pointer survives replacement or failure. Cleanup `806fba5c`
frees the global list and clears the slot. Parent-return helpers call it when
the current menu is dynamic before switching to the parent and rendering it.
The static Color Options object has dynamic flag zero and does not own a heap
list through this mechanism.

## Preview, commit, parent return and exit differ

| Color handler event | Source-checked behavior |
| --- | --- |
| `103` / `104` | Navigate temporary current choice; apply preview through `807132d0`; wait100ticks; do not store active-view `+1a` |
| `106` / `108` | Store choice in active-view `+1a`, update parent flags, apply colour, call `805a7070` then parent-return `806fc2a4` |
| `105` | Return through `806fc2a4` without that choice commit, then reapply saved active-view colour |
| `102` / `107` / `10e` / `124` | Exit via `805ab198`, which calls cleanup `805a8bf4`; subsequently reapply saved active-view colour |

Do not translate the `105` route into **no persistence write on cancel**.
Whenever a parent pointer exists, `806fc2a4` stages mode-selected state and
calls `80009644`; this includes the `105` parent-return route. The selected
Color Options value is not committed there, but other staged state may still
be written. The transition ignores the writer's returned status. A successful
UI return is not proof of successful media persistence.

Finally, outer dispatcher `805aad94` invokes current menu's `+20` handler
first. Nonzero means consumed; zero allows outer card/system/capture handling
to continue. A custom callback's return convention is therefore part of the
control contract, not a cosmetic detail. Physical button mappings, live mode
values and all concurrent/error paths remain unverified.

## Remaining gate and reproduction

The existing Color Options lifecycle is substantially traced statically. A
supported custom control still needs owned object/list storage, registration
and callback lifetimes, count/resource bounds, physical event routing, Original
bypass, persistent error/cancellation handling and mode transitions. Backup,
reset-independent recovery and executable hook ABI remain required. No safe
custom menu adapter or executable trial is exposed.

```powershell
python tools/map_menu_lifecycle.py --output derived/menu-lifecycle-check.json
python -m unittest discover -s tests -p test_menu_lifecycle.py -v
```

The nine tests use synthetic lists to check wrapping, all-disabled behavior,
marker restoration, preservation of nonselection bytes, packed low-five-bit
status and model/source rejection. Model-domain bounds deliberately reject
unbacked lists; they are not claimed to exist as checks in the camera helper.
