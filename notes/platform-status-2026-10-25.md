# Development platform status - 25 October 2026

Later checkpoint: see [backup/recovery follow-up](backup-recovery-progress-2026-10-25.md).
That pass preserves49 exposed files and adds one focused writer, bringing the
current combined index to19,527 functions and the interface catalog to53 entries.
Counts and verification below describe the earlier capture/menu/updater pass.

This is the current entry point for the capture/menu/updater follow-up. Earlier
notes retain their original observations and narrower coverage. Resource-ready
passes for the reviewed Amber workflow; code-ready and overall completion remain
false. The current machine-readable gates are in
[`evidence/development-readiness.json`](../evidence/development-readiness.json).

## Work that can be used now

- `python s3300.py browse` opens the local read-only workbench. Search hardware
  capabilities and unknowns, interface contracts, functions, calls and research
  reports without unpacking or rerunning Ghidra.
- The retained combined function index contains 19,526 entries in four code
  namespaces. Three additional packed carriers remain inventory-only. All seven
  image identities stay distinct. The native application index and direct
  Ghidra projects/exports remain available separately.
- Forty-two recovered interface entries distinguish static observations from
  callable adapters. All camera-callable flags remain false. The integer-only
  creative-look SDK is buildable and emulated independently.
- Ten focused maps can be recomputed using `research-map`; they authenticate
  source bytes, selected native instructions, tool versions and verifier hashes.
  Direct Ghidra results remain separate from REA Evidence.
- The guide covers setup, architecture, interface lookup, text/artwork/Amber,
  SDK development, packaging, camera testing, rollback and unresolved recovery.
  Local vendor listings and personal samples are excluded from source archives.

## New findings that affect modifications

The physical scanner, debounce and event routing are traced through capture mode
selection to StillCaptMain, FileCreator and FileCompressor/JPEG. The runtime
UI/capture object and persistent view bank are different pointers. This is a
static route; live mode, switch wiring and timing have not been observed.

JPEG input kind at argument+4 differs from address-layout selector at+8. A layout
selector of one cannot be interpreted as 420 input. Conditional pitch and rounding
are recovered; component order/range, live allocation extent and cache/ownership
rules still block an RGB8 camera adapter.

Color Options is a static five-entry registration. Dynamic menu entries share
one allocation owner. Cancel/return may stage and persist other settings, and
the existing UI ignores a write failure. A custom menu must preserve this
lifecycle and explicitly handle its own unsupported cases.

Updater sections use runtime erase geometry, protected-section predicates and
bad-block handling. The on-device user-area backup/restore routines erase and
program flash. Some bad-block checks may also write spare metadata. These are
not passive host reads or a complete host backup procedure.

## Remaining gates and their dependencies

1. Establish a passive, bounded way to acquire the installed memory/flash map,
   calibration/settings and required ECC/spare metadata. Normal PTP does not
   provide a verified bridge to the internal debug memory reader.
2. Establish reset-independent software entry and demonstrate recovery without
   deliberately corrupting the camera. The supplied update omits ROM bytes
   needed to prove reset-to-loader behavior. Normal menu-based rollback does
   not meet this gate.
3. Resolve live buffer domain, extent, lifetime, synchronization and cache/DMA
   ownership. Then implement a narrow adapter, placement/hook and selectable
   control with Original bypass and persistence.
4. Only after those gates pass, perform an executable camera trial and repeated
   matched performance measurements. No performance improvement is claimed now.

No camera command, new trial registration or flash operation was performed in
this follow-up. Existing camera results remain tied to their original evidence;
the exact installed firmware bytes have not been read back.

## Verification

[`complete-platform-validation-2026-10-25.json`](../evidence/complete-platform-validation-2026-10-25.json)
records ten rechecked maps, 395 passing workspace tests and desktop/mobile
browser checks. The browser run exposed a null-address contract matching bug;
the implementation and regression fixture were corrected before the passing
rerun. Local Linux execution is still unverified: Docker Desktop's Linux engine
was unavailable, and no VM configuration was changed. The repository retains
Windows/Ubuntu CI definitions; a definition is not a completed CI run.
