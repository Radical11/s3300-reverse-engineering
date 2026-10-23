# Decoded application landmarks

23 October 2026. Offline analysis; no target execution or camera access.

`tools/map_application.py` verifies the original v1.1 carrier hash, all four
decoded output hashes and lengths, and **byte-for-byte equality with the
independent decoder outputs** before mapping references. It includes the
uncompressed application ELF at carrier 0x1026c0 as well as the four decoded
regions, excluding the separate boot updater so overlapping virtual addresses
do not create misleading references.

Outputs: `evidence/application-landmarks.json` and 33 bounded MIPS32 windows
under `derived/application-landmarks/`. The mapper found 40 selected diagnostic
strings, 33 LUI+ADDIU/ORI address-materialization candidates and six aligned
pointer-valued words. Every saved window decoded completely. Full linear
decoding is not proof of reachable code or correct function boundaries.

All labels below are analyst descriptions, not recovered symbols. Candidate
entries are preceding stack-allocation/saved-return-address patterns. Nearby
JALs are instruction encodings, not a complete call graph; indirect calls and
mixed code/data require further review. These are useful investigation
locations, not established firmware hooks.

## Processing resources: real consumers are now approachable

| Diagnostic/resource string | String VA | Reference site | Candidate entry |
| --- | --- | --- | --- |
| `A:\\GAMMALUT` | 0x80256318 | 0x8021c844 / 0x8021c85c | 0x8021c7a8 |
| Gamma resource version error | 0x802562ac | 0x8021bdb8 / 0x8021bdc0 | 0x8021bd3c |
| `A:\\LCLUT` | 0x8025639c | 0x8021cc34 / 0x8021cc48 | 0x8021cbec |
| `A:\\GAMMADDE1.BIN` | 0x802575d4 | 0x8022a5a8 / 0x8022a5b4 | 0x8022a5a4 |
| IPP gamma mode error | 0x80253a88 | 0x801fe378 / 0x801fe380 | 0x801fe350 |
| IPP gamma still-mode error | 0x80253af0 | 0x801fe3f4 / 0x801fe3fc | 0x801fe3c8 |

The gamma loader already contains caching. At `0x8021c7b0..0x8021c808` it
constructs base **0x808c4eec**, indexes it with `4*id`, tests the size slot and
loads its paired source pointer at +0x28 on a hit. Both hit and miss paths call
the converter candidate at **0x8021bd3c**. A source lookup call uses
**0x8000c300**; fallback size/read candidates are **0x8022fb14** and
**0x8022fbc4**. Those API names and their full calling conventions remain
unresolved. Raw resource caching already exists; whether caching converted
tables would improve measured performance remains untested.

The converter's version-dispatch code at `0x8021bd80..0x8021be0c` distinguishes
0x6200, 0x7200 and 0x8200 through helper **0x8021bc90**. A later path allocates
0x994 and 0x4000 byte work areas. This merits bounded data-format investigation;
the existing 960-byte GammaLut0 resource cannot safely be treated as a plain
256-entry tone curve.

### Important correction: DDE is associated with DLCD

The candidate at **0x8022a5a4** references both
`Load DLCD gamma from HceGetResourceTable is wrong!!!` and
`Load DLCD gamma from file is wrong!!!`. For id zero it allocates 256 bytes,
constructs the identity sequence 0..255 at `0x8022a63c..0x8022a64c`, then calls
**0x800526c4** with selector **0x33**. The nonzero path accepts lengths 0x100
or 0x300 and selects 0x33 or 0x6c at `0x8022a778..0x8022a78c`.

These observations strongly associate the GammaDDE resources with a display
gamma path. They **do not establish a captured-photo colour transform**.
Do not install the earlier offline shadow-lift table into a DDE file expecting
to change saved photographs. Confirming the final display callee and actual
mode selection remains work to do.

## Capture and exposure investigation locations

| Diagnostic | String VA | Reference/candidate |
| --- | --- | --- |
| DirectConvertRawToYuvEx invalid parameters | 0x802540f0 | reference 0x8020599c; candidate 0x80205924 |
| Raw-to-422 scaling start/end | 0x8033f658 / 0x8033f684 | references in candidates 0x80307974 and 0x8030800c |
| StillOnSetCaptureSequence | 0x80258ba0 | reference 0x80239d34; candidate 0x80239d28 |
| AeSetCaptureExpLimit | 0x80258c9c | reference 0x8023a2c4; candidate 0x8023a240 |
| OnSetCaptureExpLimit | 0x80686a4c | reference 0x807996f0; candidate 0x80799698 |
| Capture time, frames still being stored | 0x802af8fc | reference 0x80288e30; preceding prologue 0x80288830 |
| Capture timing Start/Finish | 0x80668c80 / 0x80668cac | references 0x8058630c and 0x80586354; candidate 0x805862ec |

The timing handler candidate parses an operand and conditionally calls
**0x8000fc88** with arguments 0x50/1, or the **0x806f6c9c** and
**0x806f6c94** pair on its stop path. Their contracts and transport exposure
are unverified. The diagnostic that frames are still being stored is an
explicit reason to distinguish capture duration from final storage latency.

The `Main Image IPU RAW-YUV`, `Main Image Pre-YUV Manipulation` and
`Main Image Compression` labels reside at 0x800ba031, 0x800ba081 and
0x800ba0a5. This bounded scanner found no exact direct-address pair or aligned
pointer for them; this is incomplete cross-reference coverage, not evidence
that the labels are unused.

## Profiling, controls and settings

- CPU load checker message at **0x80446aec** has reference
  **0x804034d4/0x804034e8**, within preceding candidate **0x80403468**.
  This path calls address **0x800c7ec4** through a materialized function
  pointer; runtime console/transport access has not been demonstrated.
- Performance-counter descriptions at **0x80443b88**, **0x80443c10**,
  **0x80443c38**, **0x80443c60** and **0x80443c88** appear as pointer-valued
  words in the **0x8042b8f4..0x8042b934** area, at 16-byte intervals.
  This is a command-table candidate, not a validated command schema.
- `ButtonsEvent`, `ButtonsServer`, `ButtonsTrig` are referenced around
  **0x802243ac..0x802243fc**, preceded by candidate **0x80224354**.
  Button codes, debouncing, dispatch contracts and shortcut ownership remain
  unresolved.
- ISO menu candidate **0x805ae17c** references
  `--ViewMenuHandlerISO uPicSize:%d`. Playback-filter candidate **0x805f5c2c**,
  select-colour candidate **0x805f6794**, and save-confirm candidate
  **0x805f6914** reference explicit menu diagnostics. Playback effect paths
  must not be assumed to change live capture processing.
- `Ui/Setup/ui_SetupLib.c` is referenced near **0x80736768**, preceded by
  candidate **0x807366d8**. A setup-library source filename alone does not
  establish a settings handler: this candidate may instead be part of firmware
  update verification. No persistent-settings format, flash wear policy, write
  API or safe settings extension has been established.

## What this enables next

Follow gamma/Lclut loader callers and processor update paths to establish the
actual image domain, format, modes and ownership. Inspect the profiling table
and handlers offline before considering a runtime interface. Use source-bound
basic-block/call-graph analysis to replace heuristic boundaries with verified
entries and contracts. Then develop one minimal, reversible candidate with
explicit memory/timing constraints.

No on-camera speed improvement, creative preset, telemetry measurement,
installation workflow or restoration route is established by these landmarks.
