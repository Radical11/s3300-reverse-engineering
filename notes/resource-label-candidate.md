# First minimal firmware research candidate

24 October 2026. User priority: develop firmware before further manual capture
benchmarks. The 16 MP/8 MP shooting comparison can wait. The later
[USB trial](usb-flash-trial.md) staged this file and verified a full readback;
the user reports updating to v1.1. Completion and label activation are pending.

## Concrete candidate

`tools/build_resource_candidate.py` produces a local full-size research copy
of the supplied v1.1 carrier. Its sole presentation experiment changes the
English resource label **Welcome screen → Welcome studio**. It is a small
visible test marker for future installation verification, not an implemented
creative mode, algorithm improvement or proven runtime label replacement.

The candidate is at
`derived/label-test-candidate-01/NOT-INSTALLABLE-label-test.research.bin`.
It contains 19,005,632 bytes. SHA-256:

```
c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312
```

Only **six bytes** differ from stock: five low bytes of existing two-byte
English code units, plus one byte in the known additive checksum field. The
label has the same character and byte length. No record offsets, entry count,
FAT links, directory entries, file sizes, executable image bytes, version or
product marker change. The checksum changes from 0x5221fe2a to **0x5221fe42**.

## Checks actually completed

- Exact baseline source SHA-256 required; source left unchanged.
- Source BPB, FAT chain and target directory entry checked against extraction
  metadata rather than trusting replacement offsets alone.
- Reinserting the original resource reproduced the source byte-for-byte.
- All six original ELF files are byte-identical to stock.
- Candidate re-extracted through the FAT parser: 368 files, **367 unchanged**,
  exactly the intended English resource changed.
- Candidate ZST table reparsed and re-encoded byte-for-byte, with the intended
  label and all other records preserved.
- Full-image difference checked against the resource/checksum allowlist.
- A separate validator reconstructed the expected result directly from the
  unique original byte pattern and reparsed original ELF program headers. It
  imported neither the builder nor its resource codec, manifest or FAT map.
  Its expected whole-image bytes matched the candidate exactly.

The validator evidence is `evidence/label-test-independent-validation.json`;
the builder metadata is retained with the local candidate. Raw vendor firmware
and extracted resources stay under the project's existing Git exclusions.

## Reproduce locally

Use absent output directories and evidence paths:

```powershell
python tools/build_resource_candidate.py derived/another-label-test
python tools/validate_resource_candidate.py derived/another-label-test/NOT-INSTALLABLE-label-test.research.bin --output evidence/another-label-test-validation.json
python -m unittest discover -s tests -q
```

Neither tool has an upload, card-copy, firmware-execution or flash command.
The research filename and directory are not the camera's normal update path.
These tools establish controlled file construction; they do not establish
complete authenticity/acceptance rules or recovery.

## Installation is unfinished

The supplied carrier is v1.1 while the connected camera reports v1.0. Its
installed acceptance behavior, complete backup/calibration coverage, exact
write ranges and restoration are not verified. The existing NAND-dump command
has a fixed range and skips failed sectors without placeholders, so it cannot
yet be treated as a complete restorable backup. See `restore-path.md`.

The user explicitly requested an experimental flash despite these unresolved
recovery questions. The file is now verified on the card through USB, and the
user reports that updating has started. Record completion, version, modified
label, startup, menu display and ordinary capture before adding larger changes.
The manual shooting baseline is deferred. Foundational file validation and
recovery work remain prerequisites for a validated release.
