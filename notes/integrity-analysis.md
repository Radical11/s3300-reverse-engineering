# S3300 update descriptor and integrity analysis

23 October 2026. Offline static analysis of the supplied v1.1 image only.

## Validated structure

`tools/inspect_update_container.py` hashes the source before analysis and
refuses any unsupported or altered image. It does not create firmware output.
Run it with the bundled Python; `--self-test` runs synthetic boundary tests.
Results are in `evidence/update-container.json`; eight complete static MIPS32
listings with original source offsets are under
`derived/update-container-analysis/`.

The boot executable's `DownloadCard` routine supplies a concrete container
entrypoint. At `0x800197d0..0x8001980c` it seeks to **0x100000**, reads **0x40**
bytes, and tests a little-endian u16 at descriptor **+0x3e** against `0x55aa`.
At `0x800199b8..0x800199cc`, that marker causes a further **0x80** bytes to be
read. The supplied image has the marker, so its payload begins at **0x1000c0**.

| Descriptor offset | Actual value | Static interpretation |
| --- | ---: | --- |
| +0x00 | 0x1120000 | Passed as the payload length; exactly equals carrier length minus 0x1000c0 |
| +0x04 | 0x20000 | Read/transfer buffer size passed into `Burn` |
| +0x08 | 3 | Media selector; `BurnGetHandle` dispatches through a table |
| +0x0c | 0 | Post-burn action selector; affects shutdown/reboot handling |
| +0x10/+0x14/+0x18 | 6/2/1 | Arguments passed to `LedInit` |
| +0x3c (u16) | 0 | Hash option flag |
| +0x3e (u16) | 0x55aa | Extended descriptor marker |
| +0x40 | 0 | Copied into burn-handle +0x12f4 when extension marker is present |

At payload start, named `PrintBootHeaderProperties` identifies `MainAddr`
at +0, `MainSize` at +8, `AltAddr` at +0x10 and `AltSize` at +0xc. Their actual
values are 0x600, 0x2000, 0x2600 and 0x108000 respectively.

Adding the first two address fields to payload start yields **0x1006c0** and
**0x1026c0**, matching the separately parsed tiny ELF and first application
ELF. The first size exactly spans their separation. This independently checks
the descriptor/payload alignment. It does not imply the carved ELF extents
equal flash partitions or that all later ELFs have the same role.

The inspector retains the other diagnostic field names and raw offsets,
including resources, user area, virtual sizes and physical-user-area fields.
Their units and runtime transformations have not been fully traced; do not
use those raw values as direct file ranges or a physical flash map.

## MD5 is conditional, and the flag is off in this file

There are two relevant card-download integrity paths:

1. At `0x8001983c..0x80019844`, a **nonzero descriptor u16 +0x3c** enters
   whole-file MD5 verification. `0x80019898..0x800198b8` subtracts 16 from the
   FileX file size and seeks to offset zero. `md5_append` processes that range;
   `0x80019b24..0x80019b80` reads and compares the final 16 bytes.
2. `BurnGetHandle` at `0x8001afdc..0x8001afe0` copies the flag's low byte to
   handle +0x1280. The unnamed card-reader routine at `0x80019c20` tests it at
   `0x80019cf0..0x80019d2c`. When enabled, it reads each chunk plus a 16-byte
   digest and calls `BurnHashInit`, `BurnHashUpdate`, `BurnHashFanalize`.
   With the flag disabled, `0x80019dc0..0x80019e34` seeks back, rereads the
   chunk and compares the two byte sequences. This checks read consistency;
   it is not a cryptographic authenticity check.

The card downloader also explicitly clears its in-memory descriptor flag at
`0x80019a44` after successful whole-file verification and before constructing
the burn handle. Thus the whole-file and per-chunk branches must not be
assumed to run together for card updates. Other download transports may use
the queue-based chunk path; their complete protocols were not decoded here.

The actual descriptor u16 and low byte are both **zero**. The supplied
carrier ends with 16 zero bytes, which **do not** equal
`MD5(carrier[0:file_size-16]) = eb24b55604c86026b2f8dddd6f255bfc`.
This is consistent with the disabled trailer path, not evidence of a damaged
firmware download. No trailer has been removed or regenerated.

The earlier `BurnHashManager` result remains valid: it computes MD5 and uses
a 16-byte comparison. The additional call-site analysis now establishes how
the card reader gates that queue-based path. Neither fact proves the absence
of other checks, signatures, container rules or installed-application checks.

## Restoration and boot-descriptor acceptance limits

`InitRecoverSection` and card/UART/USB download implementations exist in this
boot executable. `BurnMain` selects source paths using hardware-register
values. Those paths have **not** been demonstrated on the real camera; code
presence is insufficient to claim a recovery mode or a usable button sequence.

No confirmed model/version acceptance field was recovered in this pass.
The descriptor has no validated S3300 identifier or v1.1 acceptance field.
Do not label any arbitrary descriptor word as a version or change it.
Matching `S3300` strings elsewhere in resource data does not establish an
update compatibility gate.

These are limits of this boot-downloader pass. Later decoded-application
verification analysis must be consulted for additional package checksum and
model/version acceptance checks; null fields here do not mean such checks
are absent from the installed application.

The official v1.1 package is not an installed-v1.0 flash backup. Device-specific
calibration coverage, actual flash geometry, physical write ranges, boot
entry/recovery accessibility and restoration remain unverified. Flashing and
repacking remain blocked by those concrete unknowns. No camera commands,
target execution or hardware writes were performed.

## Verification performed

- Source SHA-256 matched the known baseline before and after analysis.
- Five baseline structural checks passed: extension marker, exact payload
  length, two independently mapped ELF pointers, and their size adjacency.
- All eight selected windows decoded over their full bounded byte ranges.
  Linear decoding is static evidence, not control-flow or runtime proof.
- Synthetic parser checks exercise ordinary and enabled hash flags, an
  out-of-carrier payload, and three truncated-descriptor cases.

These results advance update-format understanding. They do not yet enable a
recoverable modification or demonstrate a photography performance improvement.
