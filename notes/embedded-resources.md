# Embedded resources and the first on-camera result

24 October 2026. User reports `COOLPIX S3300 Ver. 1.1` after the experimental
update, but no `Welcome studio` label. Thus the update/version transition is
reported complete; activation of our modified label is not established.

## Concrete explanation to investigate

The application contains a **byte-identical 46,392-byte English string table**
at VA **0x8036add4**. The label is at **0x8036e14c**. It is in decoded application
data, separate from the FAT resource file modified in the first candidate.

Dispatcher **0x8000c300** handles fourteen categories. Its category 12 jump-table
entry at 0x8037630c + 12*4 points to **0x8000c344**. That case compares the
requested path to `A:\\String\\Res_Str_Eng_new.bst` at 0x80347cbc, then materializes
the embedded pointer through **0x8000c35c/0x8000c360** and returns it through the
caller's pointer slot. It returns raw size **0x729e (29,342)**, smaller than the
whole matched resource; the size/consumer relationship is unresolved.

These are direct static instructions, not just a duplicated text match. They
strongly suggest that changing only the filesystem copy misses an embedded
resource path, consistent with the user's observation. The full UI call chain
and active resource selection still need verification; this is not proof that
the updater skipped a partition or rejected the modified bytes.

The same distinction matters for photography. Category 8 returns a 960-byte
gamma table at **0x80348344**. It differs in **371 bytes** from the FAT
`GammaLut0.bin`. The gamma loader at **0x8021c7a8** prefers a successful embedded
lookup and reads the filesystem on fallback. Do not tune the FAT table and
assume saved photographs will change. The embedded table's image domain and
capture-mode consumer remain to be traced.

`tools/map_embedded_resources.py` source-checks every allocated resource and
searches authenticated application regions. **9 of 368 files** have at least
one exact whole-file embedded match. Different and partial embedded resources
are outside that count. Evidence: `evidence/embedded-resources.json`.

## Packed-block rewriting now implemented

`tools/rewrite_packed_block.py` preserves original tokens whenever they still
produce the requested bytes. Incompatible literal/match tokens are replaced by
literal codes already present in the original Huffman table. It rejects missing
codes and expansion beyond the original payload allocation. It checks changed
dictionary history and overlapping matches, retaining unchanged continuation
blocks where possible. Tables, framing and payload extents never move.

`tools/build_embedded_label_candidate.py` changes both the embedded and FAT
copies of the marker, then reconstructs the entire affected **151-block,
2,630,016-byte** segment through the production decoder and the independent
prefix-code/native-zlib path. Both outputs differ from stock in exactly five
label data bytes; every other decoded byte is identical. No executable
optimization is claimed.

Only packed block **146** needed new payload bytes. It retained **8,184 tokens**,
replaced four tokens with sixteen literal tokens, and has **622 zero-padding
bits** remaining. Block 147 was checked against the changed history and did not
need new encoded bytes. In the full carrier, 1,861 bytes differ, confined to
that packed payload, the FAT label and the additive checksum.

Local candidate: `derived/embedded-label-candidate-01/NOT-INSTALLABLE-embedded-label.research.bin`.
SHA-256:

```
a222ab366e8f328dc3a3be17b780fa42cba988d3b220487b4fb14a8016a270b4
```

The later [reflash request](reflash-card-trial.md) reproduced this candidate and
staged it through a card reader, with a verified backup and final readback.
Version 1.1 is retained, and the camera now reports 1.1. Same-version acceptance
and completed second flashing remain unverified. No version bypass or marker
activation was introduced. Recovery remains unverified.

Reproduce into a fresh local directory:

```powershell
python tools/map_embedded_resources.py --output evidence/another-embedded-map.json --listings derived/another-embedded-map
python tools/build_embedded_label_candidate.py derived/another-embedded-label
python -m unittest discover -s tests -q
```

The rewrite establishes a controlled way to edit encoded application data,
needed for real firmware integration. A visible resource, a working shooting
look and a measured speed improvement remain separate milestones.
