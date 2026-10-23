# S3300 v1.1 type-2 stream decoder

23 October 2026. Offline firmware analysis only. No camera command or firmware
write was used to establish these results.

## Result and independent check

`tools/decode_firmware.py` decodes all **463 blocks** across all four packed ELF
segments into **7,950,592 bytes**. Each block reaches its declared output length,
then emits the end-of-block symbol 256, followed only by zero padding. Payload
sizes are multiples of 128 bytes in this image.

| Carrier offset | Decoded bytes | SHA-256 |
| --- | ---: | --- |
| 0x220314 | 2,630,016 | 2b1582e102904d3357de8a9ce6baf069a0f72b44ba81509573e9945bd74f409d |
| 0x3bd9fc | 3,094,784 | 8efa372c3784a7ee2c98e6ac3208ee68dfd09220c1e8eba6f6a30d2d9ee17a68 |
| 0x5c2bec | 1,601,792 | 59cdac1f2664089c92ff044136be3773aa35e39509602dea379992b28cf57e8e |
| 0x6b55a0 | 624,000 | fc743a0a8c150c958cd807c9ad3452f01680e39eab77de1d5badeb5314c7c6e5 |

An independently implemented table-to-prefix expansion and fixed-DEFLATE
transcoder produced identical segment hashes through native zlib. That check
uses a different table traversal and delegates LZ77 reconstruction to zlib;
see `derived/v1.1-independent/validation.json`. This is strong software
cross-validation, **not a comparison to observed device RAM**.

`evidence/decoded-segments.json` records every block's hash, virtual location,
literal/match counts and verified EOB/padding boundaries. The decoded bytes and
per-segment manifest stay under ignored `derived/v1.1-decoded/`.

## Inferred table instructions

Each table word is little-endian. The payload bitstream is in original byte
order, most-significant bit first. Define these word fields:

- `kind = word & 3`
- `value_or_index = (word >> 2) & 511`
- `tag_or_width = (word >> 11) & 15`
- `count = word >> 15`

### Kind 1: two comb chains

Read one side bit. The left side has `tag_or_width` outcomes; the right side has
`count` outcomes. The child array starts at `value_or_index + 1`, with the left
outcomes before the right outcomes.

On the left chain, zero continues and one terminates. On the right chain, one
continues and zero terminates. The final outcome needs no terminator bit.
For a left chain of three outcomes, the complete codes are `01`, `001`, `000`.
For a right chain of three outcomes, they are `10`, `110`, `111`.

### Kind 0: expanded direct lookup

Peek `tag_or_width` bits and select the word at `value_or_index + peek_value`.
If it is another branch, consume the full peek width and traverse it.
If it is a leaf, consume
`parent_count + leaf_count - length_extra_bits` Huffman bits instead.
This permits repeated table entries for shorter codes.

`length_extra_bits` is zero for distance-table leaves. For literal/length leaves
it is `leaf_tag >> 1` when the leaf tag is odd, otherwise zero.

### Kind 3: leaf

For table A:

- Tag zero: values 0..255 are literals; value 256 is EOB.
- Odd tag: length base is `value`; read `tag >> 1` extra bits and add them.

For table B, the tag is zero and the value encodes a distance base:

- `extra = value >> 2`
- `base = ((value & 3) << extra) + 1`
- `distance = base + read_bits(extra)`

Extra bits are also MSB first. Match lengths and distances fit DEFLATE-family
ranges of 3..258 and 1..32768. Overlapping copies are allowed. The dictionary
carries the last 32 KiB across blocks within one segment and resets between
segments. Resetting at every block fails on the second block's valid reference
to prior output; carrying history validates all 463 streams.

## Reproduce and limits

From the workspace root, with the original firmware and framing evidence present:

```powershell
python tools/decode_firmware.py
python -m unittest discover -s tests -p test_decode_firmware.py -v
```

The decoder refuses existing output/evidence paths. For another independent
run, supply new `--output` and `--evidence` paths. It requires the exact known
v1.1 source SHA-256, validates table/payload hashes against the framing evidence,
bounds reads and copies, checks EOB/zero padding and confirms the source is
unchanged after decoding. Eighteen hand-built synthetic tests cover valid
instruction forms and malformed/truncated input rejection.

This tool **does not** encode streams, build an update package, establish update
checksum coverage, supply recovery, or install any feature. The running camera
is still the separately observed v1.0; this analysis concerns the v1.1 update.
