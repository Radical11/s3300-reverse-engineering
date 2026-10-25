"""Independent type-2 decoding check using expanded prefix codes and native zlib.

This deliberately does not import the production decoder. It expands the table
graphs into complete prefix-code maps, reads tokens through those maps, and
transcodes them to RFC 1951 fixed Huffman blocks. Python's native zlib performs
all output reconstruction and window checks. No firmware or camera is written.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
LENGTH_BASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LENGTH_EXTRA = [0]*8+[1]*4+[2]*4+[3]*4+[4]*4+[5]*4+[0]
DISTANCE_BASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DISTANCE_EXTRA = [0]*4+[i for i in range(1,14) for _ in range(2)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def expand_table(words, is_distance=False):
    """Expand each branch once per path; prove aliases agree on consumed bits."""
    result = {}

    def add(code, leaf):
        if code in result and result[code] != leaf:
            raise ValueError("Inconsistent lookahead aliases")
        result[code] = leaf

    def walk(node, prefix, ancestors):
        if node in ancestors or not 0 <= node < len(words) or len(prefix) > 32:
            raise ValueError("Invalid or cyclic table graph")
        word = words[node]
        kind, base, width, count = word & 3, (word >> 2) & 511, (word >> 11) & 15, word >> 15
        ancestors = ancestors | {node}
        if kind == 3:
            add(prefix, (base, width, count))
        elif kind == 1:
            if not width or not count:
                raise ValueError("Empty compact branch")
            for side, size, start in ((0, width, base+1), (1, count, base+1+width)):
                for index in range(size):
                    # Two opposed combs. The final child needs no stop bit.
                    suffix = str(side)*(index+1)
                    if index < size-1:
                        suffix += str(1-side)
                    walk(start+index, prefix+suffix, ancestors)
        elif kind == 0:
            if not width or base+(1 << width) > len(words):
                raise ValueError("Direct lookup exceeds table")
            for slot in range(1 << width):
                target = words[base+slot]
                bits = format(slot, f"0{width}b")
                if target & 3 == 3:
                    value, flags, residual = (target >> 2) & 511, (target >> 11) & 15, target >> 15
                    extra = (flags >> 1) if flags & 1 and not is_distance else 0
                    consumed = count+residual-extra
                    if not 0 < consumed <= width:
                        raise ValueError("Invalid direct lookup consumption")
                    add(prefix+bits[:consumed], (value, flags, residual))
                else:
                    walk(base+slot, prefix+bits, ancestors)
        else:
            raise ValueError("Unknown table instruction")

    walk(0, "", set())
    trie = {}
    for code, leaf in sorted(result.items()):
        node = trie
        for bit in code:
            if "leaf" in node:
                raise ValueError("Prefix collision")
            node = node.setdefault(bit, {})
        if node or "leaf" in node:
            raise ValueError("Duplicate or non-prefix-free code")
        node["leaf"] = leaf
    return trie, result


class SourceBits:
    def __init__(self, data):
        self.data, self.position = data, 0

    def read(self, width):
        if self.position+width > len(self.data)*8:
            raise ValueError("Encoded payload truncated")
        value = 0
        for _ in range(width):
            value = (value << 1) | ((self.data[self.position//8] >> (7-self.position%8)) & 1)
            self.position += 1
        return value

    def symbol(self, trie):
        while "leaf" not in trie:
            trie = trie.get(str(self.read(1)))
            if trie is None:
                raise ValueError("Unused Huffman prefix")
        return trie["leaf"]


class DeflateBits:
    def __init__(self):
        self.bytes, self.pending, self.count = bytearray(), 0, 0

    def little(self, value, width):
        if value < 0 or value >= 1 << width:
            raise ValueError("DEFLATE value out of range")
        self.pending |= value << self.count
        self.count += width
        while self.count >= 8:
            self.bytes.append(self.pending & 255)
            self.pending >>= 8
            self.count -= 8

    def code(self, value, width):
        for shift in range(width-1, -1, -1):
            self.little((value >> shift) & 1, 1)

    def literal_length(self, symbol):
        if 0 <= symbol <= 143:
            self.code(0x30+symbol, 8)
        elif symbol <= 255:
            self.code(0x190+symbol-144, 9)
        elif symbol <= 279:
            self.code(symbol-256, 7)
        elif symbol <= 287:
            self.code(0xc0+symbol-280, 8)
        else:
            raise ValueError("Invalid DEFLATE symbol")

    def finish(self):
        if self.count:
            self.bytes.append(self.pending)
        return bytes(self.bytes)


def transcode(payload, table_a, table_b, expected_size, dictionary):
    a, codes_a = expand_table(table_a)
    b, codes_b = expand_table(table_b, is_distance=True)
    bits = SourceBits(payload)
    target = DeflateBits()
    target.little(1, 1)  # final block
    target.little(1, 2)  # fixed Huffman
    literals = matches = 0
    produced = 0
    while True:
        value, flags, _ = bits.symbol(a)
        if flags == 0:
            if value == 256:
                target.literal_length(256)
                break
            if value > 255:
                raise ValueError("Invalid literal")
            target.literal_length(value)
            literals += 1
            produced += 1
        elif flags & 1:
            extra = flags >> 1
            index = next((i for i, pair in enumerate(zip(LENGTH_BASE, LENGTH_EXTRA))
                          if pair == (value, extra)), None)
            if index is None:
                raise ValueError(f"Non-RFC1951 length base {value}/{extra}")
            extension = bits.read(extra)
            target.literal_length(257+index)
            target.little(extension, extra)
            length = value+extension
            distance_value, distance_flags, _ = bits.symbol(b)
            if distance_flags:
                raise ValueError("Unexpected distance flags")
            extra = distance_value >> 2
            if extra > 13:
                raise ValueError("Distance extra bits exceed RFC1951 window")
            base = ((distance_value & 3) << extra)+1
            index = next((i for i, pair in enumerate(zip(DISTANCE_BASE, DISTANCE_EXTRA))
                          if pair == (base, extra)), None)
            if index is None:
                raise ValueError(f"Non-RFC1951 distance base {base}/{extra}")
            extension = bits.read(extra)
            target.code(index, 5)
            target.little(extension, extra)
            produced += length
            matches += 1
        else:
            raise ValueError("Unexpected literal/length flags")
        if produced > expected_size:
            raise ValueError("Token output exceeds declared size")
    end = bits.position
    if produced != expected_size:
        raise ValueError("End marker at incorrect output size")
    # Reject any nonzero trailing bits, including the partially consumed byte.
    if bits.read((-bits.position) % 8) or any(payload[bits.position//8:]):
        raise ValueError("Nonzero data after end marker")
    stream = target.finish()
    kwargs = {"zdict": dictionary[-32768:]} if dictionary else {}
    inflater = zlib.decompressobj(wbits=-15, **kwargs)
    result = inflater.decompress(stream, expected_size+1)
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or len(result) != expected_size:
        raise ValueError("Independent zlib output incomplete or incorrectly sized")
    return result, {"end_marker_bit_position": end, "zero_padding_bits": len(payload)*8-end,
                    "literal_tokens": literals, "match_tokens": matches,
                    "prefix_codes_a": len(codes_a), "prefix_codes_b": len(codes_b),
                    "decoded_sha256": sha(result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory for independent outputs and evidence")
    parser.add_argument("--source", type=Path, help="Local copy of the hash-bound original v1.1 source")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    framing = json.loads((root/"evidence/packed-segments.json").read_text())
    source = args.source or root/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    data = source.read_bytes()
    if sha(data) != BASELINE or framing["input_sha256"] != BASELINE:
        raise ValueError("Unsupported source identity")
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for segment in framing["segments"]:
        output = bytearray()
        blocks = []
        for block in segment["blocks"]:
            tables = []
            for key in ("table_a", "table_b"):
                region = block[key]
                body = data[region["carrier_offset"]:region["carrier_offset"]+region["size"]]
                if sha(body) != region["sha256"]:
                    raise ValueError("Framing table identity mismatch")
                tables.append(struct.unpack("<"+"I"*(len(body)//4), body))
            region = block["payload"]
            payload = data[region["carrier_offset"]:region["carrier_offset"]+region["size"]]
            if sha(payload) != region["sha256"]:
                raise ValueError("Framing payload identity mismatch")
            decoded, record = transcode(payload, *tables, block["declared_output_bytes"], bytes(output[-32768:]))
            output.extend(decoded)
            blocks.append({"index": block["index"], **record})
        if len(output) != segment["elf_p_memsz"]:
            raise ValueError("Segment output size mismatch")
        path = args.output/f"segment-{segment['elf_p_vaddr']:08x}.bin"
        path.write_bytes(output)
        records.append({"virtual_start": segment["elf_p_vaddr"], "path": str(path.resolve()),
                        "size": len(output), "sha256": sha(output), "blocks": blocks})
        print(json.dumps({k: records[-1][k] for k in ("virtual_start", "size", "sha256")}), flush=True)
    if sha(source.read_bytes()) != BASELINE:
        raise ValueError("Source changed during validation")
    report = {"method": "Independent table-graph expansion, prefix token reader, RFC1951 fixed-Huffman transcoding, native zlib output reconstruction",
              "source_sha256": BASELINE, "source_unchanged": True,
              "block_count": sum(len(s["blocks"]) for s in records), "segments": records,
              "limitations": ["Independent implementations share an inferred format; no observed RAM dump is available.",
                              "No encoder for the camera format, repacking, camera write or restoration validation."]}
    (args.output/"validation.json").write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    main()
