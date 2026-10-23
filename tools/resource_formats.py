"""Documented, bounded resource codecs for offline S3300 development.

ZST code units are not universally Unicode. Text projections are informative;
code_units are authoritative. ZBM pixels are indices, not recovered RGB colours.
Encoding an isolated resource does not create an installable firmware package.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode_zst(raw):
    if len(raw) < 24 or raw[:4] != b"ZST\0":
        raise ValueError("Invalid ZST header")
    count = struct.unpack_from("<I", raw, 4)[0]
    width = struct.unpack_from("<H", raw, 20)[0]
    if not 1 <= count <= 100000 or width not in (1, 2):
        raise ValueError("Unsupported ZST count or code-unit width")
    cursor = 22+2*width
    if cursor > len(raw):
        raise ValueError("Truncated ZST default region")
    entries = []
    for ordinal in range(1, count):
        start = cursor
        if cursor+2 > len(raw):
            raise ValueError("Truncated ZST record length")
        length = struct.unpack_from("<H", raw, cursor)[0]
        cursor += 2
        if length % width or cursor+length+width > len(raw):
            raise ValueError("ZST record outside file or partial code unit")
        body = raw[cursor:cursor+length]
        terminator = raw[cursor+length:cursor+length+width]
        if terminator != bytes(width):
            raise ValueError("Nonzero ZST terminator")
        units = list(body) if width == 1 else list(struct.unpack(">"+"H"*(length//2), body))
        entries.append({"ordinal": ordinal, "resource_offset": start, "byte_length": length,
                        "code_units": units,
                        "text_projection": "".join(chr(unit) for unit in units)})
        cursor += length+width
    if cursor != len(raw):
        raise ValueError("Unparsed bytes after ZST records")
    return {"format": "s3300-zst", "source_sha256": digest(raw), "source_bytes": len(raw),
            "header_hex": raw[:22].hex(), "default_region_hex": raw[22:22+2*width].hex(),
            "count_field": count, "code_unit_width": width, "entries": entries,
            "limitations": ["Ordinal reflects serialized order, not independently verified UI identifier.",
                            "Two-byte units are stored big-endian; several languages use font-specific glyph IDs.",
                            "text_projection is informational. Edit code_units to change an isolated resource."]}


def encode_zst(document):
    if document["format"] != "s3300-zst":
        raise ValueError("Not a ZST resource document")
    header = bytes.fromhex(document["header_hex"])
    width = document["code_unit_width"]
    entries = document["entries"]
    if len(header) != 22 or header[:4] != b"ZST\0" or width not in (1, 2):
        raise ValueError("Invalid ZST document header")
    if struct.unpack_from("<H", header, 20)[0] != width:
        raise ValueError("Conflicting ZST code-unit widths")
    if struct.unpack_from("<I", header, 4)[0] != len(entries)+1 or document["count_field"] != len(entries)+1:
        raise ValueError("Changed entry count requires an understood UI ID contract")
    default = bytes.fromhex(document["default_region_hex"])
    if len(default) != 2*width:
        raise ValueError("Invalid default-region size")
    result = bytearray(header+default)
    for ordinal, entry in enumerate(entries, 1):
        if entry["ordinal"] != ordinal:
            raise ValueError("ZST serialized ordinal changed")
        units = entry["code_units"]
        if any(type(unit) is not int or not 0 <= unit < 1 << (8*width) for unit in units):
            raise ValueError("ZST code unit out of range")
        body = bytes(units) if width == 1 else struct.pack(">"+"H"*len(units), *units)
        if len(body) > 65535:
            raise ValueError("ZST record exceeds 16-bit byte length")
        result.extend(struct.pack("<H", len(body))+body+bytes(width))
    return bytes(result)


def decode_zbm(raw):
    if len(raw) < 32:
        raise ValueError("Truncated ZBM header")
    marker, = struct.unpack_from("<I", raw)
    width, height = struct.unpack_from("<HH", raw, 4)
    bits, = struct.unpack_from("<I", raw, 8)
    if marker != 0 or not width or not height or bits not in (1, 4):
        raise ValueError("Unsupported ZBM geometry")
    stride = (width*bits+7)//8
    if len(raw) != 32+stride*height:
        raise ValueError("ZBM body differs from exact row geometry")
    mask = (1 << bits)-1
    rows = []
    unused = []
    for y in range(height):
        row = raw[32+y*stride:32+(y+1)*stride]
        rows.append([(row[x*bits//8] >> (8-bits-(x*bits % 8))) & mask for x in range(width)])
        padding_bits = (-width*bits) % 8
        unused.append(row[-1] & ((1 << padding_bits)-1))
    return {"format": "s3300-zbm-indices", "source_sha256": digest(raw), "source_bytes": len(raw),
            "header_hex": raw[:32].hex(), "width": width, "height": height,
            "bits_per_index": bits, "row_stride_bytes": stride, "rows": rows,
            "unused_low_row_bits": unused,
            "limitations": ["MSB-first index projection; palette and hardware orientation remain unverified.",
                            "Pixel indices are not RGB colours; preserve the source header and row padding."]}


def encode_zbm(document):
    if document["format"] != "s3300-zbm-indices":
        raise ValueError("Not a ZBM index document")
    header = bytes.fromhex(document["header_hex"])
    if len(header) != 32:
        raise ValueError("Invalid ZBM document header")
    if struct.unpack_from("<I", header)[0] != 0:
        raise ValueError("Unsupported ZBM marker")
    width, height = struct.unpack_from("<HH", header, 4)
    bits, = struct.unpack_from("<I", header, 8)
    if (width, height, bits) != (document["width"], document["height"], document["bits_per_index"]):
        raise ValueError("ZBM document/header geometry disagreement")
    if bits not in (1, 4) or not width or not height or len(document["rows"]) != height:
        raise ValueError("Unsupported ZBM dimensions")
    stride = (width*bits+7)//8
    if document["row_stride_bytes"] != stride or len(document["unused_low_row_bits"]) != height:
        raise ValueError("Invalid ZBM stride/padding metadata")
    result = bytearray(header)
    pad_width = (-width*bits) % 8
    for row, pad in zip(document["rows"], document["unused_low_row_bits"]):
        if len(row) != width or any(type(x) is not int or not 0 <= x < 1 << bits for x in row):
            raise ValueError("Invalid ZBM pixel index")
        if type(pad) is not int or not 0 <= pad < 1 << pad_width:
            raise ValueError("Invalid ZBM unused row bits")
        packed = bytearray(stride)
        for x, value in enumerate(row):
            packed[x*bits//8] |= value << (8-bits-x*bits % 8)
        packed[-1] |= pad
        result.extend(packed)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("export", "import"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.source.resolve() == args.output.resolve():
        raise FileExistsError("Output must be a new, separate file")
    if args.operation == "export":
        raw = args.source.read_bytes()
        if raw.startswith(b"ZST\0"):
            document = decode_zst(raw)
            rebuilt = encode_zst(document)
        elif args.source.suffix.lower() == ".zbm":
            document = decode_zbm(raw)
            rebuilt = encode_zbm(document)
        else:
            raise ValueError("Supported resources: ZST/BST and ZBM")
        if rebuilt != raw:
            raise ValueError("Resource export failed byte-exact roundtrip")
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
        print(json.dumps({"format": document["format"], "byte_exact_roundtrip": True, "source_bytes": len(raw)}))
    else:
        document = json.loads(args.source.read_text(encoding="utf-8"))
        raw = encode_zst(document) if document["format"] == "s3300-zst" else encode_zbm(document)
        with args.output.open("xb") as handle:
            handle.write(raw)
        print(json.dumps({"output_bytes": len(raw), "sha256": digest(raw), "installable_firmware": False}))


if __name__ == "__main__":
    main()
