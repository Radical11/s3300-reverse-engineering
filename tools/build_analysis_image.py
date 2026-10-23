"""Build an analysis-only ELF after two independent decoders agree byte-for-byte.

Retains original virtual addresses and segment permissions. This synthesized
ELF has no camera updater header and is not an installable firmware image.
"""
import argparse
import hashlib
import json
import struct
from io import BytesIO
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def compare_decoders(production, independent):
    if production["source_sha256"] != BASELINE or independent["source_sha256"] != BASELINE:
        raise ValueError("Decoder source identities disagree")
    a = {s["virtual_start"]: s for s in production["segments"]}
    b = {s["virtual_start"]: s for s in independent["segments"]}
    if len(a) != 4 or set(a) != set(b):
        raise ValueError("Expected four uniquely addressed decoded segments")
    matches = []
    for address, left in a.items():
        right = b[address]
        raw = Path(left["file"]).read_bytes()
        native = Path(right["path"]).read_bytes()
        if raw != native or digest(raw) != left["sha256"] or digest(native) != right["sha256"]:
            raise ValueError("Independent decoder byte comparison failed")
        if len(raw) != left["decoded_bytes"] or len(raw) != right["size"]:
            raise ValueError("Decoder output length disagreement")
        if len(left["blocks"]) != len(right["blocks"]):
            raise ValueError("Decoder block count disagreement")
        for x, y in zip(left["blocks"], right["blocks"]):
            pairs = [("index", "index"), ("sha256", "decoded_sha256"),
                     ("eob_bit_end", "end_marker_bit_position"), ("padding_bits", "zero_padding_bits"),
                     ("literal_tokens", "literal_tokens"), ("match_tokens", "match_tokens")]
            if any(x[p] != y[q] for p, q in pairs):
                raise ValueError("Independent token/EOB comparison failed")
            if not x["eob_verified"] or not x["zero_padding_verified"]:
                raise ValueError("Production block is not completely validated")
        matches.append({"virtual_start": address, "size": len(raw), "sha256": digest(raw),
                        "block_count": len(left["blocks"]), "bytes_equal": True,
                        "tokens_end_markers_and_padding_equal": True})
    if sum(s["block_count"] for s in matches) != 463 or sum(s["size"] for s in matches) != 7950592:
        raise ValueError("Unexpected baseline coverage")
    return matches


def build_elf(regions, entry, flags):
    header_size = 52
    ph_size = 32*len(regions)
    result = bytearray(header_size+ph_size)
    phdrs = []
    section_records = []
    strings = bytearray(b"\0")
    for region in regions:
        while len(result) % 16:
            result.append(0)
        offset = len(result)
        body = region["body"]
        result.extend(body)
        address = region["virtual_start"]
        perms = region["permissions"]
        phdrs.append(struct.pack("<8I", 1, offset, address, address, len(body), len(body), perms, 16))
        name_offset = len(strings)
        strings.extend(region["name"].encode()+b"\0")
        sh_flags = 2 | (1 if perms & 2 else 0) | (4 if perms & 1 else 0)
        section_records.append(struct.pack("<10I", name_offset, 1, sh_flags, address, offset, len(body), 0, 0, 16, 0))
        region["analysis_elf_offset"] = offset
    name_offset = len(strings)
    strings.extend(b".shstrtab\0")
    strings_offset = len(result)
    result.extend(strings)
    while len(result) % 4:
        result.append(0)
    sh_offset = len(result)
    result.extend(bytes(40))
    result.extend(b"".join(section_records))
    result.extend(struct.pack("<10I", name_offset, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0))
    ident = b"\x7fELF"+bytes([1, 1, 1, 0])+bytes(8)
    result[:52] = struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 8, 1, entry, 52, sh_offset,
                              flags, 52, 32, len(regions), 40, len(regions)+2, len(regions)+1)
    result[52:52+ph_size] = b"".join(phdrs)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New analysis directory")
    parser.add_argument("--production", type=Path, default=Path("derived/v1.1-decoded/manifest.json"))
    parser.add_argument("--independent", type=Path, default=Path("derived/v1.1-independent/validation.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    production = json.loads(args.production.read_text())
    independent = json.loads(args.independent.read_text())
    comparisons = compare_decoders(production, independent)
    mapping = json.loads((root/"derived/v1.1-mapped/map.json").read_text())
    source = Path(mapping["input_path"])
    raw = source.read_bytes()
    if digest(raw) != BASELINE or mapping["sha256"] != BASELINE:
        raise ValueError("Unsupported source")
    primary = next(i for i in mapping["images"] if i["root_offset"] == 0x1026c0)
    # Bind address metadata directly to original ELF program headers, rather
    # than assuming a source hash also authenticates editable JSON mappings.
    decoded_headers = {}
    for offset in (0x1026c0, 0x2202c0, 0x3bd9a8, 0x5c2b78):
        original_elf = ELFFile(BytesIO(raw[offset:]))
        mapped = next(i for i in mapping["images"] if i["root_offset"] == offset)
        actual_segments = list(original_elf.iter_segments())
        if len(actual_segments) != len(mapped["segments"]):
            raise ValueError("Mapping program-header count differs from source")
        for actual, recorded in zip(actual_segments, mapped["segments"]):
            if any(actual[key] != recorded[key] for key in ("p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags")):
                raise ValueError("Mapping program-header fields differ from source")
            if offset != 0x1026c0:
                decoded_headers[offset+actual["p_offset"]] = dict(actual.header)
        if offset == 0x1026c0:
            if any(original_elf.header[key] != primary["header"][key] for key in ("e_entry", "e_flags")):
                raise ValueError("Primary entry/flags differ from original ELF")
    regions = []
    for segment in primary["segments"]:
        if segment["p_type"] != "PT_LOAD" or segment["p_filesz"] != segment["p_memsz"]:
            raise ValueError("Unexpected primary ELF layout")
        start = primary["root_offset"]+segment["p_offset"]
        regions.append({"name": f".original_{segment['p_vaddr']:08x}",
                        "virtual_start": segment["p_vaddr"], "permissions": segment["p_flags"],
                        "carrier_offset": start, "body": raw[start:start+segment["p_filesz"]]})
    for segment in production["segments"]:
        original = decoded_headers.pop(segment["carrier_offset"], None)
        if original is None or original["p_vaddr"] != segment["virtual_start"] or original["p_memsz"] != segment["decoded_bytes"]:
            raise ValueError("Decoded region differs from original ELF program header")
        regions.append({"name": f".decoded_{segment['virtual_start']:08x}",
                        "virtual_start": segment["virtual_start"], "permissions": original["p_flags"],
                        "carrier_offset": segment["carrier_offset"], "body": Path(segment["file"]).read_bytes()})
    if decoded_headers:
        raise ValueError("Missing decoded source ELF segment")
    regions.sort(key=lambda r: r["virtual_start"])
    for left, right in zip(regions, regions[1:]):
        if left["virtual_start"]+len(left["body"]) > right["virtual_start"]:
            raise ValueError("Overlapping application regions")
    elf = build_elf(regions, primary["header"]["e_entry"], primary["header"]["e_flags"])
    args.output.mkdir(parents=True, exist_ok=False)
    path = args.output/"s3300-v1.1-analysis-only.elf"
    path.write_bytes(elf)
    with path.open("rb") as handle:
        parsed = ELFFile(handle)
        if parsed.header["e_machine"] != "EM_MIPS" or parsed.num_segments() != len(regions):
            raise ValueError("Synthesized ELF failed independent parser check")
        for actual, expected in zip(parsed.iter_segments(), regions):
            if actual["p_vaddr"] != expected["virtual_start"] or actual.data() != expected["body"]:
                raise ValueError("ELF parser roundtrip failed")
    report = {"source_sha256": BASELINE, "analysis_only": True, "installable": False,
              "decoder_comparison": comparisons, "block_count": 463,
              "decoded_bytes": 7950592, "elf_file": str(path.resolve()), "elf_sha256": digest(elf),
              "regions": [{**{k: v for k, v in r.items() if k != "body"},
                           "size": len(r["body"]), "sha256": digest(r["body"])} for r in regions],
              "elf_parser_roundtrip_verified": True, "original_elf_program_headers_verified": True,
              "limitations": ["Synthetic application address map, not an observed RAM dump.",
                              "Holes and absent runtime memory are not synthesized or inferred as BSS.",
                              "Includes the primary application and four decoded segments; excludes the separate updater and tiny MIPS16 loader.",
                              "No update encoder, compatibility bypass, flash or recovery operation."]}
    if digest(source.read_bytes()) != BASELINE:
        raise ValueError("Source changed")
    (args.output/"manifest.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"elf": str(path), "sha256": digest(elf), "segments": len(regions),
                      "independently_validated_blocks": 463, "installable": False}))


if __name__ == "__main__":
    main()
