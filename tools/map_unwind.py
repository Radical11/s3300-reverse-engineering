"""Recover bounded application ranges from legacy MIPS .eh_frame headers.

Does not interpret CFI opcodes, identify every function, or execute firmware.
An independent pyelftools header parser checks every CIE/FDE field used here.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
SECTION_START = 0x807da7a4
SECTION_END = 0x808042cc


def sha(data):
    return hashlib.sha256(data).hexdigest()


def leb(data, cursor, signed=False):
    value = shift = 0
    for _ in range(5):
        if cursor >= len(data):
            raise ValueError("Truncated LEB128")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 127) << shift
        shift += 7
        if not byte & 128:
            if signed and byte & 64:
                value -= 1 << shift
            return value, cursor
    raise ValueError("Oversized LEB128")


def parse_headers(data, address, regions):
    """Return CIEs/FDEs; input excludes the terminating four-byte zero record."""
    from elftools.dwarf.structs import DWARFStructs
    dwarf = DWARFStructs(little_endian=True, dwarf_format=32, address_size=4)
    cursor = 0
    cies = {}
    fdes = []
    while cursor < len(data):
        if cursor+8 > len(data):
            raise ValueError("Truncated frame record")
        length, identity = struct.unpack_from("<II", data, cursor)
        end = cursor+4+length
        if length < 8 or length % 4 or end > len(data):
            raise ValueError("Invalid frame record length")
        raw = data[cursor:end]
        va = address+cursor
        if identity == 0:
            if raw[8] != 1:
                raise ValueError("Unsupported CIE version")
            nul = raw.index(0, 9)
            augmentation = raw[9:nul].decode("ascii")
            if augmentation not in ("", "zP", "zPL"):
                raise ValueError("Unsupported CIE augmentation")
            p = nul+1
            code_alignment, p = leb(raw, p)
            data_alignment, p = leb(raw, p, True)
            return_register = raw[p]
            p += 1
            augmentation_data = b""
            personality = None
            lsda_encoding = None
            if augmentation:
                aug_size, p = leb(raw, p)
                augmentation_data = raw[p:p+aug_size]
                if len(augmentation_data) != aug_size or p+aug_size > len(raw):
                    raise ValueError("Truncated CIE augmentation")
                expected = 6 if augmentation == "zPL" else 5
                if aug_size != expected or augmentation_data[0] != 0:
                    raise ValueError("Unsupported personality encoding")
                personality = struct.unpack_from("<I", augmentation_data, 1)[0]
                if augmentation == "zPL":
                    lsda_encoding = augmentation_data[5]
                    if lsda_encoding != 0:
                        raise ValueError("Unsupported LSDA pointer encoding")
            # All observed augmentation strings omit R: the default FDE
            # encoding is absolute native pointer (DW_EH_PE_absptr = 0).
            independent = dwarf.EH_CIE_header.parse(raw)
            pairs = [(independent["version"], 1),
                     (independent["augmentation"], augmentation.encode()),
                     (independent["code_alignment_factor"], code_alignment),
                     (independent["data_alignment_factor"], data_alignment),
                     (independent["return_address_register"], return_register)]
            if any(a != b for a, b in pairs):
                raise ValueError("Independent CIE header disagreement")
            cies[va] = {"address": va, "record_size": len(raw), "sha256": sha(raw),
                        "version": 1, "augmentation": augmentation,
                        "code_alignment": code_alignment, "data_alignment": data_alignment,
                        "return_register": return_register, "fde_pointer_encoding": 0,
                        "personality_pointer": personality, "lsda_pointer_encoding": lsda_encoding}
        else:
            cie_address = va+4-identity
            if cie_address not in cies:
                raise ValueError("FDE does not reference an earlier parsed CIE")
            if length < 12:
                raise ValueError("Truncated FDE address range")
            start, size = struct.unpack_from("<II", raw, 8)
            independent = dwarf.Dwarf_FDE_header.parse(raw)
            if (independent["CIE_pointer"], independent["initial_location"], independent["address_range"]) != (identity, start, size):
                raise ValueError("Independent FDE header disagreement")
            matches = [r for r in regions if r["virtual_start"] <= start and start+size <= r["virtual_start"]+r["size"]]
            if len(matches) != 1 or not size or start % 4 or size % 4:
                raise ValueError("Function range outside validated source regions or unaligned")
            if not matches[0]["permissions"] & 1:
                raise ValueError("FDE points to a non-executable source region")
            fdes.append({"fde_address": va, "fde_record_size": len(raw), "fde_sha256": sha(raw),
                         "cie_address": cie_address, "start": start, "end_exclusive": start+size,
                         "size": size, "source_region_start": matches[0]["virtual_start"],
                         "source_region_sha256": matches[0]["sha256"],
                         "evidence_type": "Exception-unwind FDE header; no recovered symbol or runtime execution"})
        cursor = end
    ordered = sorted(fdes, key=lambda x: x["start"])
    if len({r["start"] for r in fdes}) != len(fdes):
        raise ValueError("Duplicate FDE function starts")
    if any(a["end_exclusive"] > b["start"] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("Overlapping FDE function ranges")
    return list(cies.values()), ordered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT/"derived/v1.1-analysis-final/manifest.json")
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/unwind-functions.json")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    raw = Path(manifest["elf_file"]).read_bytes()
    source = ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    if manifest["source_sha256"] != BASELINE or sha(source.read_bytes()) != BASELINE or sha(raw) != manifest["elf_sha256"]:
        raise ValueError("Unsupported source/analysis ELF identity")
    if not manifest["original_elf_program_headers_verified"]:
        raise ValueError("Original ELF metadata not verified")
    for r in manifest["regions"]:
        body = raw[r["analysis_elf_offset"]:r["analysis_elf_offset"]+r["size"]]
        if len(body) != r["size"] or sha(body) != r["sha256"]:
            raise ValueError("Source region changed")
    region = next(r for r in manifest["regions"] if r["virtual_start"] <= SECTION_START and SECTION_END+4 <= r["virtual_start"]+r["size"])
    offset = region["analysis_elf_offset"]+SECTION_START-region["virtual_start"]
    size = SECTION_END-SECTION_START
    if raw[offset+size:offset+size+4] != bytes(4):
        raise ValueError("Missing expected terminating zero record")
    cies, functions = parse_headers(raw[offset:offset+size], SECTION_START, manifest["regions"])
    if len(cies) != 279 or len(functions) != 5798:
        raise ValueError("Unexpected baseline CIE/FDE coverage")
    report = {"source_sha256": BASELINE, "analysis_elf_sha256": sha(raw),
              "method": "Bounded little-endian DWARF32/MIPS .eh_frame header walk with independent pyelftools header-field comparison",
              "frame_section": {"start": SECTION_START, "end_exclusive": SECTION_END,
                                "bytes": size, "sha256": sha(raw[offset:offset+size]),
                                "terminator_address": SECTION_END, "terminator_size": 4,
                                "source_region_sha256": region["sha256"]},
              "counts": {"cies": len(cies), "fdes": len(functions),
                         "function_range_bytes": sum(f["size"] for f in functions),
                         "cie_augmentations": dict(Counter(c["augmentation"] for c in cies))},
              "checks": {"records_exactly_cover_bounded_section": True,
                         "all_cie_backreferences_resolve": True, "all_fields_match_pyelftools_headers": True,
                         "all_ranges_in_executable_source_regions": True,
                         "ranges_aligned_nonoverlapping_and_unique": True,
                         "output_sorted_by_start": True,
                         "original_record_order_globally_monotonic": False},
              "cies": cies, "functions": functions,
              "limitations": ["Function range metadata is static compiler evidence, not function names or proof of execution.",
                              "These are all FDEs in the bounded discovered section, not a claim that every application function has unwind metadata.",
                              "No CFI instruction interpretation, stack-unwind execution or exception-table decoding is claimed.",
                              "Full pyelftools CallFrameInfo parsing rejects legacy/nonstandard details; only independently parsed CIE/FDE headers are compared.",
                              "Empty augmentation or zP/zPL omits R; FDE start/range use absolute 32-bit pointers. No other encoding is accepted.",
                              "No changes to target bytes, source firmware, camera state or update packages."]}
    args.output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
