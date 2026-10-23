"""Read-only S3300 firmware mapping. Never runs, repacks, or flashes firmware.

Requires the existing pyelftools package. Output must be a new directory.
ELF extents are derived from file-backed tables/segments/sections, not guessed
from the next magic string. Extents do not identify update-container partitions.
"""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect_elf(data, root_offset):
    elf = ELFFile(io.BytesIO(data[root_offset:]))
    if elf.elfclass != 32 or elf.header["e_machine"] != "EM_MIPS":
        raise ValueError("Not an ELF32 MIPS image")
    if elf.num_sections() > 4096 or elf.num_segments() > 256:
        raise ValueError("Unreasonable table count")
    sections = list(elf.iter_sections())
    segments = list(elf.iter_segments())
    if not segments:
        raise ValueError("No program segments")
    extent = max(
        elf.header["e_ehsize"],
        elf.header["e_phoff"] + elf.header["e_phentsize"] * elf.header["e_phnum"],
        elf.header["e_shoff"] + elf.header["e_shentsize"] * elf.header["e_shnum"],
    )
    for section in sections:
        if section["sh_type"] != "SHT_NOBITS":
            extent = max(extent, section["sh_offset"] + section["sh_size"])
    for segment in segments:
        if segment["p_filesz"] > segment["p_memsz"]:
            raise ValueError("Segment file size exceeds memory size")
        extent = max(extent, segment["p_offset"] + segment["p_filesz"])
    if root_offset + extent > len(data):
        raise ValueError("File-backed extent exceeds firmware bounds")
    symbols = []
    for section in sections:
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                value = symbol["st_value"]
                mappings = [
                    root_offset + seg["p_offset"] + value - seg["p_vaddr"]
                    for seg in segments
                    if seg["p_type"] == "PT_LOAD"
                    and seg["p_vaddr"] <= value < seg["p_vaddr"] + seg["p_filesz"]
                ] if symbol["st_shndx"] != "SHN_UNDEF" else []
                symbols.append({"name": symbol.name, "value": value,
                                "size": symbol["st_size"],
                                "type": symbol["st_info"]["type"],
                                "section": symbol["st_shndx"],
                                "firmware_offsets": mappings})
    return {
        "root_offset": root_offset, "root_offset_hex": hex(root_offset),
        "extent": extent, "extent_basis": "maximum file-backed ELF extent",
        "sha256": digest(data[root_offset:root_offset + extent]),
        "elf_class": elf.elfclass, "little_endian": elf.little_endian,
        "header": {key: (dict(value) if key == "e_ident" else value)
                   for key, value in elf.header.items()},
        "segments": [dict(seg.header) for seg in segments],
        "sections": [{"name": sec.name, **dict(sec.header)} for sec in sections],
        "symbol_count": len(symbols), "symbols": symbols,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = args.input.read_bytes()
    if not 0 < len(data) <= 128 * 1024 * 1024:
        parser.error("Input must be nonempty and at most 128 MiB")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    elfs, rejected = [], []
    for match in re.finditer(re.escape(b"\x7fELF"), data):
        offset = match.start()
        try:
            item = inspect_elf(data, offset)
        except Exception as exc:
            rejected.append({"offset": offset, "offset_hex": hex(offset),
                             "reason": str(exc)})
            continue
        item["output_file"] = f"image-{offset:08x}.elf"
        (output / item["output_file"]).write_bytes(data[offset:offset + item["extent"]])
        elfs.append(item)
    strings = [(m.start(), m.group().decode("ascii"))
               for m in re.finditer(rb"[ -~]{8,}", data)]
    with (output / "strings.tsv").open("w", encoding="utf-8") as stream:
        stream.write("firmware_offset_hex\ttext\n")
        for offset, value in strings:
            stream.write(f"0x{offset:08x}\t{value}\n")
    patterns = {
        "platform": r"ThreadX|FileX|LX4180|COACH|Zoran|ZORAN|mipssde|COOLPIX S3300",
        "update": r"[Uu]pgrade|[Ff]irmware|[Cc][Rr][Cc]|[Cc]hecksum|BurnHash|[Ss]ignature|[Rr]ecover",
        "feature_candidates": r"[Ii]nterval|[Tt]imelapse|[Ff]ilter|[Gg]amma|[Ss]epia|[Vv]ignette|[Hh]istogram|[Dd]enois|[Nn]oise [Rr]ed|[Rr]aw|[Bb]racket",
        "debug": r"[Cc]onsole|[Ss]hell|[Uu][Aa][Rr][Tt]|[Jj][Tt][Aa][Gg]|[Pp]erformance|[Pp]ower [Ss]av",
    }
    anchors = {name: [{"firmware_offset": off, "offset_hex": hex(off), "text": s}
                       for off, s in strings if re.search(pattern, s)]
               for name, pattern in patterns.items()}
    report = {
        "method": "Python/pyelftools static analysis; not REA Evidence or runtime observation",
        "input_path": str(args.input.resolve()), "size": len(data), "sha256": digest(data),
        "header_first_512_hex": data[:512].hex(),
        "images": elfs, "rejected_magic_candidates": rejected,
        "ascii_strings_minimum_length": 8, "ascii_string_count": len(strings),
        "anchors": anchors,
        "limitations": [
            "ELF parsing does not establish execution, actual silicon, or update acceptance.",
            "Carved extents exclude container padding and are not flashable update images.",
            "Strings and symbol names are leads; they do not establish exposed functionality.",
            "No image was executed, modified, repacked or written to a camera.",
        ],
    }
    (output / "map.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Confirm the input stayed unchanged throughout analysis.
    if digest(args.input.read_bytes()) != report["sha256"]:
        raise RuntimeError("Input changed during analysis")
    for image in elfs:
        if digest((output / image["output_file"]).read_bytes()) != image["sha256"]:
            raise RuntimeError("Carved image failed digest readback")
    print(json.dumps({"input_sha256": report["sha256"], "images": len(elfs),
                      "symbols": sum(e["symbol_count"] for e in elfs),
                      "rejected_candidates": rejected,
                      "output": str(output)}, indent=2))


if __name__ == "__main__":
    main()
