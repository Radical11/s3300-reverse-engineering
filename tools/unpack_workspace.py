"""Create a lossless, searchable offline S3300 firmware development workspace.

Every source byte is preserved, including unidentified gaps and filesystem
slack. Interpretation coverage is reported separately from byte coverage.
Fresh decoder/resource runs are used; no camera, updater or vendor code runs.
"""
import argparse
from collections import Counter
import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import struct
import subprocess
import sys
import wave

from elftools.elf.elffile import ELFFile
from resource_formats import decode_zst, encode_zst, decode_zbm, encode_zbm
from workspace_functions import add_function_index

ROOT = Path(__file__).resolve().parents[1]
SOURCE_HASH = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
ELF_OFFSETS = (0x200, 0x1006c0, 0x1026c0, 0x2202c0, 0x3bd9a8, 0x5c2b78)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, obj):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(obj, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


def elf_extent(raw, offset):
    """File-backed extent from original headers, not the editable map JSON."""
    elf = ELFFile(BytesIO(raw[offset:]))
    if elf.elfclass != 32 or not elf.little_endian or elf.header["e_machine"] != "EM_MIPS":
        raise ValueError("Unexpected source ELF identity")
    h = elf.header
    extent = max(h["e_ehsize"], h["e_phoff"]+h["e_phnum"]*h["e_phentsize"],
                 h["e_shoff"]+h["e_shnum"]*h["e_shentsize"])
    for segment in elf.iter_segments():
        extent = max(extent, segment["p_offset"]+segment["p_filesz"])
    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_NOBITS":
            extent = max(extent, section["sh_offset"]+section["sh_size"])
    if offset+extent > len(raw):
        raise ValueError("ELF extent exceeds source")
    return elf, extent


def partition_carrier(raw, output):
    owners = [(0, 0x200, "outer-header", "Header fields only partially understood"),
              (0x100000, 0x1000c0, "download-descriptor", "Mapped boot download descriptor"),
              (0x1000c0, 0x1006c0, "boot-properties", "Partially mapped payload header"),
              (0x6fe2c0, len(raw), "resource-volume-available", "Available FAT16 carrier bytes; logical volume tail is absent")]
    elf_records = []
    (output/"elf-original").mkdir()
    for offset in ELF_OFFSETS:
        elf, extent = elf_extent(raw, offset)
        body = raw[offset:offset+extent]
        name = f"elf-original/image-{offset:08x}.elf"
        (output/name).write_bytes(body)
        owners.append((offset, offset+extent, f"elf-{offset:08x}", "Original ELF representation; packed segments decoded separately"))
        elf_records.append({"carrier_offset": offset, "size": extent, "sha256": digest(body), "file": name,
                            "entry": elf.header["e_entry"], "flags": elf.header["e_flags"],
                            "segments": [dict(s.header) for s in elf.iter_segments()]})
    owners.sort()
    cursor = 0
    records = []
    (output/"carrier-parts").mkdir()

    def save(start, end, label, interpretation):
        if end <= start:
            raise ValueError("Empty/inverted partition")
        body = raw[start:end]
        path = f"carrier-parts/{len(records):02d}-{start:08x}-{label}.bin"
        (output/path).write_bytes(body)
        records.append({"offset": start, "end_exclusive": end, "size": len(body),
                        "sha256": digest(body), "file": path, "label": label,
                        "interpretation": interpretation,
                        "zero_bytes": body.count(0), "ff_bytes": body.count(255)})

    for start, end, label, interpretation in owners:
        if start < cursor:
            raise ValueError("Canonical source regions overlap")
        if cursor < start:
            save(cursor, start, "unclassified-gap", "Preserved uninterpreted bytes; not assumed disposable")
        save(start, end, label, interpretation)
        cursor = end
    if cursor != len(raw):
        raise ValueError("Canonical partition does not cover carrier")
    reconstructed = b"".join((output/r["file"]).read_bytes() for r in records)
    if reconstructed != raw:
        raise ValueError("Lossless source-partition roundtrip failed")
    return records, elf_records


def run_tool(output, label, *args):
    result = subprocess.run([sys.executable, str(ROOT/"tools"/args[0]), *map(str, args[1:])],
                            cwd=ROOT, capture_output=True, text=True, timeout=240)
    (output/(label+".log")).write_text(result.stdout+result.stderr, encoding="utf-8")
    if result.returncode:
        raise ValueError(f"{label} failed; inspect its retained log")


def resource_inventory(raw, output, database):
    extraction = json.loads((output/"resource-extraction.json").read_text())
    exports = output/"resource-editable"
    exports.mkdir()
    records = []
    duplicates = {}
    totals = Counter()
    for entry in extraction["entries"]:
        if entry["kind"] != "file":
            continue
        path = output/"resources"/entry["path"]
        body = path.read_bytes()
        original = b"".join(raw[c["carrier_offset"]:c["carrier_offset"]+c["file_bytes"]] for c in entry["chunks"])
        if body != original or len(body) != entry["size"] or digest(body) != entry["sha256"]:
            raise ValueError("Extracted file does not match source chunks")
        record = {"path": entry["path"], "bytes": len(body), "sha256": digest(body),
                  "extension": path.suffix.lower(), "source_chunks": entry["chunks"],
                  "interpretation": "Opaque vendor resource; file extraction verified"}
        duplicates.setdefault(digest(body), []).append(entry["path"])
        doc = None
        if body[:4] == b"ZST\0":
            doc = decode_zst(body)
            if encode_zst(doc) != body:
                raise ValueError("ZST roundtrip differs from original")
            record.update(interpretation="Structurally decoded ZST records; glyph mapping not universal Unicode",
                          records=len(doc["entries"]), code_unit_width=doc["code_unit_width"], byte_exact_roundtrip=True)
            totals["zst_tables"] += 1
            totals["zst_records"] += len(doc["entries"])
            for row in doc["entries"]:
                database.execute("INSERT INTO ui_strings VALUES (?,?,?,?,?)", (entry["path"], row["ordinal"], row["resource_offset"],
                                 doc["code_unit_width"], row["text_projection"]))
        elif path.suffix.lower() == ".zbm":
            doc = decode_zbm(body)
            if encode_zbm(doc) != body:
                raise ValueError("ZBM roundtrip differs from original")
            record.update(interpretation="Packed indexed bitmap; palette/runtime orientation unresolved", width=doc["width"],
                          height=doc["height"], bits_per_index=doc["bits_per_index"], byte_exact_roundtrip=True)
            totals["zbm_bitmaps"] += 1
            # Standard grayscale file preserves actual index values; no RGB
            # palette or on-camera preview correctness is invented.
            projection = exports/(entry["path"]+".indices.pgm")
            projection.parent.mkdir(parents=True, exist_ok=True)
            projection.write_bytes(f"P5\n{doc['width']} {doc['height']}\n{(1 << doc['bits_per_index'])-1}\n".encode()
                                   +bytes(x for row in doc["rows"] for x in row))
        elif path.suffix.lower() == ".wav":
            with wave.open(BytesIO(body), "rb") as audio:
                audio.readframes(audio.getnframes())
                record.update(interpretation="PCM WAV parsed", channels=audio.getnchannels(), sample_rate=audio.getframerate(),
                              sample_width=audio.getsampwidth(), frames=audio.getnframes(),
                              duration_seconds=audio.getnframes()/audio.getframerate())
            totals["wav_files"] += 1
        elif path.suffix.lower() in (".jpg", ".pgm"):
            from PIL import Image
            with Image.open(BytesIO(body)) as picture:
                picture.verify()
                record.update(interpretation="Image parser verified container", image_format=picture.format,
                              width=picture.width, height=picture.height)
            totals["image_files"] += 1
        if doc:
            path = exports/(entry["path"]+".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            write_json(path, doc)
            record["editable_document"] = str(path.relative_to(output)).replace("\\", "/")
        database.execute("INSERT INTO resources VALUES (?,?,?,?,?)", (entry["path"], len(body), digest(body),
                         record["interpretation"], json.dumps(record)))
        records.append(record)
    groups = [{"sha256": key, "paths": paths, "bytes_each": next(r["bytes"] for r in records if r["sha256"] == key)}
              for key, paths in duplicates.items() if len(paths) > 1]
    potential = sum((len(g["paths"])-1)*g["bytes_each"] for g in groups)
    return {"files": records, "counts": dict(totals), "duplicate_groups": groups,
            "duplicate_content_bytes": potential,
            "duplicate_limit": "Identical files are not proven redundant at runtime. Paths, IDs and consumers must be preserved until traced.",
            "logical_volume_complete": extraction["logical_volume_complete_in_carrier"],
            "missing_logical_volume_tail": extraction["logical_volume_missing_tail_bytes"]}


def make_search_index(output, raw, original_elfs, analysis):
    db = sqlite3.connect(output/"research.sqlite")
    db.executescript("""
      CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE regions(name TEXT PRIMARY KEY, virtual_start INTEGER, size INTEGER, sha256 TEXT, file TEXT);
      CREATE TABLE code_strings(region TEXT, region_offset INTEGER, virtual_address INTEGER, text TEXT);
      CREATE TABLE symbols(artifact TEXT, name TEXT, value INTEGER, size INTEGER, type TEXT, binding TEXT);
      CREATE TABLE resources(path TEXT PRIMARY KEY, size INTEGER, sha256 TEXT, interpretation TEXT, metadata_json TEXT);
      CREATE TABLE ui_strings(resource TEXT, ordinal INTEGER, resource_offset INTEGER, code_unit_width INTEGER, text_projection TEXT);
      CREATE INDEX strings_address ON code_strings(virtual_address);
      CREATE INDEX symbol_address ON symbols(value);
      CREATE INDEX ui_ordinal ON ui_strings(resource,ordinal);
    """)
    db.execute("INSERT INTO metadata VALUES (?,?)", ("source_sha256", SOURCE_HASH))
    db.execute("INSERT INTO metadata VALUES (?,?)", ("address_scope", "Per-region application map; separate updater symbols may overlap application addresses"))
    strings = symbols = 0
    image = (output/"analysis/s3300-v1.1-analysis-only.elf").read_bytes()
    for region in analysis["regions"]:
        body = image[region["analysis_elf_offset"]:region["analysis_elf_offset"]+region["size"]]
        db.execute("INSERT INTO regions VALUES (?,?,?,?,?)", (region["name"], region["virtual_start"], len(body),
                   digest(body), "analysis/s3300-v1.1-analysis-only.elf"))
        for match in re.finditer(rb"[ -~]{5,}", body):
            db.execute("INSERT INTO code_strings VALUES (?,?,?,?)", (region["name"], match.start(),
                       region["virtual_start"]+match.start(), match.group().decode("ascii")))
            strings += 1
    for item in original_elfs:
        elf, _ = elf_extent(raw, item["carrier_offset"])
        for section in elf.iter_sections():
            if section["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for symbol in section.iter_symbols():
                db.execute("INSERT INTO symbols VALUES (?,?,?,?,?,?)", (item["file"], symbol.name,
                           symbol["st_value"], symbol["st_size"], symbol["st_info"]["type"], symbol["st_info"]["bind"]))
                symbols += 1
    function_counts = add_function_index(db, output)
    return db, {"ascii_application_strings": strings, "original_symbol_entries": symbols, **function_counts}


def verify_partition(output):
    manifest = json.loads((output/"unpacked.json").read_text())
    if manifest["source_sha256"] != SOURCE_HASH:
        raise ValueError("Unsupported source identity in workspace")
    rebuilt = bytearray()
    for part in manifest["carrier_parts"]:
        relative = PurePosixPath(part["file"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe workspace part path")
        path = (output/Path(*relative.parts)).resolve()
        if not path.is_relative_to(output.resolve()):
            raise ValueError("Workspace part escapes output directory")
        body = path.read_bytes()
        if len(rebuilt) != part["offset"] or len(body) != part["size"] or digest(body) != part["sha256"]:
            raise ValueError("Noncontiguous, changed or missing source component")
        if part["end_exclusive"] != part["offset"]+part["size"]:
            raise ValueError("Component end mismatch")
        rebuilt.extend(body)
    if len(rebuilt) != manifest["source_bytes"] or digest(rebuilt) != SOURCE_HASH:
        raise ValueError("Source reconstruction mismatch")
    return {"byte_exact_source_reassembly": True, "bytes": len(rebuilt), "sha256": digest(rebuilt), "installable_custom_firmware": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source", type=Path, default=ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin")
    parser.add_argument("--verify", action="store_true", help="Reconstruct the original in memory and verify without writing firmware")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.verify:
        print(json.dumps(verify_partition(output)))
        return
    raw = args.source.read_bytes()
    if digest(raw) != SOURCE_HASH:
        raise ValueError("Unsupported/modified source image")
    output.mkdir(parents=True, exist_ok=False)
    print("Preserving complete carrier and original ELF files", flush=True)
    parts, elfs = partition_carrier(raw, output)
    run_tool(output, "map-source", "map_firmware.py", args.source.resolve(), output/"mapped")
    print("Fresh allocated-resource extraction", flush=True)
    run_tool(output, "extract-resources", "extract_resources.py", args.source.resolve(), "--offset", "0x6fe2c0",
             "--output", output/"resources", "--evidence", output/"resource-extraction.json")
    print("Fresh application decode and independent prefix/zlib check", flush=True)
    run_tool(output, "decode", "decode_firmware.py", "--source", args.source.resolve(),
             "--output", output/"decoded", "--evidence", output/"decoded-evidence.json")
    run_tool(output, "independent", "validate_decoded_firmware.py", output/"independent", "--source", args.source.resolve())
    run_tool(output, "analysis", "build_analysis_image.py", output/"analysis", "--production", output/"decoded/manifest.json",
             "--independent", output/"independent/validation.json", "--mapping", output/"mapped/map.json",
             "--source", args.source.resolve())
    analysis = json.loads((output/"analysis/manifest.json").read_text())
    db, index_counts = make_search_index(output, raw, elfs, analysis)
    try:
        inventory = resource_inventory(raw, output, db)
        db.commit()
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
    finally:
        db.close()
    write_json(output/"resource-inventory.json", inventory)
    summary = {"source_sha256": SOURCE_HASH, "source_bytes": len(raw), "source_version": "supplied-v1.1-update",
               "carrier_parts": parts, "original_elfs": elfs,
               "raw_byte_coverage": "Every byte preserved in contiguous source components; reassembly hash checked",
               "decoded_blocks": 463, "decoded_bytes": 7950592,
               "resource_files": len(inventory["files"]), "resource_bytes": sum(r["bytes"] for r in inventory["files"]),
               "resource_formats": inventory["counts"], "search_index": index_counts,
               "duplicate_content_bytes": inventory["duplicate_content_bytes"],
               "logical_resource_volume_complete": inventory["logical_volume_complete"],
               "logical_resource_volume_missing_tail_bytes": inventory["missing_logical_volume_tail"],
               "source_unchanged": digest(args.source.read_bytes()) == SOURCE_HASH,
               "limitations": ["Byte-complete extraction does not mean every format, function or driver is understood.",
                               "Supplied update only; installed v1.0, calibration and runtime memory are not dumped.",
                               "Raw gaps/slack preserved; not proven unnecessary and not removed.",
                               "No custom code encoder, camera update package, installation or recovery path."]}
    if not summary["source_unchanged"]:
        raise ValueError("Source changed during workspace creation")
    write_json(output/"unpacked.json", summary)
    verification = verify_partition(output)
    write_json(output/"verification.json", verification)
    (output/"README.md").write_text(
        "# S3300 offline development workspace\n\n"
        "This is an unpacked v1.1 update, not a dump of installed v1.0.\n\n"
        "- `carrier-parts/`: complete lossless source partition including gaps and slack.\n"
        "- `elf-original/`: six original ELF representations.\n"
        "- `decoded/`, `independent/`, `analysis/`: paired decoder outputs and address-correct analysis ELF.\n"
        "- `resources/`: 368 allocated files with source-chunk verification.\n"
        "- `resource-editable/`: ZST JSON and ZBM index JSON/PGM; byte-exact roundtrips checked.\n"
        "- `research.sqlite`: application strings, symbols, resources and serialized UI string records.\n\n"
        "It also includes compiler-provided function ranges; names and complete code semantics are not recovered.\n"
        "Use the project's query_workspace.py for read-only search/address lookup.\n"
        "Custom glyph mappings, palette and actual UI IDs are not universally recovered.\n"
        "The logical resource volume extends beyond the supplied image. No missing bytes were invented.\n"
        "No source code, runtime speed gain, custom update or recovery procedure is implied.\n", encoding="utf-8")
    print(json.dumps({"carrier_bytes": len(raw), "carrier_parts": len(parts), "original_elfs": len(elfs),
                      "resources": len(inventory["files"]), **inventory["counts"], **index_counts,
                      "byte_exact_source_reassembly": True}), flush=True)


if __name__ == "__main__":
    main()
