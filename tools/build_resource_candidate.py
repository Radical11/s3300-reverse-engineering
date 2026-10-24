"""Build a minimal OFFLINE research candidate; no installation capability.

The sole UI experiment is one equal-length English label substitution. FAT
allocation, executable bytes, version and product markers remain unchanged.
Only that label and the known additive checksum may differ. Successful host
validation does not establish device acceptance or recovery.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from resource_formats import decode_zst, encode_zst

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
RESOURCE_PATH = "String/Res_Str_Eng_New.bst"
RESOURCE_HASH = "00fc1a72e59d8bd249720c4c8b67240bec16fd9629fcfd526ebe2aa702a0f671"
ORIGINAL_TEXT = "Welcome screen"
CANDIDATE_TEXT = "Welcome studio"


def digest(body):
    return hashlib.sha256(body).hexdigest()


def additive(data):
    if len(data) < 0x30:
        raise ValueError("Image too short for checksum")
    return (sum(data[:0x2c])+sum(data[0x30:])) & 0xffffffff


def edit_label(body, before=ORIGINAL_TEXT, after=CANDIDATE_TEXT):
    document = decode_zst(body)
    if document["code_unit_width"] != 2 or len(before) != len(after) or not after.isascii():
        raise ValueError("Experiment requires equal-length ASCII label code units")
    matches = [entry for entry in document["entries"] if entry["text_projection"] == before]
    if len(matches) != 1:
        raise ValueError("Expected exactly one original label")
    target = matches[0]
    target["code_units"] = list(map(ord, after))
    result = encode_zst(document)
    if len(result) != len(body):
        raise ValueError("Label edit changed file length")
    reparsed = decode_zst(result)
    changed = [b["ordinal"] for a, b in zip(decode_zst(body)["entries"], reparsed["entries"])
               if a["code_units"] != b["code_units"]]
    if changed != [target["ordinal"]]:
        raise ValueError("Label edit changed unexpected records")
    return result, {"ordinal": target["ordinal"], "record_offset": target["resource_offset"],
                    "byte_length": target["byte_length"], "before": before, "after": after}


def validate_chain(data, evidence, entry, expected_hash=RESOURCE_HASH):
    """Bind mutable extraction metadata back to original BPB, FAT and directory."""
    base = 0x6fe2c0
    boot = data[base:base+512]
    if len(boot) != 512 or boot[510:] != b"\x55\xaa":
        raise ValueError("Resource volume signature missing")
    bps = struct.unpack_from("<H", boot, 11)[0]
    spc, reserved, fats = boot[13], struct.unpack_from("<H", boot, 14)[0], boot[16]
    root_entries, spf = struct.unpack_from("<H", boot, 17)[0], struct.unpack_from("<H", boot, 22)[0]
    if bps != 512 or spc != 2 or fats != 1:
        raise ValueError("Unexpected baseline FAT geometry")
    fat = base+reserved*bps
    root = fat+fats*spf*bps
    start = root+((root_entries*32+bps-1)//bps)*bps
    if (fat, start) != (evidence["fat_offset"], evidence["data_offset"]):
        raise ValueError("Evidence FAT offsets differ from source BPB")
    offset = entry["directory_entry_offset"]
    directory = data[offset:offset+32]
    if len(directory) != 32 or directory[11] & 0x18:
        raise ValueError("Resource entry is not a regular file")
    cluster = struct.unpack_from("<H", directory, 26)[0]
    size = struct.unpack_from("<I", directory, 28)[0]
    if (cluster, size) != (entry["start_cluster"], entry["size"]):
        raise ValueError("Evidence file location differs from source directory")
    remaining = size
    body = bytearray()
    seen = set()
    for chunk in entry["chunks"]:
        if cluster in seen or not 2 <= cluster < 0xfff0:
            raise ValueError("Invalid or cyclic resource FAT chain")
        seen.add(cluster)
        location = start+(cluster-2)*bps*spc
        used = min(remaining, bps*spc)
        if (chunk["cluster"], chunk["carrier_offset"], chunk["file_bytes"], chunk["allocated_bytes"]) != (
                cluster, location, used, bps*spc) or location+used > len(data):
            raise ValueError("Evidence chunk differs from actual FAT chain")
        body.extend(data[location:location+used])
        remaining -= used
        cluster = struct.unpack_from("<H", data, fat+2*cluster)[0]
    if remaining or cluster < 0xfff8 or len(seen) != len(entry["clusters"]):
        raise ValueError("Incomplete or overlong resource FAT chain")
    if digest(body) != expected_hash or entry["sha256"] != expected_hash:
        raise ValueError("Resource is not the expected original resource")
    return bytes(body)


def replace_chunks(source, chunks, replacement):
    result = bytearray(source)
    cursor = 0
    intervals = []
    for chunk in chunks:
        length = chunk["file_bytes"]
        offset = chunk["carrier_offset"]
        if length <= 0 or offset < 0 or offset+length > len(source) or cursor+length > len(replacement):
            raise ValueError("Replacement outside bounded source/file chunks")
        if any(offset < end and start < offset+length for start, end in intervals):
            raise ValueError("Overlapping replacement chunks")
        intervals.append((offset, offset+length))
        result[offset:offset+length] = replacement[cursor:cursor+length]
        cursor += length
    if cursor != len(replacement):
        raise ValueError("Replacement differs from allocated file length")
    return result


def build(source, extraction, mapping):
    if digest(source) != BASELINE or extraction["input_sha256"] != BASELINE or mapping["sha256"] != BASELINE:
        raise ValueError("Unsupported or modified source identity")
    if struct.unpack_from("<I", source, 0x2c)[0] != additive(source):
        raise ValueError("Source additive checksum does not match")
    if len(mapping["images"]) != 6:
        raise ValueError("Expected all six original ELF mappings")
    matching = [entry for entry in extraction["entries"] if entry["path"] == RESOURCE_PATH and entry["kind"] == "file"]
    if len(matching) != 1:
        raise ValueError("Expected one English resource")
    entry = matching[0]
    original = validate_chain(source, extraction, entry)
    replacement, label = edit_label(original)
    if replace_chunks(source, entry["chunks"], original) != source:
        raise ValueError("Stock resource reinsertion is not byte-exact")
    result = replace_chunks(source, entry["chunks"], replacement)
    checksum = additive(result)
    struct.pack_into("<I", result, 0x2c, checksum)
    if len(result) != len(source) or additive(result) != struct.unpack_from("<I", result, 0x2c)[0]:
        raise ValueError("Candidate length/checksum failed")
    differences = [i for i, (a, b) in enumerate(zip(source, result)) if a != b]
    allowed = {i for c in entry["chunks"] for i in range(c["carrier_offset"], c["carrier_offset"]+c["file_bytes"])}
    allowed.update(range(0x2c, 0x30))
    if not differences or any(i not in allowed for i in differences):
        raise ValueError("Unexpected source change")
    image_checks = []
    for image in mapping["images"]:
        start, length = image["root_offset"], image["extent"]
        before, after = source[start:start+length], result[start:start+length]
        if len(before) != length or before != after or digest(before) != image["sha256"]:
            raise ValueError("Original ELF bytes were changed or mapping is inconsistent")
        image_checks.append({"carrier_offset": start, "size": length, "sha256": digest(after), "unchanged": True})
    if source[:0x2c] != result[:0x2c] or source[0x30:0x6fe2c0] != result[0x30:0x6fe2c0]:
        raise ValueError("Protected header, executable or loader range changed")
    report = {"purpose": "Minimal offline label-change/repacking experiment", "source_sha256": BASELINE,
              "candidate_sha256": digest(result), "candidate_bytes": len(result), "resource_path": RESOURCE_PATH,
              "source_resource_sha256": digest(original), "candidate_resource_sha256": digest(replacement),
              "label": label, "changed_byte_count": len(differences),
              "changes": [{"offset": i, "before_u8": source[i], "after_u8": result[i]} for i in differences],
              "additive_checksum": {"offset": 0x2c, "stored": checksum, "calculated": additive(result), "matches": True},
              "stock_resource_reinsertion_byte_exact": True, "original_elfs": image_checks,
              "all_six_original_elfs_unchanged": len(image_checks) == 6,
              "fat_directory_allocation_and_file_length_unchanged": True,
              "version_and_product_marker_unchanged": source[0x28:0x2c]+source[0x30:0x34] == result[0x28:0x2c]+result[0x30:0x34],
              "installable": False, "device_acceptance_verified": False, "recovery_verified": False,
              "limitations": ["Candidate is a host-validated research file, not approved for installation.",
                              "Runtime label selection/rendering, complete acceptance rules and installed-v1.0 compatibility remain unverified.",
                              "No executable optimization, on-camera custom feature, camera upload or flash operation occurs."]}
    return bytes(result), report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New LOCAL research directory")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Refusing to overwrite a research directory")
    source_path = ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    source = source_path.read_bytes()
    extraction = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    mapping = json.loads((ROOT/"derived/v1.1-mapped/map.json").read_text())
    candidate, report = build(source, extraction, mapping)
    args.output.mkdir(parents=True)
    candidate_path = args.output/"NOT-INSTALLABLE-label-test.research.bin"
    candidate_path.write_bytes(candidate)
    extraction_path = args.output/"candidate-resource-extraction.json"
    run = subprocess.run([sys.executable, str(ROOT/"tools/extract_resources.py"), str(candidate_path.resolve()),
                          "--offset", "0x6fe2c0", "--output", str((args.output/"resources").resolve()),
                          "--evidence", str(extraction_path.resolve())], cwd=ROOT, capture_output=True, text=True, timeout=60)
    (args.output/"extraction.log").write_text(run.stdout+run.stderr, encoding="utf-8")
    if run.returncode:
        raise ValueError("Fresh candidate FAT extraction failed; inspect retained log")
    candidate_extraction = json.loads(extraction_path.read_text())
    old_files = {r["path"]: r for r in extraction["entries"] if r["kind"] == "file"}
    new_files = {r["path"]: r for r in candidate_extraction["entries"] if r["kind"] == "file"}
    if set(old_files) != set(new_files) or len(new_files) != 368:
        raise ValueError("Candidate file set differs from baseline")
    changed = [p for p in old_files if old_files[p]["sha256"] != new_files[p]["sha256"]]
    if changed != [RESOURCE_PATH]:
        raise ValueError("Fresh extraction found unexpected changed files")
    rebuilt = (args.output/"resources"/RESOURCE_PATH).read_bytes()
    decoded = decode_zst(rebuilt)
    if encode_zst(decoded) != rebuilt or decoded["entries"][report["label"]["ordinal"]-1]["text_projection"] != CANDIDATE_TEXT:
        raise ValueError("Candidate resource failed independent extraction/record check")
    if digest(source_path.read_bytes()) != BASELINE or candidate_path.read_bytes() != candidate:
        raise ValueError("Source or saved candidate changed during verification")
    report.update(fresh_fat_extraction_passed=True, candidate_file_count=368,
                  unchanged_resource_files=367, exactly_one_expected_resource_changed=True,
                  source_unchanged=True, candidate_file=str(candidate_path.resolve()))
    (args.output/"manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    (args.output/"README.txt").write_text(
        "OFFLINE RESEARCH CANDIDATE - NOT VERIFIED FOR CAMERA INSTALLATION\n"
        "Change: English 'Welcome screen' -> 'Welcome studio'.\n"
        "Only the fixed-size label code units and known additive checksum change.\n"
        "Executable code, version, product marker and FAT allocation are unchanged.\n"
        "Backup/calibration coverage, acceptance, write ranges and recovery are unresolved.\n"
        "No upload/flash/marker activation was attempted. See manifest.json.\n", encoding="utf-8")
    print(json.dumps({k:report[k] for k in ("candidate_sha256", "changed_byte_count", "unchanged_resource_files", "all_six_original_elfs_unchanged", "installable")}))


if __name__ == "__main__":
    main()
