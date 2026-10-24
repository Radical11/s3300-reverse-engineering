"""Build a local, fixed-extent research image from an explicit JSON patch plan.

Supports allocated FAT resources and decoded application spans. Source bytes,
ELF/framing metadata, original spans and replacements are bound by SHA-256.
Packed segments are independently decoded in full after all edits. This tool
does not register a flash payload, write an SD card, or communicate with USB.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from build_resource_candidate import additive, validate_chain
from decode_firmware import decode_block
from map_development_interfaces import AddressMap
from map_firmware import inspect_elf
from rewrite_packed_block import rewrite_block
from validate_decoded_firmware import transcode
from workspace_functions import load_analysis

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_span(body, offset, replacement, expected_sha256, occupied):
    end = offset+len(replacement)
    if not replacement or offset < 0 or end > len(body):
        raise ValueError("Patch lies outside a nonempty bounded span")
    if any(offset < stop and start < end for start, stop in occupied):
        raise ValueError("Overlapping patch spans")
    original = bytes(body[offset:end])
    if sha(original) != expected_sha256:
        raise ValueError("Original span hash differs")
    if original == replacement:
        raise ValueError("Patch has no changes")
    body[offset:end] = replacement
    occupied.append((offset, end))


def rewrite_segment(source, segment, original, desired):
    """Return fixed-size payload edits and a complete two-decoder proof."""
    start, stop = segment["carrier_offset"], segment["carrier_end_exclusive"]
    if not 0 <= start < stop <= len(source) or sha(source[start:stop]) != segment["packed_sha256"]:
        raise ValueError("Packed segment source binding differs")
    if len(original) != len(desired) or len(original) != segment["elf_p_memsz"]:
        raise ValueError("Decoded segment extent differs")
    cursor, produced = start, 0
    blocks, edits, changed = [], [], []
    for index, block in enumerate(segment["blocks"]):
        if cursor+16 > stop or block["index"] != index:
            raise ValueError("Invalid block order or header extent")
        kind, length, payload_size, a_size, b_size = struct.unpack_from("<IIIHH", source, cursor)
        if kind != 2 or not length or not payload_size or not a_size or not b_size or a_size%4 or b_size%4:
            raise ValueError("Invalid packed block fields")
        a_start, b_start = cursor+16, cursor+16+a_size
        payload_start, end = b_start+b_size, b_start+b_size+payload_size
        if end > stop or produced+length > len(original) or length != block["declared_output_bytes"]:
            raise ValueError("Packed block exceeds its declared extent")
        for name, location, size in (("header", cursor, 16), ("table_a", a_start, a_size),
                                     ("table_b", b_start, b_size), ("payload", payload_start, payload_size)):
            binding = block[name]
            if (binding["carrier_offset"], binding["size"], binding["sha256"]) != (
                    location, size, sha(source[location:location+size])):
                raise ValueError("Block source binding differs")
        a = struct.unpack_from(f"<{a_size//4}I", source, a_start)
        b = struct.unpack_from(f"<{b_size//4}I", source, b_start)
        old, target = original[produced:produced+length], desired[produced:produced+length]
        old_history = original[max(0, produced-32768):produced]
        new_history = desired[max(0, produced-32768):produced]
        payload = source[payload_start:end]
        rewritten = payload
        if old != target or old_history != new_history:
            rewritten, proof = rewrite_block(a, b, payload, old, target, old_history, new_history)
            if rewritten != payload:
                edits.append((payload_start, rewritten))
                changed.append({"index": index, "payload_start": payload_start,
                                "payload_size": payload_size, "source_sha256": sha(payload),
                                "candidate_sha256": sha(rewritten), **proof})
        blocks.append((length, a, b, rewritten))
        cursor, produced = end, produced+length
    if cursor != stop or produced != len(original) or len(blocks) != segment["block_count"]:
        raise ValueError("Incomplete segment coverage")
    production, independent = bytearray(), bytearray()
    for length, a, b, payload in blocks:
        production.extend(decode_block(a, b, payload, length, bytes(production[-32768:]))[0])
        independent.extend(transcode(payload, a, b, length, bytes(independent[-32768:]))[0])
    if production != desired or independent != desired:
        raise ValueError("Full segment independent verification failed")
    return edits, {"virtual_start": segment["elf_p_vaddr"], "decoded_bytes": len(desired),
                   "block_count": len(blocks), "decoded_sha256": sha(desired),
                   "decoded_changed_bytes": sum(a != b for a, b in zip(original, desired)),
                   "full_segment_two_decoders_match": True, "changed_blocks": changed}


def replacement_file(root, patch):
    path = Path(patch["replacement_file"])
    resolved = (root/path).resolve()
    if path.is_absolute() or not resolved.is_relative_to(root.resolve()):
        raise ValueError("Replacement must be a project-relative local file")
    replacement = resolved.read_bytes()
    if sha(replacement) != patch["replacement_sha256"]:
        raise ValueError("Replacement file hash differs")
    return replacement


def validate_segment_elf(source, segment):
    image = inspect_elf(source, segment["elf_root_offset"])
    matches = [s for s in image["segments"] if (
        image["root_offset"]+s["p_offset"], s["p_filesz"], s["p_vaddr"], s["p_memsz"]) == (
        segment["carrier_offset"], segment["carrier_end_exclusive"]-segment["carrier_offset"],
        segment["elf_p_vaddr"], segment["elf_p_memsz"])]
    if len(matches) != 1:
        raise ValueError("Packed segment differs from original ELF program header")


def build(plan, root=ROOT, workspace=None):
    if plan.get("schema_version") != 1 or plan.get("source_sha256") != BASELINE:
        raise ValueError("Unsupported patch schema or baseline")
    patches = plan.get("patches")
    if not isinstance(patches, list) or not 1 <= len(patches) <= 64:
        raise ValueError("Supply one to 64 explicit patches")
    source = (root/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE or struct.unpack_from("<I", source, 44)[0] != additive(source):
        raise ValueError("Original image identity or checksum differs")
    manifest, raw = load_analysis(workspace or root/"derived/unpacked-v1.1-indexed")
    mapped = AddressMap(raw, manifest["regions"])
    framing = json.loads((root/"evidence/packed-segments.json").read_text())
    filesystem = json.loads((root/"evidence/resource-filesystem.json").read_text())
    if framing["input_sha256"] != BASELINE or filesystem["input_sha256"] != BASELINE:
        raise ValueError("Metadata source identity differs")
    candidate = bytearray(source)
    carrier_ranges, virtual_ranges, patch_records = [], [], []
    virtual_segments, resource_paths = {}, set()
    for patch in patches:
        replacement = replacement_file(root, patch)
        record = {k: patch[k] for k in ("kind", "expected_sha256", "replacement_sha256")}
        record["bytes"] = len(replacement)
        if patch["kind"] == "resource":
            if patch["path"] in resource_paths:
                raise ValueError("Duplicate resource patch")
            resource_paths.add(patch["path"])
            entries = [e for e in filesystem["entries"] if e["kind"] == "file" and e["path"] == patch["path"]]
            if len(entries) != 1:
                raise ValueError("Resource path is not unique")
            entry = entries[0]
            body = validate_chain(source, filesystem, entry, patch["expected_sha256"])
            if len(replacement) != len(body) or replacement == body:
                raise ValueError("Resource replacement must change bytes without changing length")
            # Occupied intervals are shared with all carrier writes.
            cursor = 0
            for chunk in entry["chunks"]:
                size, offset = chunk["file_bytes"], chunk["carrier_offset"]
                if body[cursor:cursor+size] != replacement[cursor:cursor+size]:
                    replace_span(candidate, offset, replacement[cursor:cursor+size], sha(body[cursor:cursor+size]),
                                 carrier_ranges)
                cursor += size
            record["path"] = patch["path"]
        elif patch["kind"] == "virtual":
            address = patch["address"]
            if not isinstance(address, int) or isinstance(address, bool):
                raise ValueError("Virtual address must be an integer")
            if any(address < end and start < address+len(replacement) for start, end in virtual_ranges):
                raise ValueError("Overlapping virtual patches")
            selected = [s for s in framing["segments"] if s["elf_p_vaddr"] <= address
                        and address+len(replacement) <= s["elf_p_vaddr"]+s["elf_p_memsz"]]
            if len(selected) != 1:
                raise ValueError("Virtual patch has no unique packed segment")
            segment = selected[0]
            key = segment["carrier_offset"]
            if key not in virtual_segments:
                validate_segment_elf(source, segment)
                original = mapped.read(segment["elf_p_vaddr"], segment["elf_p_memsz"])
                virtual_segments[key] = (segment, original, bytearray(original), [])
            _, _, desired, occupied = virtual_segments[key]
            replace_span(desired, address-segment["elf_p_vaddr"], replacement, patch["expected_sha256"], occupied)
            virtual_ranges.append((address, address+len(replacement)))
            record["address"] = address
        else:
            raise ValueError("Unknown patch kind")
        patch_records.append(record)
    segment_proofs = []
    for segment, original, desired, _ in virtual_segments.values():
        edits, proof = rewrite_segment(source, segment, original, bytes(desired))
        for offset, payload in edits:
            replace_span(candidate, offset, payload, sha(source[offset:offset+len(payload)]), carrier_ranges)
        segment_proofs.append(proof)
    if any(start < 0x30 or start < 0x1000c0 and 0x100000 < end for start, end in carrier_ranges):
        raise ValueError("Protected update header or download descriptor changed")
    struct.pack_into("<I", candidate, 44, additive(candidate))
    allowed = carrier_ranges+[(44, 48)]
    changed = [i for i, (a, b) in enumerate(zip(source, candidate)) if a != b]
    if not changed or any(not any(start <= i < end for start, end in allowed) for i in changed):
        raise ValueError("Carrier changed outside explicit payload extents")
    report = {"name": plan.get("name", "unnamed-research-plan"), "source_sha256": BASELINE,
              "patch_plan_sha256": sha(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()),
              "candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
              "carrier_changed_bytes": len(changed), "patches": patch_records,
              "packed_segment_proofs": segment_proofs, "allowed_carrier_ranges": allowed,
              "version_product_and_download_descriptor_unchanged": True,
              "additive_checksum": additive(candidate), "staged": False, "flashed": False,
              "hardware_behavior_verified": False, "restoration_verified": False,
              "limitations": ["Offline byte validation does not establish runtime semantics, reliability or recovery.",
                              "No candidate is automatically added to the closed staging registry."]}
    return bytes(candidate), report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("output", type=Path, help="New local directory under derived/")
    parser.add_argument("--workspace", type=Path, help="Existing authenticated unpacked workspace")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT/"derived").resolve()) or output.exists():
        raise ValueError("Use a new output directory under derived/")
    candidate, report = build(json.loads(args.plan.read_text(encoding="utf-8")), workspace=args.workspace)
    output.mkdir(parents=True)
    target = output/"NOT-INSTALLABLE-patch-plan.research.bin"
    with target.open("xb") as handle:
        handle.write(candidate)
    if target.read_bytes() != candidate:
        raise ValueError("Local output readback differs")
    (output/"manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
