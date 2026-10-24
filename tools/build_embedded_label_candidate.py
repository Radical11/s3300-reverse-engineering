"""Build an OFFLINE embedded-and-filesystem label candidate with fixed extents.

Not an installation command. Does not change version/acceptance policy, send
USB commands or write a card. On-camera label activation remains unverified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decode_firmware import decode_block
from map_development_interfaces import AddressMap
from rewrite_packed_block import rewrite_block
from validate_decoded_firmware import transcode
from workspace_functions import load_analysis

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
LABEL_VA = 0x8036e14c


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory under ignored derived/")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT/"derived").resolve()) or output.exists():
        raise ValueError("Use a new local directory under derived/")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Unsupported source")
    manifest, raw = load_analysis(ROOT/"derived/unpacked-v1.1-indexed")
    mapped = AddressMap(raw, manifest["regions"])
    framing = json.loads((ROOT/"evidence/packed-segments.json").read_text())
    if framing["input_sha256"] != BASELINE:
        raise ValueError("Framing identity differs")
    before, after = "Welcome screen".encode("utf-16-be"), "Welcome studio".encode("utf-16-be")
    if len(before) != len(after) or mapped.read(LABEL_VA, len(before)) != before or source.count(before) != 1:
        raise ValueError("Label identity differs")
    candidate = bytearray(source)
    file_label = source.index(before)
    candidate[file_label:file_label+len(after)] = after
    selected = [s for s in framing["segments"] if s["elf_p_vaddr"] <= LABEL_VA
                and LABEL_VA+len(before) <= s["elf_p_vaddr"]+s["elf_p_memsz"]]
    if len(selected) != 1:
        raise ValueError("Label has no unique packed segment")
    segment = selected[0]
    original = mapped.read(segment["elf_p_vaddr"], segment["elf_p_memsz"])
    desired = bytearray(original)
    label_offset = LABEL_VA-segment["elf_p_vaddr"]
    desired[label_offset:label_offset+len(after)] = after
    cursor, produced = segment["carrier_offset"], 0
    changed_blocks = []
    blocks = []
    for block in segment["blocks"]:
        if cursor != block["header"]["carrier_offset"]:
            raise ValueError("Framing not contiguous")
        kind, length, payload_size, a_size, b_size = struct.unpack_from("<IIIHH", source, cursor)
        a_start, b_start = cursor+16, cursor+16+a_size
        payload_start, end = b_start+b_size, b_start+b_size+payload_size
        if kind != 2 or length != block["declared_output_bytes"] or not a_size or not b_size or a_size%4 or b_size%4:
            raise ValueError("Framing fields differ")
        if end > segment["carrier_end_exclusive"]:
            raise ValueError("Block outside source segment")
        for name, start, size in (("table_a", a_start, a_size), ("table_b", b_start, b_size),
                                   ("payload", payload_start, payload_size)):
            binding = block[name]
            if (binding["carrier_offset"], binding["size"], binding["sha256"]) != (start, size, sha(source[start:start+size])):
                raise ValueError("Source-bound block metadata differs")
        a, b = struct.unpack_from(f"<{a_size//4}I", source, a_start), struct.unpack_from(f"<{b_size//4}I", source, b_start)
        old = original[produced:produced+length]
        target = bytes(desired[produced:produced+length])
        old_history = original[max(0, produced-32768):produced]
        new_history = bytes(desired[max(0, produced-32768):produced])
        payload = source[payload_start:end]
        if old != target or old_history != new_history:
            print(f"Rewriting/checking packed block {block['index']} with original allocation", flush=True)
            rewritten, proof = rewrite_block(a, b, payload, old, target, old_history, new_history)
            if rewritten != payload:
                candidate[payload_start:end] = rewritten
                changed_blocks.append({"index": block["index"], "virtual_start": segment["elf_p_vaddr"]+produced,
                                       "payload_start": payload_start, "payload_size": payload_size,
                                       "source_payload_sha256": sha(payload), "candidate_payload_sha256": sha(rewritten), **proof})
        blocks.append((produced, length, a, b, payload_start, end))
        cursor, produced = end, produced+length
    if cursor != segment["carrier_end_exclusive"] or produced != len(desired) or not changed_blocks:
        raise ValueError("Incomplete or empty application rewrite")
    production, independent = bytearray(), bytearray()
    for position, length, a, b, start, end in blocks:
        production.extend(decode_block(a, b, bytes(candidate[start:end]), length, bytes(production[-32768:]))[0])
        independent.extend(transcode(bytes(candidate[start:end]), a, b, length, bytes(independent[-32768:]))[0])
    if production != desired or independent != desired:
        raise ValueError("Whole-segment independent verification failed")
    checksum = (sum(candidate[:44])+sum(candidate[48:])) % (1 << 32)
    candidate[44:48] = checksum.to_bytes(4, "little")
    differences = [i for i, (a, b) in enumerate(zip(source, candidate)) if a != b]
    ranges = [(44,48), (file_label, file_label+len(after))]+[(b["payload_start"], b["payload_start"]+b["payload_size"]) for b in changed_blocks]
    if any(not any(start <= i < end for start, end in ranges) for i in differences):
        raise ValueError("Unexpected carrier difference outside allowlist")
    decoded_changes = [i for i, (a, b) in enumerate(zip(original, desired)) if a != b]
    if any(not label_offset <= i < label_offset+len(after) for i in decoded_changes):
        raise ValueError("Decoded changes outside label")
    report = {"purpose": "Offline embedded-and-filesystem label rewrite; no upload or version bypass",
              "source_sha256": BASELINE, "candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
              "filesystem_label_offset": file_label, "embedded_label_va": LABEL_VA,
              "decoded_changed_bytes": len(decoded_changes), "decoded_changed_virtual_addresses": [segment["elf_p_vaddr"]+i for i in decoded_changes],
              "carrier_changed_bytes": len(differences), "allowed_changed_carrier_ranges": ranges,
              "changed_blocks": changed_blocks, "all_original_block_extents_and_tables_preserved": True,
              "full_segment_production_and_independent_zlib_match": True,
              "verified_decoded_segment_bytes": len(desired), "verified_block_count": len(blocks),
              "version_unchanged_0x28": struct.unpack_from("<I", candidate, 40)[0],
              "checksum": checksum, "hardware_label_activation_verified": False,
              "same_version_installation_verified": False, "restoration_verified": False,
              "staged": False, "flashed": False,
              "limitations": ["Installed camera now reports v1.1; repeat-update policy is unresolved.",
                              "Source-bound static dispatcher suggests this embedded copy matters; runtime UI selection remains unverified.",
                              "No performance improvement or creative feature is implemented by this label marker."]}
    output.mkdir(parents=True)
    target = output/"NOT-INSTALLABLE-embedded-label.research.bin"
    target.write_bytes(candidate)
    if target.read_bytes() != candidate:
        raise ValueError("Local output readback differs")
    (output/"manifest.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
