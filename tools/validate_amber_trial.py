"""Decode and verify the fixed Amber trial independently of the patch builder.

Transcodes every block of both affected segments from candidate bytes and
compares against original bytes with only three exact declared data spans.
No rewrite helper or builder manifest is trusted for expected decoded output.
"""
import argparse
import json
from pathlib import Path
import struct

from build_amber_trial import EXPECTED, AMBER_TINT, TINT_VA, AMBER_LABEL_VA
from build_patch_candidate import ROOT, BASELINE, sha
from build_resource_candidate import edit_label, validate_chain, replace_chunks, additive
from map_development_interfaces import AddressMap
from validate_decoded_firmware import transcode
from workspace_functions import load_analysis


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--evidence", required=True, type=Path, help="New metadata-only evidence")
    args = parser.parse_args()
    if args.evidence.exists():
        raise ValueError("Use a new evidence path")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    candidate = args.candidate.read_bytes()
    prior = (ROOT/"derived/pocket-studio-identity-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin").read_bytes()
    if sha(source) != BASELINE or sha(candidate) != EXPECTED or len(candidate) != len(source):
        raise ValueError("Exact original/candidate identity differs")
    if sha(prior) != "8f742b9a699b276a001827721fab4bd50e578372a582acc020ba1caa6e75754c":
        raise ValueError("Prior working identity image differs")
    manifest, raw = load_analysis(ROOT/"derived/unpacked-v1.1-indexed")
    mapped = AddressMap(raw, manifest["regions"])
    changes = [(0x8036e14c, "Welcome screen".encode("utf-16-be"), "Welcome studio".encode("utf-16-be")),
               (AMBER_LABEL_VA, "Sepia".encode("utf-16-be"), "Amber".encode("utf-16-be")),
               (TINT_VA, struct.pack("<hh", -30, 30), struct.pack("<hh", *AMBER_TINT))]
    framing = json.loads((ROOT/"evidence/packed-segments.json").read_text())
    if framing["input_sha256"] != BASELINE:
        raise ValueError("Framing source differs")
    reconstructed = bytearray(prior)
    proofs, covered = [], set()
    for segment in framing["segments"]:
        base, size = segment["elf_p_vaddr"], segment["elf_p_memsz"]
        edits = [(a, b, c) for a, b, c in changes if base <= a and a+len(b) <= base+size]
        if not edits:
            continue
        desired = bytearray(mapped.read(base, size))
        for address, before, after in edits:
            offset = address-base
            if desired[offset:offset+len(before)] != before or len(before) != len(after):
                raise ValueError("Expected original data span differs")
            desired[offset:offset+len(after)] = after
            covered.add(address)
        output = bytearray()
        changed_payloads = []
        for block in segment["blocks"]:
            start = block["header"]["carrier_offset"]
            kind, length, payload_size, a_size, b_size = struct.unpack_from("<IIIHH", source, start)
            a_start, b_start = start+16, start+16+a_size
            p_start, end = b_start+b_size, b_start+b_size+payload_size
            if kind != 2 or candidate[start:p_start] != source[start:p_start]:
                raise ValueError("Packed framing or prefix table changed")
            if (p_start, payload_size, sha(source[p_start:end])) != (
                    block["payload"]["carrier_offset"], block["payload"]["size"], block["payload"]["sha256"]):
                raise ValueError("Original packed binding differs")
            a = struct.unpack_from(f"<{a_size//4}I", source, a_start)
            b = struct.unpack_from(f"<{b_size//4}I", source, b_start)
            output.extend(transcode(candidate[p_start:end], a, b, length, bytes(output[-32768:]))[0])
            if candidate[p_start:end] != prior[p_start:end]:
                reconstructed[p_start:end] = candidate[p_start:end]
                changed_payloads.append({"block": block["index"], "start": p_start, "bytes": payload_size})
        if output != desired:
            raise ValueError("Independent decoded output has an unexpected data/code difference")
        proofs.append({"virtual_start": base, "bytes": len(output), "blocks": len(segment["blocks"]),
                       "independent_exact_data_diff_match": True, "changed_payloads_vs_identity": changed_payloads})
    if covered != {c[0] for c in changes}:
        raise ValueError("Not all planned application data spans checked")
    fs = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    entry = next(e for e in fs["entries"] if e["path"] == "String/Res_Str_Eng_New.bst")
    english = validate_chain(source, fs, entry)
    english, _ = edit_label(english)
    english, _ = edit_label(english, "Sepia", "Amber")
    reconstructed = replace_chunks(reconstructed, entry["chunks"], english)
    struct.pack_into("<I", reconstructed, 44, additive(reconstructed))
    if bytes(reconstructed) != candidate:
        raise ValueError("Carrier differs outside two checked packed segments, English resource and checksum")
    unchanged = 0
    for entry in fs["entries"]:
        if entry["kind"] != "file" or entry["path"] == "String/Res_Str_Eng_New.bst":
            continue
        for chunk in entry["chunks"]:
            start, size = chunk["carrier_offset"], chunk["file_bytes"]
            if candidate[start:start+size] != prior[start:start+size]:
                raise ValueError("Non-English resource changed versus working identity")
        unchanged += 1
    report = {"method": "Independent prefix/native-zlib full-segment decode and exact carrier reconstruction against working identity",
              "source_sha256": BASELINE, "candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
              "application_allowed_data_spans": [{"address": a, "bytes": len(b)} for a, b, _ in changes],
              "independent_segment_proofs": proofs, "only_declared_decoded_data_changed": True,
              "exact_carrier_reconstruction_matches": True, "other_resources_unchanged_vs_identity": unchanged,
              "startup_art_preserved": True, "version_product_and_download_descriptor_unchanged": True,
              "look": "Amber", "treatment": "Tinted monochrome using existing Sepia effect",
              "tint_before": [-30, 30], "tint_after": list(AMBER_TINT),
              "saved_photo_effect_verified": False, "speed_gain_demonstrated": False, "restoration_verified": False,
              "staged": False, "flashed": False}
    with args.evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
