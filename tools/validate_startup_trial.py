"""Independently check the Pocket Studio candidate against the prior label image.

Exact reconstruction uses the known prior image and resource FAT chunks, not
the packed patch builder. No USB, card writes or update execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from build_startup_asset import jpeg_contract

ROOT = Path(__file__).resolve().parents[1]
PRIOR_SHA = "a222ab366e8f328dc3a3be17b780fa42cba988d3b220487b4fb14a8016a270b4"
ASSET_SHA = "d003134ffe03c7f4ceb54bb58219d75c451f0bb16eebf0a4294c8d3bd22a14b4"
CANDIDATE_SHA = "8f742b9a699b276a001827721fab4bd50e578372a582acc020ba1caa6e75754c"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(prior, candidate, entries):
    if sha(prior) != PRIOR_SHA or len(candidate) != len(prior) or sha(candidate) != CANDIDATE_SHA:
        raise ValueError("Exact prior/candidate identities differ")
    rows = [e for e in entries if e["kind"] == "file"]
    targets = [e for e in rows if e["path"] == "JPG/Startup1.jpg"]
    if len(targets) != 1 or len(rows) != 368:
        raise ValueError("Expected complete resource inventory")
    target = targets[0]
    expected = bytearray(prior)
    original, replacement, ranges = bytearray(), bytearray(), []
    for chunk in target["chunks"]:
        start, size = chunk["carrier_offset"], chunk["file_bytes"]
        end = start+size
        if not 0 <= start < end <= len(prior) or any(start < b and a < end for a, b in ranges):
            raise ValueError("Invalid resource chunks")
        ranges.append((start, end))
        original.extend(prior[start:end])
        replacement.extend(candidate[start:end])
        expected[start:end] = candidate[start:end]
    if len(replacement) != 24210 or sha(replacement) != ASSET_SHA or sha(original) != target["sha256"]:
        raise ValueError("Resource payload identity differs")
    stock_format, new_format = jpeg_contract(original), jpeg_contract(replacement)
    if stock_format["frame"] != new_format["frame"] or stock_format["markers"] != new_format["markers"]:
        raise ValueError("JPEG frame or marker layout differs")
    checksum = (sum(expected[:44])+sum(expected[48:])) & 0xffffffff
    struct.pack_into("<I", expected, 44, checksum)
    if expected != candidate or struct.unpack_from("<I", candidate, 44)[0] != checksum:
        raise ValueError("Unexpected change outside startup payload and checksum")
    unchanged = 0
    for entry in rows:
        if entry["path"] == target["path"]:
            continue
        for chunk in entry["chunks"]:
            start, size = chunk["carrier_offset"], chunk["file_bytes"]
            if prior[start:start+size] != candidate[start:start+size]:
                raise ValueError("Another resource changed relative to the prior marker image")
        unchanged += 1
    if candidate[0x30:0x6fe2c0] != prior[0x30:0x6fe2c0]:
        raise ValueError("Application/loader bytes changed relative to marker image")
    return {"method": "Exact reconstruction from prior marker image and bounded JPEG chunks; independent of packed builder",
            "prior_candidate_sha256": PRIOR_SHA, "candidate_sha256": sha(candidate),
            "candidate_bytes": len(candidate), "startup_jpeg_sha256": sha(replacement),
            "startup_jpeg_bytes": len(replacement), "jpeg_frame_and_marker_layout_match": True,
            "jpeg_complete_decode": True, "other_resources_unchanged_vs_marker_candidate": unchanged,
            "application_and_loader_bytes_identical_to_marker_candidate": True,
            "exact_reconstruction_matches": True, "only_startup_payload_and_checksum_differ_vs_marker_candidate": True,
            "changed_bytes_vs_marker_candidate": sum(a != b for a, b in zip(prior, candidate)),
            "fat_metadata_unchanged": True, "version_product_and_download_descriptor_unchanged": True,
            "staged": False, "flashed": False, "startup_activation_verified": False,
            "creative_looks_integrated": False, "performance_gain_demonstrated": False,
            "restoration_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True, help="New evidence file")
    args = parser.parse_args()
    if args.evidence.exists():
        raise FileExistsError("Use a new evidence file")
    prior = (ROOT/"derived/embedded-label-candidate-02/NOT-INSTALLABLE-embedded-label.research.bin").read_bytes()
    candidate = (ROOT/"derived/pocket-studio-identity-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin").read_bytes()
    filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    report = verify(prior, candidate, filesystem["entries"])
    with args.evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
