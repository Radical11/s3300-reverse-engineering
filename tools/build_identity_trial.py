"""Reproduce the Pocket Studio startup-art + existing menu-marker experiment.

Local research output only; fixed source, asset digest, labels and patch spans.
No camera, card or update operations. Original shooting algorithms unchanged.
"""
import argparse
import json
from pathlib import Path

from build_patch_candidate import ROOT, BASELINE, build, sha
from build_resource_candidate import edit_label, validate_chain
from build_startup_asset import jpeg_contract
from validate_startup_trial import ASSET_SHA, CANDIDATE_SHA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset", type=Path, help="Previously generated original Startup1.jpg")
    parser.add_argument("output", type=Path, help="New local directory under derived/")
    args = parser.parse_args()
    output, asset = args.output.resolve(), args.asset.resolve()
    derived = (ROOT/"derived").resolve()
    if output.exists() or not output.is_relative_to(derived) or not asset.is_relative_to(derived):
        raise ValueError("Use local asset and new output under derived/")
    replacement = asset.read_bytes()
    if sha(replacement) != ASSET_SHA or len(replacement) != 24210:
        raise ValueError("Not the reviewed Pocket Studio artwork")
    jpeg_contract(replacement)
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Unsupported source")
    filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    english = next(e for e in filesystem["entries"] if e["path"] == "String/Res_Str_Eng_New.bst")
    original = validate_chain(source, filesystem, english)
    table, _ = edit_label(original)
    startup = next(e for e in filesystem["entries"] if e["path"] == "JPG/Startup1.jpg")
    output.mkdir(parents=True)
    inputs = output/"inputs"
    inputs.mkdir()
    (inputs/"english.bst").write_bytes(table)
    label = "Welcome studio".encode("utf-16-be")
    (inputs/"label.bin").write_bytes(label)
    plan = {"schema_version": 1, "source_sha256": BASELINE, "name": "pocket-studio-identity-01",
            "patches": [
                {"kind": "resource", "path": english["path"], "expected_sha256": sha(original),
                 "replacement_file": (inputs/"english.bst").relative_to(ROOT).as_posix(), "replacement_sha256": sha(table)},
                {"kind": "virtual", "address": 0x8036e14c, "expected_sha256": sha("Welcome screen".encode("utf-16-be")),
                 "replacement_file": (inputs/"label.bin").relative_to(ROOT).as_posix(), "replacement_sha256": sha(label)},
                {"kind": "resource", "path": startup["path"], "expected_sha256": startup["sha256"],
                 "replacement_file": asset.relative_to(ROOT).as_posix(), "replacement_sha256": ASSET_SHA}]}
    candidate, report = build(plan)
    if sha(candidate) != CANDIDATE_SHA:
        raise ValueError("Rebuild differs from reviewed identity trial")
    (output/"plan.json").write_text(json.dumps(plan, indent=2)+"\n", encoding="utf-8")
    (output/"NOT-INSTALLABLE-patch-plan.research.bin").write_bytes(candidate)
    if (output/"NOT-INSTALLABLE-patch-plan.research.bin").read_bytes() != candidate:
        raise ValueError("Local readback differs")
    (output/"manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
                      "output": str(output), "staged": False, "flashed": False}, indent=2))


if __name__ == "__main__":
    main()
