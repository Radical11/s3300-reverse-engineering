"""Build the fixed Amber tinted-mono experiment, retaining Pocket Studio.

Uses existing Sepia mode with a smaller constant tint; no extra processing pass,
new controls, exposure change or executable instruction edit. Offline only.
"""
import argparse
import json
from pathlib import Path
import struct

from build_patch_candidate import ROOT, BASELINE, build, sha
from build_resource_candidate import edit_label, validate_chain
from validate_startup_trial import ASSET_SHA

EXPECTED = "d801708b06abbaece3974b2ae0cb9c55ce4154fffc0c132e00b35564ec86ce28"
TINT_VA = 0x80882d24
AMBER_LABEL_VA = 0x8036e47a
ORIGINAL_TINT = (-30, 30)
AMBER_TINT = (-18, 22)


def make_plan(output):
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Unsupported original source")
    filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    english = next(e for e in filesystem["entries"] if e["path"] == "String/Res_Str_Eng_New.bst")
    original = validate_chain(source, filesystem, english)
    table, _ = edit_label(original)
    table, label_record = edit_label(table, "Sepia", "Amber")
    if 0x8036add4+label_record["record_offset"]+2 != AMBER_LABEL_VA:
        raise ValueError("Sepia label location differs")
    inputs = output/"inputs"
    inputs.mkdir(parents=True)
    replacements = {"english.bst": table, "welcome.bin": "Welcome studio".encode("utf-16-be"),
                    "amber.bin": "Amber".encode("utf-16-be"), "tint.bin": struct.pack("<hh", *AMBER_TINT)}
    for name, body in replacements.items():
        (inputs/name).write_bytes(body)
    patches = []
    for kind, name, before, location in (
            ("resource", "english.bst", original, {"path": english["path"]}),
            ("virtual", "welcome.bin", "Welcome screen".encode("utf-16-be"), {"address": 0x8036e14c}),
            ("virtual", "amber.bin", "Sepia".encode("utf-16-be"), {"address": AMBER_LABEL_VA}),
            ("virtual", "tint.bin", struct.pack("<hh", *ORIGINAL_TINT), {"address": TINT_VA})):
        patches.append({"kind": kind, **location, "expected_sha256": sha(before),
                        "replacement_file": (inputs/name).relative_to(ROOT).as_posix(),
                        "replacement_sha256": sha(replacements[name])})
    artwork = ROOT/"firmware/branding/pocket-studio.jpg"
    if sha(artwork.read_bytes()) != ASSET_SHA:
        raise ValueError("Original Pocket Studio artwork differs")
    startup = next(e for e in filesystem["entries"] if e["path"] == "JPG/Startup1.jpg")
    patches.append({"kind": "resource", "path": startup["path"], "expected_sha256": startup["sha256"],
                    "replacement_file": artwork.relative_to(ROOT).as_posix(), "replacement_sha256": ASSET_SHA})
    return {"schema_version": 1, "source_sha256": BASELINE, "name": "amber-mono-01", "patches": patches}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New ignored local directory under derived/")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/"derived").resolve()):
        raise ValueError("Use a new local output under derived/")
    plan = make_plan(output)
    candidate, report = build(plan)
    if sha(candidate) != EXPECTED:
        raise ValueError("Rebuild differs from the reviewed Amber candidate")
    report.update(look="Amber", treatment="Tinted monochrome via existing Sepia mode",
                  original_tint=list(ORIGINAL_TINT), candidate_tint=list(AMBER_TINT),
                  saved_photo_effect_verified=False, tint_activation_verified=False,
                  additional_processing_passes=0, speed_gain_demonstrated=False)
    target = output/"NOT-INSTALLABLE-patch-plan.research.bin"
    target.write_bytes(candidate)
    if target.read_bytes() != candidate:
        raise ValueError("Local output readback differs")
    (output/"plan.json").write_text(json.dumps(plan, indent=2)+"\n", encoding="utf-8")
    (output/"manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
                      "look": "Amber", "staged": False, "flashed": False}, indent=2))


if __name__ == "__main__":
    main()
