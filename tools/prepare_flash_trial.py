"""Prepare a LOCAL card-layout package for the user-requested experimental trial.

Outputs must stay in this project's ignored derived directory. This tool does
not enumerate devices, write a card, upload, format, eject or execute firmware.
Device acceptance and restoration remain unverified.
"""
import argparse
import hashlib
import json
from pathlib import Path

from validate_resource_candidate import verify

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory inside this project's derived/")
    parser.add_argument("--candidate", type=Path, default=ROOT/"derived/label-test-candidate-01/NOT-INSTALLABLE-label-test.research.bin")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT/"derived").resolve()) or output.exists():
        raise ValueError("Choose a new LOCAL directory inside this project's derived/")
    source_path = ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    candidate = args.candidate.read_bytes()
    validation = verify(source_path.read_bytes(), candidate)
    directory = output/"firmware"
    directory.mkdir(parents=True)
    target = directory/"firmware.bin"
    with target.open("xb") as handle:
        handle.write(candidate)
    if target.read_bytes() != candidate:
        raise ValueError("Local package readback differs")
    report = {"phase": "local experimental staging package only",
              "user_requested_flash_trial": True,
              "file": "firmware/firmware.bin", "size": len(candidate),
              "sha256": hashlib.sha256(candidate).hexdigest(),
              "independent_byte_validation_passed": validation["candidate_exactly_matches_independent_reconstruction"],
              "local_file_readback_verified": True,
              "device_acceptance_verified": False, "restoration_verified": False,
              "copied_to_card": False, "camera_uploaded": False, "camera_flashed": False,
              "source_unchanged": hashlib.sha256(source_path.read_bytes()).hexdigest() == validation["source_sha256"],
              "vendor_update_guide": "https://nikonimglib.com/europe/Firmware/S3300/v1.1/En/ecpx_win_en.html",
              "limitations": ["The folder layout follows the stock update route; Nikon's guide does not validate the modified file.",
                              "User authorization does not establish acceptance, backup coverage or recoverability.",
                              "Physical card staging and the camera's update confirmation have not occurred."]}
    if not report["source_unchanged"]:
        raise ValueError("Source changed during preparation")
    (output/"trial-manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    (output/"README.txt").write_text(
        "EXPERIMENTAL LABEL-TEST PACKAGE - DEVICE ACCEPTANCE/RECOVERY UNVERIFIED\n"
        "Prepared locally at the user's request; not copied to a card or flashed.\n"
        "Change: English 'Welcome screen' to 'Welcome studio'; executable bytes unchanged.\n"
        "The firmware directory has the stock card-update layout.\n"
        "Use an adequately charged battery or the specified power adapter for an update.\n"
        "Do not disconnect power or operate controls while the camera reports an update in progress.\n"
        "The stock guide does not establish that this experimental file will be accepted or recoverable.\n"
        "See trial-manifest.json and the project progress/recovery notes.\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
