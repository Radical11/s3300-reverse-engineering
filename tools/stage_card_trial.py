"""Stage an exact registered research trial on a removable FAT card, with backup.

No formatting, raw flash, version bypass, directory recursion or photo writes.
Only the existing FIRMWARE/FIRMWARE.BIN is replaceable, after known-hash backup.
"""
import argparse
import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import re

from flash_trial_payloads import BASELINE, ROOT, TRIALS, load_trial


def sha(data):
    return hashlib.sha256(data).hexdigest()


def removable_fat_identity(root):
    if os.name != "nt" or not re.fullmatch(r"[A-Z]:\\", str(root)):
        raise ValueError("Use an explicit Windows drive root")
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes, kernel.GetDriveTypeW.restype = [ct.c_wchar_p], ct.c_uint
    if kernel.GetDriveTypeW(str(root)) != 2:
        raise ValueError("Target must report DRIVE_REMOVABLE; fixed drives are forbidden")
    serial, maximum, flags = ct.c_ulong(), ct.c_ulong(), ct.c_ulong()
    filesystem = ct.create_unicode_buffer(64)
    kernel.GetVolumeInformationW.argtypes = [ct.c_wchar_p, ct.c_wchar_p, ct.c_ulong,
        ct.POINTER(ct.c_ulong), ct.POINTER(ct.c_ulong), ct.POINTER(ct.c_ulong), ct.c_wchar_p, ct.c_ulong]
    kernel.GetVolumeInformationW.restype = ct.c_int
    if not kernel.GetVolumeInformationW(str(root), None, 0, ct.pointer(serial), ct.pointer(maximum),
                                        ct.pointer(flags), filesystem, len(filesystem)):
        raise ct.WinError(ct.get_last_error())
    if filesystem.value.upper() not in ("FAT", "FAT32"):
        raise ValueError("Expected the camera's removable FAT card")
    for path in (root, root/"FIRMWARE", root/"DCIM"):
        if not path.is_dir() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Required card directories are missing or redirected")
    return serial.value, filesystem.value


def replace_verified(directory, payload, expected_sha, backup_directory, identity_check=lambda: None):
    """Exclusive temp write, exact backup, recheck old bytes, then same-folder rename."""
    directory, backup_directory = Path(directory), Path(backup_directory)
    target, temporary = directory/"FIRMWARE.BIN", directory/"S3300LAB.TMP"
    if sha(payload) != expected_sha:
        raise ValueError("Incoming payload identity differs")
    if not target.is_file() or target.is_symlink() or temporary.exists() or backup_directory.exists():
        raise ValueError("Existing file required; temporary and backup outputs must be new")
    previous = target.read_bytes()
    previous_sha = sha(previous)
    known = {BASELINE} | {value["sha256"] for value in TRIALS.values()}
    if previous_sha not in known:
        raise ValueError("Existing update file is not a known project image; refusing replacement")
    backup_directory.mkdir(parents=True)
    backup = backup_directory/"previous-firmware.bin"
    with backup.open("xb") as handle:
        handle.write(previous)
        handle.flush()
        os.fsync(handle.fileno())
    if backup.read_bytes() != previous:
        raise ValueError("Host backup readback differs")
    identity_check()
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    if temporary.read_bytes() != payload:
        raise ValueError("Card temporary readback differs; original file not replaced")
    identity_check()
    if sha(target.read_bytes()) != previous_sha:
        raise ValueError("Original file changed during preparation; refusing replacement")
    os.replace(temporary, target)
    with target.open("r+b") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    readback = target.read_bytes()
    if readback != payload or sha(readback) != expected_sha:
        raise ValueError("Final card readback differs; do not start an update")
    return {"previous_sha256": previous_sha, "host_backup_sha256": sha(backup.read_bytes()),
            "backup_readback_verified": True, "card_bytes": len(readback),
            "card_sha256": sha(readback), "card_exact_readback_verified": True,
            "file": "FIRMWARE/FIRMWARE.BIN", "staged": True, "camera_flashed": False,
            "creative_looks_integrated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("drive", help="Explicit removable card drive, e.g. E:\\")
    parser.add_argument("output", type=Path, help="New local audit/backup directory inside derived/")
    parser.add_argument("--trial", choices=("embedded-label", "pocket-studio", "amber-mono"), default="embedded-label")
    args = parser.parse_args()
    root, output = Path(args.drive), args.output.resolve()
    if not output.is_relative_to((ROOT/"derived").resolve()) or output.exists():
        raise ValueError("Choose a new local output under derived/")
    identity = removable_fat_identity(root)

    def recheck():
        if removable_fat_identity(root) != identity:
            raise ValueError("Card identity changed during staging")

    payload = load_trial(args.trial)
    if args.trial == "pocket-studio":
        from validate_startup_trial import verify
        baseline_trial = load_trial("embedded-label")
        filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
        verify(baseline_trial, payload, filesystem["entries"])
    result = replace_verified(root/"FIRMWARE", payload, TRIALS[args.trial]["sha256"], output, recheck)
    result.update(trial=args.trial, drive=str(root), filesystem=identity[1],
                  package_version="1.1 unchanged", version_bypass=False,
                  same_version_acceptance_verified=False, restoration_verified=False)
    if args.trial == "amber-mono":
        result.update(experimental_amber_tint_included=True, saved_photo_effect_verified=False,
                      creative_looks_integrated=False,
                      scope="Existing Sepia constant-tint experiment; four-look module is not integrated")
    (output/"card-staging.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
