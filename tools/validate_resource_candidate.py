"""Independent exact-difference check for the offline label-test candidate.

Uses a unique source byte-pattern and direct original ELF parsing. Does not
import the candidate builder, ZST codec, resource-extraction metadata or its
patch manifest. No upload or camera command is implemented.
"""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile

BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(source, candidate):
    if sha(source) != BASELINE or len(candidate) != len(source):
        raise ValueError("Unsupported source or candidate length")
    old = "Welcome screen".encode("utf-16-be")
    new = "Welcome studio".encode("utf-16-be")
    if source.count(old) != 1:
        raise ValueError("Label pattern not unique in source")
    location = source.index(old)
    if location < 0x7092c0:
        raise ValueError("Label pattern is not in resource-data area")
    expected = bytearray(source)
    expected[location:location+len(old)] = new
    checksum = (sum(expected[:44])+sum(expected[48:])) % (1 << 32)
    expected[44:48] = checksum.to_bytes(4, "little")
    if candidate != expected:
        raise ValueError("Candidate differs from the independently reconstructed minimal change")
    if int.from_bytes(candidate[44:48], "little") != (sum(candidate[:44])+sum(candidate[48:])) % (1 << 32):
        raise ValueError("Candidate checksum invalid")
    checks = []
    for offset in (0x200, 0x1006c0, 0x1026c0, 0x2202c0, 0x3bd9a8, 0x5c2b78):
        original = ELFFile(BytesIO(source[offset:]))
        for segment in original.iter_segments():
            start = offset+segment["p_offset"]
            end = start+segment["p_filesz"]
            if end > len(source) or source[start:end] != candidate[start:end]:
                raise ValueError("Original ELF program bytes differ")
        header_size = max(original.header["e_ehsize"], original.header["e_phoff"]+
                          original.header["e_phentsize"]*original.header["e_phnum"])
        if source[offset:offset+header_size] != candidate[offset:offset+header_size]:
            raise ValueError("Original ELF headers differ")
        checks.append({"elf_carrier_offset": offset, "program_headers_and_segments_unchanged": True})
    changes = [i for i, (a, b) in enumerate(zip(source, candidate)) if a != b]
    return {"method": "Independent unique raw byte-pattern reconstruction and direct ELF program-header parsing",
            "source_sha256": BASELINE, "candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
            "label_storage_offset": location, "changed_byte_offsets": changes, "changed_byte_count": len(changes),
            "candidate_exactly_matches_independent_reconstruction": True, "checksum_matches": True,
            "stored_checksum": struct.unpack_from("<I", candidate, 44)[0], "elf_checks": checks,
            "installable": False, "hardware_acceptance_verified": False, "restoration_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", required=True, type=Path, help="New evidence path")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Evidence path already exists")
    source = ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    report = verify(source.read_bytes(), args.candidate.read_bytes())
    if sha(source.read_bytes()) != BASELINE:
        raise ValueError("Source changed during verification")
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({k:report[k] for k in ("candidate_sha256", "changed_byte_count", "candidate_exactly_matches_independent_reconstruction", "installable")}))


if __name__ == "__main__":
    main()
