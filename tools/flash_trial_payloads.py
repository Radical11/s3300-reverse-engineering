"""Closed registry of exact research images; no arbitrary flash input.

Host validation and selection only. Device acceptance/recovery are not implied.
"""
import hashlib
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
TRIALS = {
    "resource-label": {
        "path": "derived/experimental-flash-trial-01/firmware/firmware.bin",
        "sha256": "c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312",
        "installed_firmware": "COOLPIX S3300 V1.0",
        "purpose": "First filesystem-only label trial"},
    "embedded-label": {
        "path": "derived/embedded-label-candidate-02/NOT-INSTALLABLE-embedded-label.research.bin",
        "sha256": "a222ab366e8f328dc3a3be17b780fa42cba988d3b220487b4fb14a8016a270b4",
        "installed_firmware": "COOLPIX S3300 V1.1",
        "purpose": "Embedded and filesystem label trial, retaining v1.1; no creative-look integration"},
    "pocket-studio": {
        "path": "derived/pocket-studio-identity-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin",
        "sha256": "8f742b9a699b276a001827721fab4bd50e578372a582acc020ba1caa6e75754c",
        "installed_firmware": "COOLPIX S3300 V1.1",
        "purpose": "Pocket Studio startup artwork plus existing Welcome studio marker; stock shooting and sound"},
    "amber-mono": {
        "path": "derived/amber-mono-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin",
        "sha256": "d801708b06abbaece3974b2ae0cb9c55ce4154fffc0c132e00b35564ec86ce28",
        "installed_firmware": "COOLPIX S3300 V1.1",
        "purpose": "Experimental Amber tint through existing Sepia option; Pocket Studio retained; photo effect unverified"}
}


def check_image(source, candidate, expected_sha):
    if hashlib.sha256(source).hexdigest() != BASELINE:
        raise ValueError("Unsupported source identity")
    if len(candidate) != len(source) or hashlib.sha256(candidate).hexdigest() != expected_sha:
        raise ValueError("Candidate is not the exact reviewed trial image")
    if candidate[0x28:0x2c] != source[0x28:0x2c] or candidate[0x30:0x34] != source[0x30:0x34]:
        raise ValueError("Version/product marker changed")
    if candidate[0x100000:0x1000c0] != source[0x100000:0x1000c0]:
        raise ValueError("Download descriptor changed")
    checksum = (sum(candidate[:44])+sum(candidate[48:])) & 0xffffffff
    if struct.unpack_from("<I", candidate, 44)[0] != checksum:
        raise ValueError("Candidate checksum disagrees")
    return candidate


def load_trial(name):
    if name not in TRIALS:
        raise ValueError("Unknown trial; arbitrary image selection is not supported")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    candidate = (ROOT/TRIALS[name]["path"]).read_bytes()
    return check_image(source, candidate, TRIALS[name]["sha256"])
