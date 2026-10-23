"""Read-only, source-bound inspection of the S3300 v1.1 update descriptor.

Produces analysis evidence only. Does not repack, fix checksums, talk to a
camera, or establish a safe restoration route. All ranges are end-exclusive.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

BASELINE_SHA256 = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
DESCRIPTOR_OFFSET = 0x100000


def parse_descriptor(data, offset=DESCRIPTOR_OFFSET):
    if offset < 0 or len(data) < offset + 0x40:
        raise ValueError("Truncated download descriptor")
    u32 = lambda n: struct.unpack_from("<I", data, offset + n)[0]
    u16 = lambda n: struct.unpack_from("<H", data, offset + n)[0]
    extended = u16(0x3e) == 0x55aa
    header_size = 0xc0 if extended else 0x40
    if len(data) < offset + header_size:
        raise ValueError("Truncated download descriptor extension")
    payload_start = offset + header_size
    payload_end = payload_start + u32(0)
    if payload_end > len(data):
        raise ValueError("Declared payload extends outside carrier")
    return {
        "offset": offset, "size": header_size,
        "payload_size": u32(0), "transfer_buffer_size": u32(4),
        "media_selector": u32(8), "post_burn_action_selector": u32(0xc),
        "led_parameters_raw": [u32(n) for n in (0x10, 0x14, 0x18)],
        "hash_flag_u16": u16(0x3c),
        "hash_flag_handle_low_byte": u16(0x3c) & 0xff,
        "extension_magic_u16": u16(0x3e),
        "extension_present": extended,
        "extension_word_0x40": u32(0x40) if extended else None,
        "payload_range": [payload_start, payload_end],
        "payload_ends_at_carrier_end": payload_end == len(data),
    }


def inspect(data, mapping):
    digest = hashlib.sha256(data).hexdigest()
    if digest != BASELINE_SHA256 or digest != mapping["sha256"]:
        raise ValueError("Unsupported or modified firmware identity")
    descriptor = parse_descriptor(data)
    boot = descriptor["payload_range"][0]
    # Names and byte offsets come from PrintBootHeaderProperties (0x8001a21c).
    # Retain raw values: resource-size units and runtime transformations have
    # not been completely traced and must not be treated as carrier offsets.
    fields = [
        (0, "MainAddr"), (8, "MainSize"), (0x10, "AltAddr"),
        (0xc, "AltSize"), (0x204, "ulResourceAFileSize"),
        (0x208, "ulResourceBFileSize"), (0x20c, "ulResourceCFileSize"),
        (0x210, "ulUserAreaFileSize"), (0x214, "ulResourceAVirtualSize"),
        (0x218, "ulResourceBVirtualSize"), (0x21c, "ulResourceCVirtualSize"),
        (0x220, "ulUserAreaVirtualSize"), (0x224, "Code area size"),
        (0x22c, "User area mode"), (0x230, "User Area Start"),
        (0x310, "User Area Phys Start"), (0x314, "User Area Actual Size"),
    ]
    properties = [{"name": name, "relative_offset": n,
                   "firmware_offset": boot+n,
                   "raw_u32": struct.unpack_from("<I", data, boot+n)[0]}
                  for n, name in fields]
    main = boot + struct.unpack_from("<I", data, boot)[0]
    alt = boot + struct.unpack_from("<I", data, boot+0x10)[0]
    image_offsets = {i["root_offset"] for i in mapping["images"]}
    checks = {
        "descriptor_extension_magic": descriptor["extension_present"],
        "declared_payload_exactly_fits": descriptor["payload_ends_at_carrier_end"],
        "main_pointer_matches_mapped_elf": main in image_offsets,
        "alt_pointer_matches_mapped_elf": alt in image_offsets,
        "main_extent_ends_at_alt": main + struct.unpack_from("<I", data, boot+8)[0] == alt,
    }
    if not all(checks.values()):
        raise ValueError(f"Baseline structural checks failed: {checks}")
    return {
        "method": "Offline Python descriptor parsing plus source-bound static MIPS evidence",
        "input_sha256": digest, "input_size": len(data),
        "ranges_end_exclusive": True, "descriptor": descriptor,
        "boot_header_offset": boot, "boot_properties_raw": properties,
        "checks": checks,
        "integrity": {
            "download_card_flag_branch": "0x8001983c..0x80019844",
            "hash_flag_actual": descriptor["hash_flag_u16"],
            "whole_carrier_trailer_md5_path_enabled": descriptor["hash_flag_u16"] != 0,
            "path_if_enabled": "MD5 of carrier bytes [0, file_size-16), compared against final 16 bytes",
            "calculated_md5_excluding_last16": hashlib.md5(data[:-16]).hexdigest(),
            "last16_hex": data[-16:].hex(),
            "last16_matches_calculated_md5": data[-16:] == hashlib.md5(data[:-16]).digest(),
            "whole_carrier_result": "Not applicable: flag is zero; no MD5 trailer asserted",
            "chunk_hash_gate": "Handle byte +0x1280 copied from descriptor +0x3c; actual zero",
            "no_hash_chunk_behavior": "Card reader at 0x80019c20 rereads each chunk and compares bytes",
            "other_integrity_or_signature_rules": "Unresolved; this parser does not prove absence",
        },
        "acceptance_and_restore": {
            "analysis_scope": "Boot downloader only; null acceptance fields mean unresolved in this pass, not absence of installed-application checks",
            "model_acceptance_field": None, "version_acceptance_field": None,
            "device_flash_layout_verified": False,
            "installed_v1_0_backup_available": False,
            "device_specific_calibration_backup_verified": False,
            "restoration_tested": False, "safe_to_flash": False,
            "boot_recovery_code": "InitRecoverSection and UART/USB/card download paths exist in supplied boot executable; reachability on the camera is unverified",
        },
        "limitations": [
            "Download descriptor semantics apply to the supplied boot updater, not necessarily Nikon's installed application acceptance checks.",
            "Diagnostic property names do not establish storage units or physical flash addresses.",
            "Random-looking 128-byte region at boot-header +0x318 is not identified as a signature or digest.",
            "No hardware access, update execution, checksum fixing, repacking, or flashable output.",
        ],
    }


def save_static_evidence(root, data, mapping):
    sys.path.insert(0, str(root / "tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    im = mapping["images"][0]
    symbols = [s for s in im["symbols"] if s["type"] == "STT_FUNC"]
    names = {s["value"]: s["name"] for s in symbols}
    selected = ["DownloadCard", "BurnGetHandle", "PrintBootHeaderProperties",
                "PrintRecoverHeaderProperties", "InitRecoverSection",
                "GetSectionFromBootHeader", "BurnHashManager"]
    windows = [(name, next(s for s in symbols if s["name"] == name)["value"],
                next(s for s in symbols if s["name"] == name)["size"])
               for name in selected]
    windows.append(("card_chunk_reader_analyst_label", 0x80019c20, 0x37c))
    out = root / "derived/update-container-analysis"
    out.mkdir(exist_ok=True)
    records = []
    for name, address, size in windows:
        segment = next(s for s in im["segments"] if s["p_vaddr"] <= address
                       and address+size <= s["p_vaddr"]+s["p_filesz"])
        offset = im["root_offset"]+segment["p_offset"]+address-segment["p_vaddr"]
        body = data[offset:offset+size]
        instructions = list(Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN).disasm(body, address))
        if sum(i.size for i in instructions) != size:
            raise ValueError("Incomplete static listing")
        lines = ["; Static MIPS32; branch delay slots matter. No target execution."]
        for i in instructions:
            annotation = names.get(int(i.op_str, 0), "") if i.mnemonic in ("jal", "j") else ""
            lines.append(f"{i.address:08x} file:{offset+i.address-address:08x} {i.bytes.hex()} {i.mnemonic:9} {i.op_str} {annotation}")
        path = out / f"{name}.asm"
        path.write_text("\n".join(lines)+"\n", encoding="utf-8")
        records.append({"name": name, "virtual_start": address, "firmware_offset": offset,
                        "size": size, "complete_linear_decode": True,
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "listing": str(path.relative_to(root))})
    return records


def self_test():
    # No proprietary bytes needed for parser boundary tests.
    sample = bytearray(0xc0 + 16)
    struct.pack_into("<II", sample, 0, 16, 0x20000)
    struct.pack_into("<H", sample, 0x3e, 0x55aa)
    assert parse_descriptor(sample, 0)["payload_range"] == [0xc0, 0xd0]
    assert parse_descriptor(sample, 0)["hash_flag_u16"] == 0
    sample[0x3c] = 1
    assert parse_descriptor(sample, 0)["hash_flag_handle_low_byte"] == 1
    struct.pack_into("<I", sample, 0, 17)
    try:
        parse_descriptor(sample, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("Out-of-carrier payload accepted")
    for truncated in [b"", bytes(0x3f), bytes(sample[:0x80])]:
        try:
            parse_descriptor(truncated, 0)
        except ValueError:
            pass
        else:
            raise AssertionError("Truncated descriptor accepted")
    return {"synthetic_parser_cases_passed": 6}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test()))
        return
    root = Path(__file__).resolve().parents[1]
    mapping = json.loads((root/"derived/v1.1-mapped/map.json").read_text())
    source = Path(mapping["input_path"])
    data = source.read_bytes()
    report = inspect(data, mapping)
    report["static_windows"] = save_static_evidence(root, data, mapping)
    report["self_test"] = self_test()
    report["source_unchanged_after_analysis"] = hashlib.sha256(source.read_bytes()).hexdigest() == BASELINE_SHA256
    (root/"evidence/update-container.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"checks": report["checks"], "hash_flag": report["integrity"]["hash_flag_actual"],
                      "static_windows": len(report["static_windows"]), "safe_to_flash": False}))


if __name__ == "__main__":
    main()
