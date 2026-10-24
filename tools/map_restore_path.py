"""Offline audit of dump/recovery leads; never invokes a camera command.

This inventories source-bound v1.1 code, not installed-v1.0 behavior. It emits
no target payload, markers, USB requests, memory addresses to probe, or update.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
from map_development_interfaces import AddressMap, SOURCE_SHA
sys.path.insert(0, str(ROOT/"tools/vendor"))
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

WINDOWS = [
    ("nand_dump_monitor_fde_function", 0x805810c0, 0x854),
    ("media_read_dispatch", 0x800e408c, 0x108),
    ("media_handle_lookup", 0x800e4194, 0x78),
    ("media_geometry_query", 0x800e3fd8, 0xb4),
    ("media_operation_forwarder", 0x800e2d4c, 0xc0),
    ("getmem_handler_static_window", 0x8079de34, 0x1d8),
    ("setmem_monitor_static_window", 0x8079d74c, 0x264),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump_bounds(first=0, last_inclusive=0xffff, data_bytes=0x200, extra_bytes=0x10):
    """Nominal all-success output; deliberately not a backup validation."""
    if not 0 <= first <= last_inclusive <= 0xffffffff:
        raise ValueError("Invalid sector bounds")
    if not 0 < data_bytes <= 0x10000 or not 0 <= extra_bytes <= 0x10000:
        raise ValueError("Invalid record sizes")
    count = last_inclusive-first+1
    return {"first_sector": first, "last_sector_inclusive": last_inclusive,
            "requested_sectors": count, "data_bytes_per_success": data_bytes,
            "extra_bytes_per_success": extra_bytes,
            "nominal_data_bytes_if_all_reads_and_writes_succeed": count*data_bytes,
            "nominal_total_bytes_if_all_reads_and_writes_succeed": count*(data_bytes+extra_bytes)}


def reviewed_dump_contract(address_map):
    body = address_map.read(0x805810c0, 0x854)
    instructions = {i.address: (i.mnemonic, i.op_str) for i in Cs(CS_ARCH_MIPS, CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN).disasm(body, 0x805810c0)}
    expected = {
        0x805816e0: ("addiu", "$a1, $zero, 0x400"),
        0x805816f8: ("addiu", "$a1, $zero, 0x10"),
        0x805817e8: ("move", "$s0, $zero"),
        0x80581808: ("addiu", "$a2, $zero, 0x10"),
        0x8058180c: ("ori", "$t8, $zero, 0xffff"),
        0x8058185c: ("jal", "0x800e408c"),
        0x8058186c: ("addiu", "$a2, $zero, 0x200"),
        0x80581870: ("bnez", "$v0, 0x805817f4"),
        0x8058189c: ("addiu", "$s0, $s0, 1"),
        0x805818a8: ("beqz", "$t7, 0x80581820"),
    }
    for address, operation in expected.items():
        if instructions.get(address) != operation:
            raise ValueError(f"Reviewed instruction changed at {address:#x}")
    return {"reviewed_instruction_assertions": len(expected), **dump_bounds(),
            "read_failure_behavior": "Prints error and increments sector without writing a placeholder (0x80581878..0x805818ac)",
            "write_error_handling": "No checked write result before subsequent extra-data write or next iteration in reviewed path",
            "geometry_behavior": "Queries geometry into stack buffer at 0x80581724 but loop bound remains literal0xffff",
            "parsed_arguments_define_range": False,
            "is_complete_restorable_backup_proven": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/restore-path.json")
    parser.add_argument("--listings", type=Path, default=ROOT/"derived/restore-path")
    args = parser.parse_args()
    manifest_path = ROOT/"derived/v1.1-analysis-final/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    data = Path(manifest["elf_file"]).read_bytes()
    source = ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    if sha(data) != manifest["elf_sha256"] or manifest["source_sha256"] != SOURCE_SHA or sha(source.read_bytes()) != SOURCE_SHA:
        raise ValueError("Source identity mismatch")
    for region in manifest["regions"]:
        body = data[region["analysis_elf_offset"]:region["analysis_elf_offset"]+region["size"]]
        if len(body) != region["size"] or sha(body) != region["sha256"]:
            raise ValueError("Analysis region changed")
    if args.output.exists() or args.listings.exists():
        raise FileExistsError("Refusing to overwrite prior analysis")
    amap = AddressMap(data, manifest["regions"])
    command = amap.command(0x808983cc)
    if command["name"] != "Nanddn" or command["handler"] != 0x805810c0:
        raise ValueError("Unexpected monitor record")
    contract = reviewed_dump_contract(amap)
    fde_path = ROOT/"evidence/unwind-functions.json"
    fde_report = json.loads(fde_path.read_text())
    fde = next(f for f in fde_report["functions"] if f["start"] == command["handler"])
    if fde["size"] != 0x854 or fde_report["analysis_elf_sha256"] != manifest["elf_sha256"]:
        raise ValueError("Function boundary source mismatch")
    args.listings.mkdir(parents=True)
    windows = []
    for label, address, size in WINDOWS:
        raw = amap.read(address, size)
        instructions = list(Cs(CS_ARCH_MIPS, CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN).disasm(raw, address))
        if sum(i.size for i in instructions) != size:
            raise ValueError("Incomplete linear window decode")
        path = args.listings/f"{label}.asm"
        path.write_text("; Offline static listing. Branch delay slots matter; labels are analyst descriptions.\n"+
                        "\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in instructions)+"\n")
        windows.append({"label": label, "address": address, "size": size,
                        "sha256": sha(raw), "listing": str(path.relative_to(ROOT)),
                        "complete_linear_decode": True,
                        "boundary": "FDE verified" if address == 0x805810c0 else "Analyst-bounded window"})
    raw_table = amap.read(0x80899658, 16)
    setmem, setflag, getmem, getflag = struct.unpack("<4I", raw_table)
    if (setmem, setflag, getmem, getflag) != (0x8079d74c, 0, 0x8079de34, 0):
        raise ValueError("USB handler table changed")
    switches = []
    for address, count in ((0x800eb26c, 9), (0x800eb290, 5), (0x800eb2a4, 9), (0x80686fb4, 17)):
        raw = amap.read(address, count*4)
        switches.append({"address": address, "sha256": sha(raw), "entries": list(struct.unpack("<"+"I"*count, raw))})
    report = {"source_sha256": SOURCE_SHA, "analysis_elf_sha256": sha(data),
              "method": "Source-bound MIPS listings, verified monitor record and FDE boundary; no device access",
              "nand_dump_command": command, "nand_dump_contract": contract,
              "dump_path": {"string_address": 0x8066790c, "text": amap.text(0x8066790c),
                            "load_site": 0x80581730, "open_sites": [0x80581738, 0x8058174c]},
              "media_route": {"handle_lookup": "0x800e4194(1) ->0x800e41d4 ->0x800e3274(1)",
                              "read_dispatch": "0x800e408c(a1=1,a2=0) ->0x800e415c ->0x800e4188 ->0x800e2d4c ->0x800e2800",
                              "scope_limit": "Exact installed flash geometry, spare/OOB semantics, ECC state and bad-block handling remain unresolved"},
              "usb_getmem": {"table_address": 0x80899660, "handler": getmem,
                             "neighbor_mutating_handler_address": 0x80899658, "neighbor_mutating_handler": setmem,
                             "table_flag_meaning": "Unknown; zero is not asserted as permission or transfer-size metadata",
                             "command_state": 0x800e113c,
                             "reviewed_modes": {"1": "Memory alias formed from command address OR0x20000000, length at command+0x10, then transfer0x80796070",
                                                "16": "Allocates and reads file data before transfer; not arbitrary flash dump proof",
                                                "2..8": "Delegates to0x8079d9b0; full semantics unresolved"},
                             "external_command_number_and_transport": None,
                             "installed_v1_0_presence_verified": False,
                             "safe_flash_readback_via_usb_established": False},
              "switch_tables": switches, "static_windows": windows,
              "restore_status": {"installed_v1_0_dump_available": False,
                                 "calibration_coverage_verified": False,
                                 "physical_flash_geometry_verified": False,
                                 "write_back_or_recovery_demonstrated": False,
                                 "software_only_route_proven": False,
                                 "physical_access_requirement_proven": False,
                                 "safe_to_install": False},
              "limitations": ["v1.1 static code is not a dump or runtime observation of the installed v1.0.",
                              "Nanddn writes a card file and changes display/debug state; it is not a passive external read command.",
                              "A finite fixed-range dump and RAM GetMem routine do not establish a complete flash backup or restoration path.",
                              "No USB requests, monitor commands, marker files, driver changes, writes, or recovery attempts occur."]}
    if sha(source.read_bytes()) != SOURCE_SHA:
        raise ValueError("Source changed")
    args.output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"static_windows": len(windows), "instruction_assertions": contract["reviewed_instruction_assertions"],
                      "nominal_dump_bytes": contract["nominal_total_bytes_if_all_reads_and_writes_succeed"], "safe_to_install": False}))


if __name__ == "__main__":
    main()
