"""Map UI state, user-store staging and debug dispatch in authenticated v1.1.

Offline only: exports listings and evidence, never sends a camera command.
Recovered layouts describe static code, not a supported public firmware API.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from build_patch_candidate import ROOT, BASELINE, sha
from map_development_interfaces import AddressMap
from workspace_functions import recover_ranges, containing

sys.path.insert(0, str(ROOT / "tools/vendor"))
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

TABLE_BASE = 0x80898ec8
FUNCTIONS = (0x80008f80, 0x800093b0, 0x80009644, 0x805ac85c,
             0x805a7070, 0x8061c18c, 0x806fbfa8, 0x806fc2a4,
             0x806fc4f0, 0x806fc98c, 0x8071c7ac, 0x8071d58c,
             0x807372f8, 0x807373a4, 0x807375e8, 0x80737664,
             0x8073782c)
WINDOWS = (("debug_dispatcher", 0x80796108, 0x208),
           ("debug_control_receiver", 0x80796310, 0x114),
           ("debug_control_loop", 0x8078d7b4, 0xac),
           ("debug_queue_loop", 0x8078d860, 0x2c),
           ("debug_serial_loop", 0x80791d10, 0x110),
           ("debug_serial_header", 0x80795b90, 0x150),
           ("getmem", 0x8079de34, 0x1d8),
           ("command_state_setter", 0x80203e54, 0x50),
           ("media_operation_router", 0x800e408c, 0x108))

# These are deliberately exact instructions, not strings or guessed symbols.
ASSERTIONS = {
    0x800093b4: ("jr", "$ra"),
    0x800093b8: ("addiu", "$v0, $v0, 0x32d4"),
    0x805ac8cc: ("sb", "$ra, 0x1a($t9)"),
    0x805ac934: ("jal", "0x807132d0"),
    0x805ac944: ("jal", "0x805a7070"),
    0x805a713c: ("j", "0x806fc2a4"),
    0x805a7150: ("j", "0x806fc2a4"),
    0x8061c1d0: ("sb", "$a0, 0x19($t0)"),
    0x806fc2f0: ("jal", "0x80009644"),
    0x806fc398: ("jal", "0x80737664"),
    0x806fc2e8: ("beq", "$v1, $t1, 0x806fc384"),
    0x806fc3a8: ("b", "0x806fc2f0"),
    0x806fc3c8: ("b", "0x806fc2f0"),
    0x806fc3a0: ("jal", "0x8073782c"),
    0x806fc3b4: ("jal", "0x807372f8"),
    0x807372fc: ("sw", "$s0, 0x10($sp)"),
    0x8073730c: ("addiu", "$a2, $v0, 0x28"),
    0x80737310: ("addiu", "$a3, $s0, 0x40"),
    0x807373a0: ("sb", "$a3, 9($a2)"),
    0x807375fc: ("addiu", "$a3, $v0, 0x156"),
    0x80737600: ("addiu", "$a2, $v0, 0x76"),
    0x80737678: ("addiu", "$a2, $v0, 0x76"),
    0x8073767c: ("addiu", "$a3, $s0, 0xe0"),
    0x807376c4: ("bne", "$s0, $a3, 0x80737680"),
    0x807376c8: ("addiu", "$a2, $a2, 0x10"),
    0x8071c868: ("sll", "$v1, $v0, 3"),
    0x8071c86c: ("subu", "$ra, $v1, $v0"),
    0x8071c870: ("sll", "$t9, $ra, 3"),
    0x8071c888: ("sw", "$t8, 0x18ac($t7)"),
    0x8071d680: ("lbu", "$t3, 0x1a($s1)"),
    0x8071d684: ("sb", "$t3, 9($s0)"),
    0x8000965c: ("addiu", "$a1, $zero, 0x400"),
    0x800096d0: ("lw", "$s3, 0x3258($a0)"),
    0x80009714: ("addiu", "$a3, $zero, 0x19f"),
    0x80009724: ("sb", "$v0, 0x19f($s2)"),
    0x800096d8: ("addiu", "$fp, $s2, 0x1a0"),
    0x800097b4: ("jal", "0x800e408c"),
    0x800097ec: ("jal", "0x800e408c"),
    0x80009810: ("lbu", "$a3, 0x19f($s1)"),
    0x80009944: ("b", "0x80009878"),
    0x80009948: ("move", "$v0, $zero"),
    0x80796158: ("sll", "$a3, $s0, 3"),
    0x8079615c: ("addiu", "$a2, $t0, -0x7138"),
    0x807961b4: ("andi", "$v0, $v0, 1"),
    0x807961cc: ("jalr", "$v0"),
    0x80796280: ("jal", "0x80795fe0"),
    0x807962bc: ("lhu", "$a1, ($s1)"),
    0x807962d4: ("lbu", "$s5, 2($s1)"),
    0x807962dc: ("addiu", "$s4, $s1, 4"),
    0x8079dec0: ("lui", "$t1, 0x2000"),
    0x8079dec4: ("or", "$s1, $t2, $t1"),
    0x8079def0: ("jal", "0x80796070"),
    0x8079dec8: ("lw", "$a1, 0x10($s3)"),
    0x80203e64: ("sw", "$a1, 4($t0)"),
    0x80203e68: ("sw", "$a2, 0x10($t0)"),
}


def decode_window(mapping, address, size):
    """Reject incomplete decoding; a linear decode does not prove reachability."""
    if address % 4 or size <= 0 or size % 4:
        raise ValueError("MIPS32 window must be positive and word aligned")
    body = mapping.read(address, size)
    instructions = list(Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
                        .disasm(body, address))
    if sum(i.size for i in instructions) != size:
        raise ValueError("Incomplete MIPS32 decode")
    return body, instructions


def check_instructions(observed, expected):
    for address, instruction in expected.items():
        if observed.get(address) != instruction:
            raise ValueError(f"Reviewed instruction changed at {address:#x}")
    return len(expected)


def paired_dispatch_records(mapping, base, count):
    """Parse only a caller-selected bounded prefix of eight-byte records."""
    if base % 4 or not 1 <= count <= 1024:
        raise ValueError("Invalid dispatch table bounds")
    records = []
    for index in range(count):
        address = base + index*8
        handler, flags = struct.unpack("<2I", mapping.read(address, 8))
        if handler:
            if handler % 4:
                raise ValueError("Unaligned dispatch handler")
            mapping.read(handler, 4)
        records.append({"index": index, "record_address": address,
                        "handler": handler, "raw_flags": flags,
                        "receive_before_handler_bit0": bool(flags & 1)})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT/"derived/unpacked-v1.1-indexed")
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/state-contracts.json")
    parser.add_argument("--listings", type=Path, default=ROOT/"derived/state-contracts-01")
    args = parser.parse_args()
    args.workspace = args.workspace.resolve()
    args.output = args.output.resolve()
    args.listings = args.listings.resolve()
    if args.output.exists() or args.listings.exists():
        raise FileExistsError("Use fresh evidence and listing paths")
    source = ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    if sha(source.read_bytes()) != BASELINE:
        raise ValueError("Unsupported original firmware identity")
    functions, manifest, raw = recover_ranges(args.workspace)
    mapping = AddressMap(raw, manifest["regions"])
    specs = []
    for address in FUNCTIONS:
        function = containing(functions, address)
        if function["start"] != address or function["size"] > 0x4000:
            raise ValueError("Unexpected compiler-unwind function boundary")
        specs.append((f"function-{address:08x}", address, function["size"], function))
    specs.extend((name, address, size, None) for name, address, size in WINDOWS)
    observed, listings = {}, []
    decoded = []
    for name, address, size, function in specs:
        body, instructions = decode_window(mapping, address, size)
        observed.update({i.address: (i.mnemonic, i.op_str) for i in instructions})
        path = args.listings/f"{name}.asm"
        decoded.append((path, instructions))
        listings.append({"label": name, "address": address, "bytes": size,
                         "sha256": sha(body), "complete_linear_decode": True,
                         "boundary": "compiler-unwind FDE" if function else "analyst-bounded window",
                         "fde_address": function["fde_address"] if function else None,
                         "path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)})
    checked = check_instructions(observed, ASSERTIONS)
    events = struct.unpack("<35I", mapping.read(0x8066dbac, 35*4))
    if events[4] != 0x805ac8a4 or events[6] != 0x805ac8a4:
        raise ValueError("Color Options event table differs")
    records = paired_dispatch_records(mapping, TABLE_BASE, 0xf4)
    if records[0xf2]["handler"] != 0x8079d74c or records[0xf3]["handler"] != 0x8079de34:
        raise ValueError("SetMem/GetMem dispatcher bindings differ")
    names = {hex(address): mapping.text(address) for address in
             (0x8037e720, 0x803813e4, 0x803813f4, 0x80686dd8)}
    getmem_cases = struct.unpack("<17I", mapping.read(0x80686fb4, 17*4))
    if getmem_cases[1] != 0x8079deb8 or getmem_cases[16] != 0x8079df78:
        raise ValueError("GetMem submode dispatch differs")
    report = {
        "method": "Authenticated source, ELF/program-header/region hashes, compiler-unwind function ranges, exact reviewed MIPS32 instructions and bounded tables",
        "source_sha256": BASELINE, "analysis_elf_sha256": sha(raw),
        "rea_evidence": False, "evidence_class": "local source-bound static evidence",
        "target_executed": False, "device_commands_issued": False,
        "reviewed_instruction_assertions": checked, "listings": listings,
        "diagnostic_and_filename_bindings": names,
        "ui_events": {"handler": 0x805ac85c, "dispatch_table": 0x8066dbac,
                      "first_event": 0x102, "last_event": 0x124,
                      "entries": [{"event": 0x102+i, "target": target} for i, target in enumerate(events)],
                      "commit_selection_events": [0x106, 0x108],
                      "physical_button_meanings": None,
                      "color_ram_byte_offset": 0x1a,
                      "current_view_pointer_global": 0x808918ac,
                      "menu_state_pointer_global": 0x80107188,
                      "menu_descriptor": {"entry_count_u32_offset": 0, "selected_u32_offset": 4,
                                          "parent_pointer_offset": 0x10, "next_pointer_offset": 0x14,
                                          "creator_callback_offset": 0x18, "entries_pointer_offset": 0x24,
                                          "entry_stride": 3, "selected_flag_offset": 2, "selected_flag_mask": 1},
                      "finding": "Color commit stores selection, applies pipeline, then reaches generic menu transition; selection helper modifies RAM flags rather than directly serializing settings."},
        "settings": {
            "store_getter": 0x800093b0, "store_ram_base": 0x800032d4,
            "setup_ram_pointer_global": 0x80891ebc,
            "welcome_byte_offset": 0x19,
            "view_ram_base": 0x80891ec0, "view_bank_stride": 0x38,
            "view_banks_copied": 4, "current_bank_selector": 0x8071c7ac,
            "bank_selector_limit": "Selector also uses banks8,9,10 and special fixed pointers; four copied banks do not cover every active mode.",
            "serialization": [
                {"label": "setup", "store_offset": 0x28, "bytes": 0x4a,
                 "stage_api": 0x807372f8, "load_api": 0x807373a4,
                 "menu_mode": 0x3000, "field_welcome_store_offset": 0x41},
                {"label": "view_banks", "store_offset": 0x76, "bytes": 0xe0,
                 "stage_api": 0x80737664, "load_api": 0x807375e8,
                 "menu_mode": 0x2100,
                 "color_field_store_offsets_for_four_banks": [0x90, 0xc8, 0x100, 0x138]},
                {"label": "shared_view_fields", "store_offset": 0x156, "bytes": 0x24,
                 "stage_api": 0x8073782c, "source_ram_base": 0x80891e88}],
            "menu_transition": 0x806fc2a4, "media_transaction_candidate": 0x80009644,
            "transaction": {"store_copy_bytes": 0x1a0, "allocation_bytes": 0x400,
                            "checksum_helper": 0x80008f80, "checksum_argument": 0x19f,
                            "checksum_complete_coverage_established": False,
                            "checksum_trailer_byte_offset": 0x19f,
                            "media_position_global": 0x80003258,
                            "media_router": 0x800e408c,
                            "operation_selectors_observed": [2, 1, 0],
                            "success_return": 0, "failure_return": 1,
                            "media_operations_semantics": "Prepare/write/read interpretation is an inference from call order, buffer use and checksum readback; exact physical flash operation boundaries remain unproven."},
            "finding": "Mode-selected menu transitions stage RAM fields into the shared store before calling a media transaction that writes, reads back and compares a trailer byte. Filename arguments to the view copy helpers are ignored in the reviewed helpers; UiView.bin is not evidence of file-based persistence.",
            "safe_standalone_settings_api": False,
            "power_cycle_persistence_observed": False},
        "debug_dispatch": {
            "dispatcher": 0x80796108, "table_base": TABLE_BASE, "record_bytes": 8,
            "bounded_prefix_records": len(records), "records": records,
            "getmem_table_index": 0xf3, "setmem_table_index": 0xf2,
            "table_end_established": False,
            "handler_abi": {"a0": "low8 subcommand", "a1": "allocated payload buffer", "a2": "transport selector"},
            "flag_bit0": "Receive payload before handler through 0x80795fe0; not an authorization bit",
            "selector1_opcode0_header": {"opcode_le16_offset": 0, "subcommand_u8_offset": 2, "payload_offset": 4},
            "callers": [{"address": 0x8078d850, "selector": 1, "entry": 0x8078d7b4},
                        {"address": 0x8078d87c, "selector": 1, "entry": 0x8078d860},
                        {"address": 0x80791da4, "selector": 0, "entry": 0x80791d10}],
            "getmem": {"handler": 0x8079de34, "command_state": 0x800e113c,
                       "mode_byte_offset": 0, "address_u32_offset": 4, "length_u32_offset": 0x10,
                       "memory_mode": 1, "address_or_mask": 0x20000000,
                       "mode_dispatch_table": 0x80686fb4,
                       "mode_dispatch_entries": list(getmem_cases),
                       "transfer": 0x80796070,
                       "command_state_setter": 0x80203e54,
                       "side_effects": "Calls cache/memory preparation 0x800b52e4, timestamps and status helper 0x8020108c; not established as a purely passive interface."},
            "safe_external_transport_established": False,
            "installed_version_reachability_observed": False},
        "coverage": [
            {"question": "UI selection and state layout", "status": "partially_answered", "remaining": "Physical buttons, all creators and complete event ownership"},
            {"question": "Persistent-settings route", "status": "partially_answered", "remaining": "Physical media geometry, checksum coverage, transaction recovery/atomicity, power-cycle observation"},
            {"question": "GetMem registration and dispatch", "status": "partially_answered", "remaining": "External activation/mode/endpoints, command-state population from that transport, installed firmware correspondence"},
            {"question": "Full backup and recovery", "status": "unresolved", "remaining": "Complete flash/calibration capture and demonstrated restore; fixed Nanddn loop is insufficient"}],
        "limitations": [
            "Bounded static v1.1 findings; no original C source, runtime execution, device observation or supported API is recovered.",
            "Full function linear decoding and direct calls do not establish entrypoint reachability or whole-program coverage.",
            "Index0xf3 is a proven internal table index; it is not a PTP operation code or a validated host request recipe.",
            "GetMem command state may be populated separately; dispatcher payload alone does not establish its memory-read framing.",
            "User-store stage/load sizes are inferred from reviewed copy loops, independently asserted loop constants and delay slots.",
            "No firmware patch, media access, marker creation, USB request, update or recovery operation is performed."]}
    args.listings.mkdir(parents=True)
    for path, instructions in decoded:
        with path.open("x", encoding="utf-8") as handle:
            handle.write("; Offline MIPS32; branch delay slots matter. No runtime observation.\n")
            handle.write("\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in instructions)+"\n")
    if sha(source.read_bytes()) != BASELINE:
        raise ValueError("Source changed during analysis")
    report["source_unchanged"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"output": str(args.output), "listings": len(listings),
                      "instruction_assertions": checked, "dispatch_prefix_records": len(records),
                      "safe_external_transport_established": False}))


if __name__ == "__main__":
    main()
