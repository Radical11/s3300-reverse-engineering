"""Recover source-bound settings and image-command integration contracts.

Independent static Capstone analysis plus a bounded, instruction-level model
of the settings checksum helper. No camera or MMIO access, target binary
execution, patch construction or installation occurs.
"""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import random
import struct
import sys

from elftools.elf.elffile import ELFFile
from map_development_interfaces import AddressMap
from workspace_functions import load_analysis

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
WORKSPACE = ROOT / "derived/unpacked-v1.1-indexed"
sys.path.insert(0, str(ROOT / "tools/vendor"))
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

WINDOWS = (
    ("settings_checksum", 0x80008f80, 0xc4),
    ("settings_media_transaction", 0x80009644, 0x308),
    ("settings_media_router", 0x800e408c, 0x108),
    ("media_device_router", 0x800e2d4c, 0xc0),
    ("media_device1_operations", 0x800e2800, 0x12c),
    ("dirty_mask_consumer", 0x801fbc8c, 0xcd8),
    ("cached_command_selection", 0x801fbb3c, 0xa8),
    ("driver_command_retention", 0x80192e04, 0x2a4),
    ("driver_context0_bridge", 0x8019e724, 0x10),
    ("hardware_command_stage", 0x802e57a8, 0x230),
    ("context5_caller", 0x802a8a50, 0xb0),
)

# Instruction words are checked against the authenticated image before a
# named interpretation is emitted. The map is not generated from names alone.
ASSERTIONS = {
    0x80009008: ("addiu", "$a3, $a3, -1"),
    0x80009018: ("addiu", "$a3, $a3, -1"),
    0x80009024: ("bne", "$a3, $t0, 0x80009018"),
    0x80009028: ("andi", "$t1, $a1, 0xffff"),
    0x80008fb8: ("sb", "$t3, ($t2)"),
    0x80008fec: ("andi", "$t1, $t0, 0xffff"),
    0x80009714: ("addiu", "$a3, $zero, 0x19f"),
    0x80009724: ("sb", "$v0, 0x19f($s2)"),
    0x800097b0: ("sw", "$s4, 0x10($sp)"),
    0x800e28a4: ("addiu", "$a2, $zero, 8"),
    0x800e28bc: ("mflo", "$a3"),
    0x801fc15c: ("lui", "$ra, 0x10"),
    0x801fc160: ("and", "$t8, $a2, $ra"),
    0x801fc16c: ("bnel", "$s4, $zero, 0x801fc5f4"),
    0x801fc5f4: ("addiu", "$a3, $zero, 0xf"),
    0x801fc5fc: ("jal", "0x801fbb3c"),
    0x801fbbdc: ("j", "0x80192e04"),
    0x801fbbe0: ("move", "$a0, $t4"),
    0x80192f78: ("jal", "0x8019e724"),
    0x8019e728: ("j", "0x802e57a8"),
    0x802e5830: ("sb", "$t7, 0x51($t6)"),
    0x802e5860: ("sw", "$a2, 0x324($s2)"),
    0x802e5880: ("sw", "$ra, 0x320($s2)"),
    0x802a8aa4: ("jal", "0x801fbc8c"),
    0x801fc484: ("sw", "$s5, ($s1)"),
    0x801fc488: ("sw", "$s0, 4($s1)"),
}


def digest(body):
    return hashlib.sha256(body).hexdigest()


def settings_sum(source, length_argument):
    """Reviewed mode-zero helper: sum source[0:N-1] modulo 65536.

    Reject zero/negative/oversized lengths instead of reproducing the target's
    unsigned underflow and potential unbounded invalid-memory reads.
    """
    if not isinstance(length_argument, int) or not 1 <= length_argument <= len(source) + 1:
        raise ValueError("Require N>=1 and at least N-1 source bytes")
    return sum(source[:length_argument - 1]) & 0xffff


def settings_store_checksum(store):
    if len(store) != 0x1a0:
        raise ValueError("Expected exact 0x1a0-byte settings store")
    return settings_sum(store, 0x19f) & 0xff


def model_checksum_instructions(code, source, length_argument, mode=0, step_limit=100000):
    """Small fail-closed MIPS interpreter for the checksum's integer subset.

    Its memory contains only synthetic source/destination byte arrays. It
    models branch delay slots and branch-likely nullification. Unsupported
    opcodes, out-of-range memory and nontermination fail instead of guessing.
    It is not a camera emulator and performs no external calls.
    """
    if len(code) != 0xc4 or not 1 <= length_argument < len(source):
        raise ValueError("Need checked 0xc4-byte code and source through offset N")
    base, src, dst, end = 0x1000, 0x100000, 0x200000, 0x300000
    registers = [0] * 32
    registers[4:8] = [mode & 0xffffffff, dst, src, length_argument]
    registers[31] = end
    memory = {src + i: value for i, value in enumerate(source)}
    destination = bytes([0xa5]) * len(source)
    memory.update({dst + i: value for i, value in enumerate(destination)})
    read_addresses, written_addresses = [], []
    words = struct.unpack("<49I", code)
    steps = 0

    def execute(pc, allow_control=True):
        nonlocal steps
        steps += 1
        if steps > step_limit or pc % 4 or not base <= pc < base + len(code):
            raise ValueError("Checksum model exceeded bounded code/step range")
        word = words[(pc - base) // 4]
        op, rs, rt, rd, fn = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31, word & 63
        immediate = word & 65535
        signed = immediate - 65536 if immediate & 32768 else immediate
        control = None
        if op == 0 and fn in (33, 37):
            value = registers[rs] + registers[rt] if fn == 33 else registers[rs] | registers[rt]
            registers[rd] = value & 0xffffffff
        elif op == 0 and fn == 0 and word == 0:
            pass
        elif op == 9:
            registers[rt] = (registers[rs] + signed) & 0xffffffff
        elif op == 11:
            registers[rt] = int(registers[rs] < (signed & 0xffffffff))
        elif op == 12:
            registers[rt] = registers[rs] & immediate
        elif op in (36, 40):
            address = (registers[rs] + signed) & 0xffffffff
            if address not in memory:
                raise ValueError("Checksum model read/write outside synthetic memory")
            if op == 36:
                registers[rt] = memory[address]
                read_addresses.append(address)
            else:
                memory[address] = registers[rt] & 0xff
                written_addresses.append(address)
        elif op in (4, 5, 20):
            taken = registers[rs] == registers[rt]
            if op == 5:
                taken = not taken
            # Target addresses are expressed relative to our rebased code.
            control = (taken, pc + 4 + signed * 4, op == 20)
        elif op == 0 and fn == 8:
            control = (True, registers[rs], False)
        else:
            raise ValueError(f"Unsupported checksum-model instruction {word:#x}")
        registers[0] = 0
        if control and not allow_control:
            raise ValueError("Control transfer in checksum delay slot")
        return control

    pc = base
    while pc != end:
        control = execute(pc)
        if control:
            taken, target, likely = control
            if taken or not likely:
                execute(pc + 4, allow_control=False)
            pc = target if taken else pc + 8
        else:
            pc += 4
    return {"value": registers[2], "destination": bytes(memory[dst+i] for i in range(len(source))),
            "source_read_offsets": sorted(set(address - src for address in read_addresses if src <= address < src + len(source))),
            "destination_write_offsets": sorted(set(address - dst for address in written_addresses if dst <= address < dst + len(source))),
            "steps": steps}


def verify_checksum_model(code):
    random_source = random.Random(3300)
    cases = 0
    for length in (1, 2, 3, 4, 15, 255, 414, 415, 416, 1024):
        for source in (bytes(length + 3), bytes([255]) * (length + 3),
                       bytes(random_source.randrange(256) for _ in range(length + 3))):
            for mode in (0, 1, 0x100, 0x101):
                result = model_checksum_instructions(code, source, length, mode)
                if result["value"] != settings_sum(source, length):
                    raise ValueError("Independent checksum instruction model disagrees")
                copied = bool(mode & 255)
                expected_destination = source[:length+1] + bytes([0xa5]) * (len(source) - length - 1) if copied else bytes([0xa5]) * len(source)
                if result["destination"] != expected_destination:
                    raise ValueError("Independent checksum copy model disagrees")
                cases += 1
    return {"cases": cases, "all_agree": True, "scope": "Synthetic memory; exact checksum-helper instruction words; no hardware or whole-camera execution"}


def checked_table(mapping, address, expected):
    observed = list(struct.unpack(f"<{len(expected)}I", mapping.read(address, len(expected) * 4)))
    if observed != expected:
        raise ValueError(f"Reviewed table changed at {address:#x}")
    return observed


def build_report(workspace, source_path):
    source = source_path.read_bytes()
    if digest(source) != BASELINE:
        raise ValueError("Unsupported vendor source identity")
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw, manifest["regions"])
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    windows, instructions = [], {}
    for label, address, size in WINDOWS:
        body = mapping.read(address, size)
        decoded = list(decoder.disasm(body, address))
        if sum(i.size for i in decoded) != size:
            raise ValueError(f"Incomplete linear decode: {label}")
        instructions.update({i.address: (i.mnemonic, i.op_str) for i in decoded})
        windows.append({"label": label, "address": address, "bytes": size,
                        "sha256": digest(body), "boundary": "bounded analyst window; not a recovered complete function"})
    for address, expected in ASSERTIONS.items():
        if instructions.get(address) != expected:
            raise ValueError(f"Reviewed instruction changed at {address:#x}")
    tables = {
        "media_device_selector": checked_table(mapping, 0x800eb26c, [0x800e415c,0x800e415c,0x800e4154,0x800e4148,0x800e4140,0x800e4114,0x800e4114,0x800e4114,0x800e4114]),
        "media_operation_selector": checked_table(mapping, 0x800eb290, [0x800e4188,0x800e417c,0x800e4170,0x800e4164,0x800e40e8]),
        "device1_backend_selector": checked_table(mapping, 0x800eaf04, [0x800e2844,0x800e28cc,0x800e28e4,0x800e2910,0x800e2888]),
    }
    model = verify_checksum_model(mapping.read(0x80008f80, 0xc4))
    artifact_profiles = []
    for offset in (0x200,0x1006c0,0x1026c0,0x2202c0,0x3bd9a8,0x5c2b78):
        elf = ELFFile(BytesIO(source[offset:]))
        artifact_profiles.append({"carrier_offset": offset, "machine": elf.header["e_machine"],
            "flags": elf.header["e_flags"], "entry": elf.header["e_entry"],
            "abi_flags_sections": [s.name for s in elf.iter_sections() if s.name == ".MIPS.abiflags"],
            "type": elf.header["e_type"], "byte_order": "little" if elf.little_endian else "big"})
    return {
        "schema_version": 1, "source_sha256": BASELINE, "analysis_sha256": digest(raw),
        "method": "Independent authenticated static Python/Capstone plus bounded checksum instruction model",
        "rea_evidence": False, "native_decompiler_evidence": False,
        "target_binary_executed": False, "checksum_semantics_emulated_on_synthetic_memory": True,
        "camera_commands_issued": False, "instruction_assertions": len(ASSERTIONS),
        "reviewed_windows": windows, "checked_tables": tables, "checksum_model_validation": model,
        "contracts": [
            {"id": "settings.checksum", "status": "static-contract-verified", "address": 0x80008f80,
             "arguments": {"a0": "mode low8; zero calculates only, nonzero also copies", "a1": "destination pointer in copy mode; ignored for calculate-only", "a2": "source byte pointer", "a3": "N; valid modeled domain1..1024"},
             "return": "sum(source[0:N-1]) modulo65536; source offsets0..N-2 inclusive",
             "copy_mode": "Copies N+1 bytes, offsets0..N inclusive; excludes final two copied bytes from sum",
             "settings_call_N": 0x19f, "settings_covered_bytes": 0x19e, "settings_checksum_offset": 0x19f,
             "settings_serialized_bytes": 0x1a0, "settings_stored_formula": "sum(store[0:0x19e]) modulo256",
             "unchecked_byte_offset": 0x19e,
             "limits": "N<=0 can underflow target loops; this host API rejects it. Overlap/null/alias behavior is not a supported public copying contract. No settings are written."},
            {"id": "settings.media_route", "status": "partial", "address": 0x80009644,
             "router": 0x800e408c, "selected_device": 1, "operation_order": [2,1,0],
             "operation_to_driver_selector": {"2": 8, "1": 5, "0": 4},
             "driver_entry": 0x800e2800, "driver_dispatch": 0x80063aec,
             "write_read_count": 2, "staging_buffer_bytes": 0x400, "serialized_settings_bytes": 0x1a0,
             "erase_position_rule": "operation2 divides position from global0x80003258 by1<<u16(handle+0x11c4)",
             "inference": "selectors8/5/4 are erase-like/write-like/read-like based on position conversion, buffer direction and verification order",
             "unknowns": ["physical address and erase extent", "live device geometry and flags", "calibration overlap", "atomicity/wear policy", "recovery after power loss"]},
            {"id": "image.command15_dirty_consumer", "status": "partial", "address": 0x801fbc8c,
             "arguments": {"a0": "driver/context pointer", "a1": "pointer to two-word dirty mask", "stack_arg6": "numeric context index"},
             "mask": 0x100000, "mask_check": 0x801fc15c, "mask_branch": 0x801fc16c,
             "selected_cache_subindex": 15, "cache_selector": 0x801fbb3c,
             "cache_rule": "0x808c1d88+4*(74*context_index+37*bank+subindex); context2/5 can fallback tocontext0 when its pointer is null",
             "driver_command_receiver": 0x80192e04,
             "mask_clear_sites": [0x801fc484,0x801fc488],
             "context5_caller": 0x802a8a50, "context5_callsite": 0x802a8aa4,
             "unknowns": ["numeric context5 ordinary saved-still identity", "current driver type", "final matrix MMIO application"]},
            {"id": "image.driver_command_stage", "status": "partial", "address": 0x80192e04,
             "driver_type_field": 4,
             "type0": "calls0x8019e724 ->0x802e57a8 with driver object field+0x880 and retained command",
             "type5": "retains command payload in driver-owned command slots; no immediate hardware upload established",
             "stage_entry": 0x802e57a8, "stage_slot_rule": "driver+0x48+12*command_id; command_id<37",
             "stage_observations": ["allocates/reuses a command-length-sized copy", "writes status byte3 at slot+9", "sets driver+0x324 bit1", "sets driver+0x320 to4"],
             "unknowns": ["stage scheduler/consumer", "final MMIO matrix encoding", "buffer lifetime across async completion", "saved JPEG runtime verification"]},
        ],
        "artifact_profiles": artifact_profiles,
        "development_gates": {
            "settings_checksum_model_verified": True, "settings_writer_safe_public_api": False,
            "saved_photo_buffer_abi_verified": False, "executable_hook_verified": False,
            "executable_placement_verified": False, "software_unbootable_recovery_verified": False,
            "code_trial_allowed": False,
            "explanation": "A compiler output and valid packed patch are not proven placement, hook safety or recovery. Zero-filled gaps and unused bytes are not designated code caves."},
        "limitations": [
            "This static pass does not prove all active saved-photo, driver, storage or boot paths.",
            "A known menu update rollback requires a running application and is not unbootable recovery.",
            "No arbitrary monitor, GetMem/SetMem, NAND dump or device command is invoked.",
            "Original ELF headers/flags are retained, including absent ABI metadata; tiny loader profile is separate.",
            "Settings checksum coverage is independent of the firmware-update additive checksum."]}


def write_report(report, workspace, output, listings):
    if output.exists() or listings.exists():
        raise FileExistsError("Choose new evidence and listings paths")
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw, manifest["regions"])
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    texts = []
    for row in report["reviewed_windows"]:
        body = mapping.read(row["address"], row["bytes"])
        if digest(body) != row["sha256"]:
            raise ValueError("Window changed before output")
        text = "; Bounded static window. Not target execution or a complete-function claim.\n"
        text += "\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in decoder.disasm(body, row["address"])) + "\n"
        texts.append((row["label"], text))
    listings.mkdir(parents=True)
    for label, text in texts:
        (listings / (label + ".asm")).write_text(text, encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE)
    parser.add_argument("--source", type=Path, default=ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin")
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/development-contracts.json")
    parser.add_argument("--listings", type=Path, default=ROOT/"derived/development-contracts")
    args = parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise FileExistsError("Choose new evidence and listings paths")
    report = build_report(args.workspace.resolve(), args.source.resolve())
    write_report(report, args.workspace.resolve(), args.output.resolve(), args.listings.resolve())
    print(json.dumps({"contracts": len(report["contracts"]), "checksum_model": report["checksum_model_validation"],
                      "code_trial_allowed": False}))


if __name__ == "__main__":
    main()
