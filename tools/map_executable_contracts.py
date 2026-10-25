"""Map source-authenticated executable placement, startup and hook constraints.

This emits research evidence only. It neither selects a free code cave nor
constructs patches, executes target code or enables executable camera trials.
"""
import argparse
from bisect import bisect_right
from contextlib import closing
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys

from elftools.elf.elffile import ELFFile
from workspace_functions import load_analysis
from map_development_interfaces import AddressMap

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
DEFAULT_WORKSPACE = ROOT / "derived/unpacked-v1.1-indexed"
DEFAULT_NATIVE = ROOT / "derived/native-analysis-complete"
DEFAULT_INDEX = ROOT / "derived/native-index-final/native.sqlite"
ASSERTIONS = {
    0x80000624: "11801c3c", 0x80000628: "80ef9c27",
    0x8000062c: "9f801d3c", 0x80000630: "6821bd27",
    0x8000063c: "08006001", 0x800006c8: "01780440",
    0x800006d4: "19004310", 0x800006ec: "80c86425",
    0x800006f0: "74154925", 0x80000700: "0cbf030c",
    0x80000710: "f06fe424", 0x80000714: "0876a624",
    0x8000071c: "0cbf030c", 0x800ce7e4: "78212925",
    0x800ce7fc: "78312925", 0x800ce808: "480289ad",
    0x800ce80c: "00100d24", 0x800ce820: "a80189ad",
    0x80020844: "ebf0000c", 0x8002085c: "24180302",
    0x80020860: "24800402", 0x8002087c: "2368c301",
    0x80020880: "fcffac25", 0x80020888: "6981000c",
    0x800df4a4: "0182000c", 0x80000d38: "1c00023c",
    0x80000d40: "00204234", 0x800b45b0: "000070bc",
    0x800b3c94: "000071bc", 0x800b551c: "000075bc",
    0x800b47f8: "000079bc", 0x80205918: "21608000",
    0x80205924: "38ffbd27", 0x80205958: "08014014",
}
FUNCTIONS = (0x80000600, 0x80000d38, 0x80020768, 0x80020804,
             0x80020980, 0x800b22fc, 0x800b2364, 0x800b256c,
             0x800b3680, 0x800b3a9c, 0x800b43bc, 0x800b4614,
             0x800b52e4, 0x800ce7c8, 0x800df450, 0x800efc30)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def checked_instructions(mapping, assertions=ASSERTIONS):
    for address, expected in assertions.items():
        if mapping.read(address, 4).hex() != expected:
            raise ValueError(f"Executable contract instruction differs at {address:#x}")
    return len(assertions)


def jump_target(word, pc):
    if pc & 3 or word >> 26 not in (2, 3):
        raise ValueError("Expected an aligned standard MIPS J/JAL instruction")
    return ((pc + 4) & 0xf0000000) | ((word & 0x03ffffff) << 2)


def direct_jump_reachable(pc, target):
    if not 0 <= pc <= 0xffffffff or not 0 <= target <= 0xffffffff or (pc | target) & 3:
        return False
    return ((pc + 4) & 0xf0000000) == (target & 0xf0000000)


def branch_target(pc, immediate):
    if pc & 3 or not 0 <= immediate <= 0xffff:
        raise ValueError("Expected aligned MIPS PC and u16 branch displacement")
    signed = immediate - 0x10000 if immediate & 0x8000 else immediate
    return (pc + 4 + signed * 4) & 0xffffffff


def pool_extent(start, dram_bytes):
    """Transcribe arithmetic, preserving unsigned wrap; does not grant ownership."""
    if type(start) is not int or type(dram_bytes) is not int or not 0 <= start <= 0xffffffff or not 0 <= dram_bytes <= 0xffffffff:
        raise ValueError("Expected u32 allocation inputs")
    return {"cached_start": start & 0xdfffffff,
            "length": (dram_bytes - (start & 0x0fffffff) - 4) & 0xffffffff,
            "runtime_inputs_measured": False, "safe_code_placement": False}


def zero_runs(body, base, minimum=32):
    if minimum < 4:
        raise ValueError("Use a nontrivial zero-run minimum")
    return [{"start": base + match.start(), "end_exclusive": base + match.end(),
             "bytes": match.end() - match.start(), "safe_code_placement": False}
            for match in re.finditer(b"\x00{" + str(minimum).encode() + b",}", body)]


def load_dossier(native, address, mapping):
    path = native / "application/functions" / f"{address:08x}.json"
    record = json.loads(path.read_text())
    if int(record["address"], 16) != address:
        raise ValueError("Native dossier entry differs")
    checked = 0
    for instruction in record["instructions"]:
        location = int(instruction["address"], 16)
        expected = bytes.fromhex(instruction["bytes"])
        if not expected or mapping.read(location, len(expected)) != expected:
            raise ValueError("Ghidra instruction bytes differ from authenticated image")
        checked += 1
    return {"address": address, "source_file": path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path),
            "dossier_sha256": sha(path.read_bytes()), "name_inferred": record["name"],
            "ranges_inferred": record["ranges"], "decompilation_completed": record.get("decompilation_completed", False),
            "instructions_byte_checked": checked,
            "signature_warning": "Ghidra pseudocode/signatures are inference, not a proven runtime ABI"}


def build_report(workspace=DEFAULT_WORKSPACE, native=DEFAULT_NATIVE, index=DEFAULT_INDEX, source=None):
    source = source or ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    raw_source = Path(source).read_bytes()
    if sha(raw_source) != SOURCE_SHA:
        raise ValueError("Original source digest differs")
    manifest, raw = load_analysis(Path(workspace))
    mapping = AddressMap(raw, manifest["regions"])
    checked = checked_instructions(mapping)
    native = Path(native).resolve()
    profile = json.loads((native / "profile.json").read_text())
    if profile["source_sha256"] != SOURCE_SHA or profile["analysis_sha256"] != sha(raw):
        raise ValueError("Native profile source identity differs")
    with closing(sqlite3.connect(Path(index).resolve(strict=True).as_uri() + "?mode=ro", uri=True)) as database:
        database.row_factory = sqlite3.Row
        metadata = dict(database.execute("SELECT key,value FROM metadata"))
        if metadata.get("source_sha256") != SOURCE_SHA or metadata.get("analysis_sha256") != sha(raw):
            raise ValueError("Native index source metadata differs")
        known_entries = [row[0] for row in database.execute("SELECT address FROM functions ORDER BY address")]
    dossiers = [load_dossier(native, address, mapping) for address in FUNCTIONS]
    images = []
    for offset in (0x200, 0x1006c0, 0x1026c0, 0x2202c0, 0x3bd9a8, 0x5c2b78):
        elf = ELFFile(BytesIO(raw_source[offset:]))
        images.append({"carrier_offset": offset, "entry": elf.header["e_entry"],
                       "flags_hex": hex(elf.header["e_flags"]),
                       "abi_flags_record_present": elf.get_section_by_name(".MIPS.abiflags") is not None,
                       "segments": [{key: segment[key] for key in ("p_type", "p_vaddr", "p_filesz", "p_memsz", "p_flags")}
                                    for segment in elf.iter_segments()]})
    gaps, zero_candidates = [], []
    main_regions = sorted((r for r in manifest["regions"] if r["virtual_start"] < 0x90000000), key=lambda r: r["virtual_start"])
    for previous, current in zip(main_regions, main_regions[1:]):
        begin = previous["virtual_start"] + previous["size"]
        if begin < current["virtual_start"]:
            gaps.append({"start": begin, "end_exclusive": current["virtual_start"],
                         "bytes": current["virtual_start"] - begin,
                         "has_source_bytes": False, "safe_code_placement": False})
    for region in manifest["regions"]:
        if region["permissions"] & 1:
            offset, length = region["analysis_elf_offset"], region["size"]
            for candidate in zero_runs(raw[offset:offset + length], region["virtual_start"]):
                candidate["region"] = region["name"]
                candidate["native_function_entries_inside"] = bisect_right(known_entries, candidate["end_exclusive"] - 1) - bisect_right(known_entries, candidate["start"] - 1)
                zero_candidates.append(candidate)
    # These 32-bit return/call encodings have delay-slot effects. Do not turn
    # source inspection into a patch writer or assume source clauses are dead.
    hook_examples = []
    for site in (0x800006dc, 0x80020844, 0x80020888, 0x800df4a4):
        words = struct.unpack("<II", mapping.read(site, 8))
        hook_examples.append({"site": site, "target": jump_target(words[0], site),
                              "instruction_hex": mapping.read(site, 4).hex(),
                              "delay_slot_hex": mapping.read(site + 4, 4).hex(),
                              "architectural_link_address": site + 8,
                              "synthetic_sdk_direct_jump_reachable": direct_jump_reachable(site, 0x10000)})
    report = {
        "schema_version": 1, "date_local": "2026-10-25", "timezone": "Asia/Calcutta",
        "source_sha256": SOURCE_SHA, "analysis_sha256": sha(raw),
        "evidence_class": "independent checked instructions plus direct Ghidra static dossiers; not native REA Evidence",
        "original_images": images, "reviewed_instruction_assertions": checked,
        "native_dossiers": dossiers,
        "startup": {"entry": 0x80000600, "gp": 0x8010ef80, "initial_sp": 0x809f2168,
                    "continuation": 0x800006c0,
                    "zeroing_condition": "CP0 EBase select1 low10 bits != 1",
                    "clear_routine": 0x800efc30,
                    "zeroed_ranges": [{"start": 0x8089c880, "end_exclusive": 0x809f1574, "bytes": 0x154cf4},
                                      {"start": 0x80106ff0, "end_exclusive": 0x80107608, "bytes": 0x618}],
                    "safe_placement_in_zeroed_ranges": False},
        "rtos_reservations": {"routine": 0x800ce7c8, "timer_stack_bytes": 0x1000,
                              "context_zero": {"state": 0x800d1ad4, "stack_start": 0x809f3178, "stack_end_exclusive": 0x809f4178},
                              "context_nonzero": {"state": 0x800d4b34, "stack_start": 0x809f2178, "stack_end_exclusive": 0x809f3178},
                              "writes": {"saved_sp_state_offset": 0, "stack_start_offset": 0x248, "stack_length_offset": 0x24c, "end_passed_to_allocator_offset": 0x1a8},
                              "physical_core_count_established": False},
        "allocator": {"initializer": 0x80020804, "boot_caller": 0x800df450,
                      "dram_query": 0x8003c3ac, "pool_constructor": 0x800205a4,
                      "pool_start_formula": "input_start & 0xdfffffff",
                      "pool_length_formula": "(queried_DRAM_bytes - (input_start & 0x0fffffff) - 4) modulo2^32",
                      "subpool_initializer": 0x80020768,
                      "default_subpool_bytes": 0x380000,
                      "boot_override_getter": 0x80000d38, "boot_override_bytes": 0x1c2000,
                      "second_subpool_bytes": 0x180000, "second_subpool_unit_hint": 0x200,
                      "installed_capacity_and_free_headroom_known": False,
                      "heap_is_owned_runtime_memory": True},
        "cache_contracts": [
            {"function": 0x800b43bc, "parameters": "a0=address,a1=length; null/zero assert", "operation": "cache0x10", "instruction_site": 0x800b45b0,
             "role_inference": "I-cache invalidation path", "line_exponent_field": "context+0x29c"},
            {"function": 0x800b3a9c, "parameters": "a0=address,a1=length; null/zero assert", "operation": "cache0x11", "instruction_site": 0x800b3c94,
             "role_inference": "D-cache invalidation path", "line_exponent_field": "context+0x2a0"},
            {"function": 0x800b52e4, "parameters": "a0=address,a1=length; null/zero use whole-cache fallback", "operation": "cache0x15", "instruction_site": 0x800b551c,
             "role_inference": "D-cache writeback/invalidation candidate", "line_exponent_field": "context+0x2a0"},
            {"function": 0x800b4614, "parameters": "a0=address,a1=length; complete invalid-input policy not established", "operation": "cache0x19", "instruction_site": 0x800b47f8,
             "role_inference": "D-cache writeback candidate", "line_exponent_field": "context+0x2a0"}],
        "cache_limits": ["Cache geometry comes from runtime CP0 Config1/context state, not supplied bytes.",
                         "Reviewed paths can switch to tag scans and invoke timing/interrupt helpers0x800b22fc/0x800b2364; not passive APIs.",
                         "No complete cross-context DMA/code-publication synchronization sequence is established."],
        "call_and_hook_constraints": {"known_application_header": "ELF32 little-endian MIPS32r2/o32,0x70001001; no floating-point ABI record",
                                      "call_examples": hook_examples,
                                      "known_first_instruction": {"function_candidate": 0x80205918, "meaning": "move t4,a0 before pointer checks and stack allocation", "interior_stack_allocation": 0x80205924, "native_function_entry_discovered": 0x80205918 in known_entries, "boundary_type": "reviewed instruction window; no matching native function entry"},
                                      "hazards": ["J/JAL uses high4 bits of PC+4 and has a branch delay slot; JAL link is PC+8.",
                                                  "Conditional branches use signed16-word displacements; branch-likely annuls an untaken delay slot.",
                                                  "Preserve displaced instructions, live arguments, caller/callee-saved state, gp and stack conventions at each actual hook.",
                                                  "The SDK's0x10000 synthetic address cannot be reached by direct J/JAL from0x8xxxxxxx.",
                                                  "Tiny loader entry0x81000401 is odd and flags0x10001000 differ; instruction mode requires separate recovery.",
                                                  "Generated o32 integer code and emulator preservation tests do not establish an executable insertion/return/cache ABI for the camera."]},
        "unbacked_gaps": gaps,
        "zero_run_scan": {"minimum_bytes": 32, "executable_permission_regions_only": True,
                          "count": len(zero_candidates), "total_bytes": sum(r["bytes"] for r in zero_candidates),
                          "largest_candidates": sorted(zero_candidates, key=lambda r: (-r["bytes"], r["start"]))[:32],
                          "safe_candidates_proven": 0,
                          "limit": "Zero bytes, ELF execute permission, absent entries and unmapped address gaps do not prove unused ownership or loader support."},
        "gates": {"camera_code_placement_verified": False, "executable_hook_abi_verified": False,
                  "complete_code_cache_publication_verified": False, "software_recovery_verified": False,
                  "executable_trials_allowed": False},
        "target_executed": False, "device_commands_issued": False, "patch_constructed": False,
        "source_unchanged": sha(Path(source).read_bytes()) == SOURCE_SHA,
        "remaining": ["Verified owner/lifetime/loader destination for an executable placement", "Complete hook live-state and instruction-mode contract", "Validated runtime cache/coherency sequence", "Software recovery independent of a functioning modified application"]}
    if not report["source_unchanged"]:
        raise ValueError("Source changed during analysis")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--native", type=Path, default=DEFAULT_NATIVE)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/executable-contracts.json")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh evidence path; prior results are never replaced")
    report = build_report(args.workspace.resolve(), args.native.resolve(), args.index.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"output": str(args.output), "checked_instructions": report["reviewed_instruction_assertions"],
                      "native_dossiers_checked": len(report["native_dossiers"]), "zero_run_candidates": report["zero_run_scan"]["count"],
                      "safe_code_placements": 0, "executable_trials_allowed": False}))


if __name__ == "__main__":
    main()
