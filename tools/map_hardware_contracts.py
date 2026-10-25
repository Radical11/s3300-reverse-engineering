"""Reproduce offline hardware-contract leads from authenticated S3300 v1.1.

Independent Python/Capstone evidence, not a native REA Evidence record. No
camera access, emulation, register reads, firmware edits, or target execution.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from map_development_interfaces import AddressMap, ELF_SHA, SOURCE_SHA
from workspace_functions import recover_ranges

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    "processor_and_platform": r"Zoran|ZORAN|ThreadX|FileX|_tx_|MCPU|SCPU|Main CPU|COP CPU|ARC CPU|ConfigSensorC13|DriverClocksOnC13",
    "memory_and_allocation": r"(?:main|internal) DRAM|dram size|DRAM size|DDR selection|DRAM selection|Dram params|Allocator|allocat(?:or|ion)|MemPool|Heap|heap|CppMalloc|DRAM_WIDTH|Dcu/Dram",
    "clocks": r"CGU|Cgu|PLL|clock frequency|Clock Statistics|boot clock|Requested frequency|Reachable frequency|Achieved.*frequency|CguGetFrequency|Configure and Enable Clock|Disable Clock",
    "sensor": r"Os/Sensor/|SensorGetCaps|SensorSetCaps|SensorSetMode|SensorQueue|SensorReady|SensorProcessed|SensorFree|Sensor.*Mutex|FRAME_TIME_US|READOUT|SCAN_DEPTH",
    "dma_and_memory_controller": r"Os/Dma/|DmaEvents|DmaCopyMutex|dma channels|DMA Transfer|DCU_|Os/Dcu/|Dcu.*Config|DRAM Transactions",
    "peripherals": r"Os/Gpio/|GPIO|GSIU|I2C|IIC|SPI|JTAG|jtag|UsbSetAddress|Os/Usb/|Real-Time-Clock",
}
COMPILED = {key: re.compile(value, re.I) for key, value in RULES.items()}
LOADS = {32: "lb", 33: "lh", 35: "lw", 36: "lbu", 37: "lhu"}
STORES = {40: "sb", 41: "sh", 43: "sw"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def categories(text):
    return [key for key, pattern in COMPILED.items() if pattern.search(text)]


def signed16(word):
    value = word & 0xffff
    return value - 0x10000 if value & 0x8000 else value


def scan_constants(data, base, targets=(), max_age=12):
    """Conservative straight-line MIPS32 constant syntax, not value-flow proof.

    Forget constants across control transfers and their delay slots. Recognize
    LUI, ADDIU, ORI and zero-copy ADDU/OR; invalidate other recognized register
    writes and all unknown opcodes. This intentionally misses computed/indexed,
    cross-block, longer-lived and interprocedural addresses. No CFG is executed.
    """
    known = {}
    accesses, references = [], []
    skip_delay = False
    for offset in range(0, len(data) - 3, 4):
        address = base + offset
        word = struct.unpack_from("<I", data, offset)[0]
        op, rs, rt, rd, fn = word >> 26, word >> 21 & 31, word >> 16 & 31, word >> 11 & 31, word & 63
        if skip_delay:
            skip_delay = False
            continue
        known = {reg: entry for reg, entry in known.items() if address - entry[1] <= max_age * 4}
        # Includes J/JAL, REGIMM, ordinary/likely branches and JR/JALR.
        if op in (1, 2, 3, 4, 5, 6, 7, 20, 21, 22, 23) or (op == 0 and fn in (8, 9)):
            known.clear()
            skip_delay = True
            continue
        if op == 15:
            if rt:
                known[rt] = ((word & 0xffff) << 16, address)
        elif op in (9, 13):
            entry = known.get(rs, (0, address)) if rs == 0 else known.get(rs)
            known.pop(rt, None)
            if entry and rt:
                value = ((entry[0] + signed16(word)) if op == 9 else (entry[0] | (word & 0xffff))) & 0xffffffff
                known[rt] = (value, entry[1])
                if value in targets:
                    references.append({"target": value, "lui_or_origin_address": entry[1],
                                       "materialization_address": address, "instruction_word": f"{word:08x}"})
        elif op in LOADS or op in STORES:
            entry = known.get(rs)
            if entry:
                value = (entry[0] + signed16(word)) & 0xffffffff
                if 0xb0000000 <= value < 0xc0000000:
                    accesses.append({"instruction_address": address, "address": value,
                        "operation": LOADS.get(op, STORES.get(op)), "access": "read" if op in LOADS else "write",
                        "lui_or_origin_address": entry[1], "instruction_word": f"{word:08x}"})
            if op in LOADS:
                known.pop(rt, None)
        elif op == 0 and fn in (33, 37) and (rs == 0 or rt == 0):
            entry = known.get(rt if rs == 0 else rs)
            known.pop(rd, None)
            if entry and rd:
                known[rd] = entry
        elif op == 0 and fn in (0, 2, 3, 4, 6, 7, 16, 18, 32, 33, 34, 35, 36, 37, 38, 39, 42, 43):
            known.pop(rd, None)
        elif op in (8, 10, 11, 12, 14, 34, 38, 48):
            known.pop(rt, None)
        elif op == 0 and fn in (17, 19, 24, 25, 26, 27):
            pass  # HI/LO writes do not change integer registers.
        else:
            known.clear()
    return accesses, references


def string_inventory(raw, regions):
    rows = []
    for region in regions:
        body = raw[region["analysis_elf_offset"]:region["analysis_elf_offset"] + region["size"]]
        for match in re.finditer(rb"[ -~]{4,}", body):
            text = match.group().decode("ascii")
            groups = categories(text)
            if groups:
                rows.append({"address": region["virtual_start"] + match.start(), "text": text,
                             "categories": groups, "source_region_start": region["virtual_start"],
                             "region_offset": match.start(), "references": []})
    return rows


def command_inventory(mapping, raw, regions):
    rows = []
    for region in regions:
        body = raw[region["analysis_elf_offset"]:region["analysis_elf_offset"] + region["size"]]
        for offset in range(0, len(body) - 15, 4):
            pointers = struct.unpack_from("<4I", body, offset)
            if not all(0x80000000 <= p < 0x81000000 for p in pointers) or pointers[3] % 4:
                continue
            try:
                name = mapping.text(pointers[0], 65)
                if not re.fullmatch(r"[a-z_?][A-Za-z0-9_?.-]{0,62}", name):
                    continue
                command = mapping.command(region["virtual_start"] + offset)
            except ValueError:
                continue
            groups = categories(" ".join((name, command["arguments"], command["description"])))
            if groups:
                rows.append({**command, "categories": groups,
                    "classification": "Four-pointer command-record candidate; transport exposure unverified",
                    "device_invocation": "Not performed; many hardware diagnostics mutate state"})
    return rows


WINDOWS = [
    ("dram_size_handler", 0x803e7238, 0xa8),
    ("dram_attributes_api", 0x8003c3ac, 0xd0),
    ("clock_frequency_table_lookup", 0x80025198, 0x28),
    ("clock_operation_handler", 0x80405828, 0x1ec),
    ("clock_configure_handler", 0x80405b00, 0x2f4),
    ("gpio_output_handler", 0x8040c3e4, 0xc8),
    ("gpio_input_handler", 0x8040c4ac, 0xb8),
    ("gpio_enable_api", 0x800a1468, 0x118),
    ("gpio_direction_api", 0x800a1580, 0x178),
    ("gpio_pin_set_get_api", 0x800a16f8, 0x5c),
    ("allocator_initialize", 0x80020804, 0xd4),
    ("allocator_dispatch_entry", 0x80020980, 0x8c),
    ("rtos_semaphore_get_entry", 0x800c3b18, 0x168),
    ("dma_transaction_submit", 0x8005d208, 0x84),
]


def reviewed_contracts(mapping):
    table = list(struct.unpack("<7I", mapping.read(0x80045cb0, 28)))
    expected = [0x8003c3e0, 0x8003c420, 0x8003c43c, 0x8003c46c, 0x8003c44c, 0x8003c45c, 0x8003c3e8]
    if table != expected:
        raise ValueError("DRAM selector table differs from reviewed source")
    # Each constant is checked at its reviewed instruction, rather than inferred
    # from the address span or generic memory-library strings.
    sizes = [None, 8 << 20, 16 << 20, 32 << 20, 64 << 20, 128 << 20, 256 << 20]
    sites = [None, 0x8003c424, 0x8003c440, 0x8003c470, 0x8003c450, 0x8003c460, 0x8003c3ec]
    for value, site in zip(sizes[1:], sites[1:]):
        instruction = struct.unpack("<I", mapping.read(site, 4))[0]
        if instruction >> 26 != 15 or (instruction & 0xffff) << 16 != value:
            raise ValueError("DRAM size constant differs from reviewed source")
    gpio_groups = []
    for group in range(11):
        address = 0x800a2264 + group * 0x54
        row = mapping.read(address, 0x54)
        base = struct.unpack_from("<I", row, 8)[0]
        if not 0xb0020000 <= base < 0xb0024000:
            raise ValueError("GPIO table register-base pointer differs")
        gpio_groups.append({"group": group, "record_address": address, "register_base": base,
                            "map0_bytes": list(row[0x14:0x34]), "map1_bytes": list(row[0x34:0x54])})
    return {
        "dram_attributes": {
            "evidence_type": "Reviewed bounded static disassembly plus checked jump-table words",
            "api_address": 0x8003c3ac, "handler": 0x803e7238, "command": "dramsize",
            "selector_register": 0xb8002010, "selector_read_instruction": 0x8003c3b4,
            "jump_table": 0x80045cb0,
            "selector_cases": [{"selector": i, "branch_target": target, "reported_bytes": size,
                                 "constant_instruction": site}
                               for i, (target, size, site) in enumerate(zip(table, sizes, sites))],
            "api_contract": "Returns zero for selector 0 or values >=7. Cases 1..6 return one. Non-null a1 receives the supported DRAM byte-size value. Other non-null output arguments receive attributes; byte-size query handler passes a2=a3=arg5=0.",
            "address_alias_outputs": {"a3": "0x80000000", "stack_arg5": "0xa0000000"},
            "handler_contract": "Calls API with a1=&stack_u32; if success, shifts byte count right 20 for MiB and multiplies that result by eight for printed Mbit. No actual selector value was read.",
            "actual_installed_ram_bytes": None,
            "limitation": "Six supported software cases are not six observed devices; register reset/current value and actual camera geometry remain unknown."},
        "clock_interface": {
            "evidence_type": "Reviewed bounded static disassembly; runtime state unavailable",
            "frequency_lookup_api": 0x80025198, "frequency_table": 0x808a5b8c,
            "frequency_table_entries": 56, "frequency_table_entry_bytes": 4,
            "lookup_contract": "Index a0 is checked unsigned <0x38; returns indexed u32 at 0x808a5b8c or zero. Table contents are outside the file-backed analysis image.",
            "operation_handler": 0x80405828, "configure_handler": 0x80405b00,
            "configure_api_candidate": 0x80025ec8,
            "finding": "cguop get path passes parsed/default clock ID to frequency lookup; set path validates a requested frequency then prints reachable and achieved values. cgucfgen parses clock id/frequency/mode and invokes configuration paths.",
            "measured_cpu_hz": None, "clock_id_names_and_units": "Frequency diagnostics say Hz; exact ID-to-clock table remains unresolved",
            "limitation": "An available frequency getter does not reveal the installed operating clock or authorize clock changes."},
        "platform_identity": {
            "evidence_type": "Embedded diagnostic/source-path strings, not a chip-ID read",
            "observed_names": ["Zoran", "ThreadX", "FileX", "MCPU", "SCPU", "ConfigSensorC13.c"],
            "inference": "Firmware contains Zoran camera-platform software, ThreadX-named RTOS diagnostics and FileX-named filesystem objects. C13 and multiple processor labels are software-family leads.",
            "exact_soc": None, "exact_sensor": None, "installed_cpu_topology": None,
            "limitation": "Bundled drivers and monitor help can cover unused hardware variants; strings do not prove fitted chips or enabled cores."},
        "gpio": {
            "evidence_type": "Reviewed driver/monitor disassembly plus checked file-backed table",
            "table_address": 0x800a2264, "record_stride": 0x54, "observed_groups": gpio_groups,
            "output_handler": 0x8040c3e4, "input_handler": 0x8040c4ac,
            "enable_api_candidate": 0x800a1468, "direction_api_candidate": 0x800a1580,
            "pin_write_api": 0x800a16f8, "pin_read_api": 0x800a1728,
            "pin_io_contract": "a0=group index, a1=pin index, a2=value for write; table[group*0x54].u32_at_8 gives base; read/write u32 at base+0x0c+4*pin. Getter returns loaded u32. Writer returns one.",
            "monitor_side_effects": "gpioset and gpioget both invoke enable/configure and direction routines before pin I/O. gpioget therefore is not a passive hardware read. Monitor diagnostics explicitly say GPIO state is not restored.",
            "direction_values": "Monitor output path passes direction argument0; input path passes1. Driver updates cached mask at record+4 and writes it to register_base+4. Register bit meanings inferred from these callers.",
            "bounds": "No group/pin validation in these short pin-access leaf APIs; observed table groups0..10 are not authorization to call arbitrary indices.",
            "physical_wiring": None,
            "limitation": "The two byte maps are retained raw. Pad identities, pin mux state, board wiring and attached devices are not established."},
        "allocator": {
            "evidence_type": "Reviewed static initialization and dispatch windows",
            "initialization": 0x80020804, "dram_query_callsite": 0x80020844,
            "allocation_dispatch_entry": 0x80020980,
            "initialization_contract": "Queries DRAM byte size through0x8003c3ac. On success derives a candidate pool extent from reported size, the caller-provided start masked with0x0fffffff, and a four-byte deduction; failure reports Unknown main DRAM size. This ties allocator sizing to runtime geometry rather than ELF extent.",
            "dispatch_contract": "Entry saves a0..a3 plus a fifth argument; when a0 pool pointer is nonzero, reads pool+8 then calls its first u32 function pointer with pool,size and forwarded metadata/flags. Other/default-pool branches need further work.",
            "current_free_bytes": None, "maximum_safe_allocation": None,
            "limitation": "Byte/page/fixed allocator source paths establish multiple allocator families, not usable headroom or complete ownership/free semantics."},
        "rtos_primitives": {
            "evidence_type": "Diagnostic names plus selected implementation disassembly",
            "semaphore_get_candidate": 0x800c3b18,
            "semaphore_get_contract": "Selected routine receives a0=object and a1=wait/control parameter; checks word at object+8, decrements it on the immediate-acquire path, and has a suspension path using thread/queue bookkeeping. Error paths reference _tx_semaphore_get. Full status values and tick units remain unresolved.",
            "diagnostic_api_families": ["mutex create/get/put/delete/info/prioritize", "semaphore create/get/put/delete/info", "queue create/send/front_send/receive/flush/delete/info", "event flags create/get/set/delete/info"],
            "cpu_context_selection": "Selected allocator/RTOS windows use MFC0 register15 select1, mask0x3ff and compare with1 to choose context. This does not recover the processor model or prove active core count.",
            "limitation": "Diagnostic function names are useful entry anchors, not recovered symbols or complete callable ABI definitions."},
        "dma": {
            "evidence_type": "Reviewed static transaction-submission window and diagnostic strings",
            "transaction_submit_candidate": 0x8005d208,
            "contract": "Given a0 context, stores a2,a1,a3,stack_arg5,stack_arg6 at context+0x18,+0x1c,+0x20,+0x24,+0x28; clears byte+0x2c, copies context byte0 to+0x2d, calls0x8005d02c(context+0x10). Nonzero stack_arg7 additionally calls0x8005d140(context). Returns one on the shown paths.",
            "unresolved": ["Meaning and units of each transaction field", "DMA channel ownership", "Synchronization/wait semantics", "Cache maintenance and alignment for each engine"],
            "limitation": "The GSIU diagnostic requiring transfers multiple of4 is subsystem-specific and must not become a universal DMA rule."},
    }


def build_report(workspace, source):
    functions, manifest, raw = recover_ranges(workspace)
    if sha(source.read_bytes()) != SOURCE_SHA:
        raise ValueError("Original vendor firmware identity mismatch")
    mapping = AddressMap(raw, manifest["regions"])
    strings = string_inventory(raw, manifest["regions"])
    by_address = {row["address"]: row for row in strings}
    # Mixed code/data scan is deliberately recorded separately from bounded
    # compiler-range memory-access candidates.
    for region in manifest["regions"]:
        start = region["analysis_elf_offset"]
        _, references = scan_constants(raw[start:start + region["size"]], region["virtual_start"], by_address)
        for reference in references:
            by_address[reference["target"]]["references"].append({**reference,
                "classification": "Straight-line instruction-syntax candidate in mixed code/data; reachability unverified"})
    accesses, banks = [], defaultdict(list)
    for function in functions:
        body = mapping.read(function["start"], function["size"])
        found, _ = scan_constants(body, function["start"])
        for row in found:
            row.update({"function_start": function["start"], "function_end_exclusive": function["end_exclusive"],
                        "fde_address": function["fde_address"], "source_region_start": function["source_region_start"]})
            banks[row["address"] & ~0xfff].append(row)
            accesses.append(row)
    commands = command_inventory(mapping, raw, manifest["regions"])
    contracts = reviewed_contracts(mapping)
    # A queried runtime table must not quietly be treated as file-backed data.
    try:
        mapping.read(contracts["clock_interface"]["frequency_table"], 4)
    except ValueError:
        contracts["clock_interface"]["table_file_backed"] = False
    else:
        raise ValueError("Reviewed clock-table backing assumption changed")
    windows = []
    for label, address, size in WINDOWS:
        windows.append({"label": label, "address": address, "size": size,
                        "sha256": sha(mapping.read(address, size))})
    return {
        "schema_version": 1, "method": "Independent offline Python/Capstone static mapping; not native REA Evidence",
        "target_execution": False, "device_access": False,
        "source": {"firmware_path": str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else str(source),
                   "firmware_sha256": SOURCE_SHA, "analysis_elf_sha256": ELF_SHA,
                   "workspace": str(workspace.relative_to(ROOT)) if workspace.is_relative_to(ROOT) else str(workspace)},
        "summary": {"hardware_strings": len(strings), "string_reference_candidates": sum(len(s["references"]) for s in strings),
                    "hardware_command_record_candidates": len(commands), "compiler_unwind_ranges": len(functions),
                    "compiler_range_bytes_scanned": sum(f["size"] for f in functions),
                    "high_address_access_candidates": len(accesses), "high_address_4k_banks": len(banks)},
        "regions": [{key: r[key] for key in ("name", "virtual_start", "size", "sha256", "analysis_elf_offset")} for r in manifest["regions"]],
        "reviewed_contracts": contracts,
        "hardware_strings": strings, "hardware_commands": commands,
        "high_address_access_candidates": accesses,
        "high_address_banks": [{"bank_start": bank, "access_candidate_count": len(rows),
              "distinct_accessed_addresses": len({row["address"] for row in rows}),
              "function_count": len({row["function_start"] for row in rows}),
              "operations": dict(sorted(Counter(row["operation"] for row in rows).items())),
              "classification": "4 KiB grouping of syntactic high-address accesses; MMIO identity unproven"}
             for bank, rows in sorted(banks.items())],
        "reviewed_windows": windows,
        "limitations": [
            "This is a hardware research inventory, not complete register semantics or original C source.",
            "String references are scanned in mixed code/data and can be false positives.",
            "High-address accesses use only 5,798 compiler-unwind ranges, not all code; unsupported instructions and control-flow boundaries drop constants.",
            "Addresses 0xb0000000..0xbfffffff may represent MMIO, ROM or other mapped memory; bank grouping is not a peripheral label.",
            "No dynamic calls, pointer arithmetic, register-state propagation across branches, aliases or indirect access paths are fully recovered.",
            "Memory capacities, operating frequencies, sensor register semantics, DMA ownership/cache coherency and real-time deadlines require additional evidence.",
            "Command records are offline inventory; no debug transport reachability or safe invocation protocol is established."]}


def write_outputs(report, workspace, output, listings):
    if output.exists() or listings.exists():
        raise FileExistsError("Refusing to overwrite prior evidence or listings")
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    _, manifest, raw = recover_ranges(workspace)
    mapping = AddressMap(raw, manifest["regions"])
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    prepared = []
    for window in report["reviewed_windows"]:
        body = mapping.read(window["address"], window["size"])
        instructions = list(decoder.disasm(body, window["address"]))
        if sum(i.size for i in instructions) != window["size"]:
            raise ValueError("Incomplete reviewed-window decode")
        text = "; Analyst-selected static window; not a claimed complete function or observed execution.\n"
        text += "\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in instructions) + "\n"
        prepared.append((window["label"], text))
    listings.mkdir(parents=True)
    for label, text in prepared:
        (listings / (label + ".asm")).write_text(text, encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT / "derived/unpacked-v1.1-indexed")
    parser.add_argument("--source", type=Path, default=ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/hardware-contracts.json")
    parser.add_argument("--listings", type=Path, default=ROOT / "derived/hardware-contracts")
    args = parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise FileExistsError("Refusing to overwrite prior evidence or listings")
    report = build_report(args.workspace.resolve(), args.source.resolve())
    write_outputs(report, args.workspace.resolve(), args.output, args.listings)
    print(json.dumps(report["summary"]))


if __name__ == "__main__":
    main()
