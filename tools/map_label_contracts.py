"""Authenticate the Color Options label path and optionally emulate two helpers.

Direct Ghidra/Capstone evidence, separate from REA Evidence. Host emulation
uses only bounded source-authenticated function bytes and synthetic RAM. It
does not connect to the camera, render its display, or construct a candidate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from build_patch_candidate import BASELINE, ROOT
from map_development_interfaces import AddressMap
from resource_formats import decode_zst
from workspace_functions import load_analysis

TABLE = 0x8036add4
TABLE_BYTES = 46392
LABEL = 0x8036e47a
NATIVE = ROOT / "derived/native-analysis-complete/application/functions"
FUNCTIONS = (0x8000c300, 0x801f2b14, 0x802c0c40, 0x802c0d28,
             0x802c73fc, 0x805b7f04, 0x805c099c, 0x80595f60,
             0x806fb780, 0x802436b8, 0x801f211c, 0x806e47f4)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def records(body, base=TABLE):
    """Independently map the native loader's header and default record too."""
    if len(body) < 24 or body[:4] != b"ZST\0":
        raise ValueError("Invalid ZST header")
    count, first_id = struct.unpack_from("<II", body, 4)
    maximum, bits = struct.unpack_from("<HH", body, 12)
    if not 1 <= count <= 100000 or bits not in (8, 16):
        raise ValueError("Unsupported native ZST geometry")
    width, cursor, result = bits // 8, 20, []
    for index in range(count):
        if cursor + 2 > len(body):
            raise ValueError("Truncated native ZST record length")
        length = struct.unpack_from("<H", body, cursor)[0]
        start = cursor + 2
        end = start + length
        if length > maximum or length % width or end + width > len(body):
            raise ValueError("Native ZST record outside bounds")
        if body[end:end + width] != bytes(width):
            raise ValueError("Native ZST terminator differs")
        text = body[start:end].decode("utf-16-be" if width == 2 else "latin1")
        result.append({"id": first_id + index, "ordinal": index,
                       "record_offset": cursor, "data_address": base + start,
                       "byte_length": length, "text_projection": text})
        cursor = end + width
    if cursor != len(body):
        raise ValueError("Unparsed native ZST tail")
    return {"count": count, "first_id": first_id, "bits": bits,
            "maximum_record_bytes": maximum, "records": result}


def authenticate_dossier(path, mapping):
    row = json.loads(path.read_text())
    checked = 0
    for instruction in row["instructions"]:
        address = int(instruction["address"], 16)
        body = bytes.fromhex(instruction["bytes"])
        if not body or mapping.read(address, len(body)) != body:
            raise ValueError("Native label dossier bytes differ from source")
        checked += len(body)
    if not checked:
        raise ValueError("Empty native label dossier")
    return row, {"address": int(row["address"], 16),
                 "dossier": path.relative_to(ROOT).as_posix(),
                 "dossier_sha256": sha(path.read_bytes()),
                 "instruction_bytes_authenticated": checked,
                 "pseudocode_is_inferred": True}


def inspect_reviewed_candidate(path, mapping):
    """Independently decode the English-containing segment of the fixed trial."""
    from build_amber_trial import EXPECTED
    from build_resource_candidate import validate_chain
    from validate_decoded_firmware import transcode
    from decode_firmware import decode_block
    source = (ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    candidate = path.read_bytes()
    if sha(source) != BASELINE or sha(candidate) != EXPECTED or len(source) != len(candidate):
        raise ValueError("Reviewed original/candidate identity differs")
    fs = json.loads((ROOT / "evidence/resource-filesystem.json").read_text())
    entry = next(e for e in fs["entries"] if e["path"] == "String/Res_Str_Eng_New.bst")
    validate_chain(source, fs, entry)
    fat = b"".join(candidate[c["carrier_offset"]:c["carrier_offset"] + c["file_bytes"]]
                   for c in entry["chunks"])
    framing = json.loads((ROOT / "evidence/packed-segments.json").read_text())
    if framing["input_sha256"] != BASELINE:
        raise ValueError("Packed framing source differs")
    segment = next(s for s in framing["segments"] if s["elf_p_vaddr"] <= TABLE and
                   TABLE + TABLE_BYTES <= s["elf_p_vaddr"] + s["elf_p_memsz"])
    production, independent = bytearray(), bytearray()
    for block in segment["blocks"]:
        start = block["header"]["carrier_offset"]
        kind, length, payload_size, a_size, b_size = struct.unpack_from("<IIIHH", source, start)
        a_start, b_start = start + 16, start + 16 + a_size
        payload_start = b_start + b_size
        if kind != 2 or candidate[start:payload_start] != source[start:payload_start]:
            raise ValueError("Candidate changed packed framing")
        a = struct.unpack_from(f"<{a_size // 4}I", source, a_start)
        b = struct.unpack_from(f"<{b_size // 4}I", source, b_start)
        payload = candidate[payload_start:payload_start + payload_size]
        production.extend(decode_block(a, b, payload, length, bytes(production[-32768:]))[0])
        independent.extend(transcode(payload, a, b, length, bytes(independent[-32768:]))[0])
    base, size = segment["elf_p_vaddr"], segment["elf_p_memsz"]
    desired = bytearray(mapping.read(base, size))
    for address, before, after in ((0x8036e14c, "Welcome screen", "Welcome studio"),
                                   (LABEL, "Sepia", "Amber")):
        offset = address - base
        old, new = before.encode("utf-16-be"), after.encode("utf-16-be")
        if desired[offset:offset + len(old)] != old or len(old) != len(new):
            raise ValueError("Expected original label differs")
        desired[offset:offset + len(old)] = new
    if production != independent or independent != desired:
        raise ValueError("Full English-containing segment differs beyond declared labels")
    embedded = bytes(independent[TABLE - base:TABLE - base + TABLE_BYTES])
    if fat != embedded or records(embedded)["records"][563]["text_projection"] != "Amber":
        raise ValueError("Reviewed candidate's English copies/label differ")
    return embedded, {"candidate_sha256": EXPECTED,
        "exact_installed_image_identity_established": False,
        "independently_decoded_blocks": len(segment["blocks"]), "decoded_bytes": len(independent),
        "two_decoders_agree": True, "only_declared_labels_changed_in_checked_segment": True,
        "fat_and_embedded_english_copies_equal": True, "english_table_sha256": sha(embedded),
        "label_563": "Amber"}


def emulate_loader(mapping, body, flag=0x729e, ids=(560, 561, 562, 563, 564)):
    """Execute retained loader and lookup instructions in bounded synthetic RAM.

    Allocation/memset/strcmp and drawing endpoints are host stubs. Every other
    called instruction is rejected. This verifies parsing/ID selection, not
    device execution, filesystem fallback, font rasterization or cache/DMA.
    """
    from verify_sdk_emulation import emulator_imports
    uc_api = emulator_imports()
    from unicorn import mips_const as r
    if len(body) != TABLE_BYTES or not 1 <= flag <= 0xffffffff:
        raise ValueError("Bounded embedded table and nonzero selector required")
    parsed = records(body)
    machine = uc_api.Uc(uc_api.UC_ARCH_MIPS,
                        uc_api.UC_MODE_MIPS32 | uc_api.UC_MODE_LITTLE_ENDIAN)
    # MIPS KSEG0 accesses alias the low physical backing in Unicorn. Map only
    # the selected code/data pages; no MMIO, OS calls or peripheral model.
    mapped = set()
    writable = [(0x81000000, 0x81010000), (0x82000000, 0x82010000)]

    def reserve(address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            physical = page & 0x1fffffff
            if physical not in mapped:
                machine.mem_map(physical, 4096)
                mapped.add(physical)

    def write(address, data):
        machine.mem_write(address & 0x1fffffff, data)

    def read(address, size):
        return bytes(machine.mem_read(address & 0x1fffffff, size))

    def word(address):
        return struct.unpack("<I", read(address, 4))[0]

    def cstring(address):
        result = bytearray()
        for offset in range(256):
            value = read(address + offset, 1)[0]
            if value == 0:
                return bytes(result)
            result.append(value)
        raise ValueError("Unterminated bounded stub string")

    ranges = ((0x802c0d28, 0x4ac), (0x802c73fc, 0xe4))
    for start, size in ranges:
        reserve(start, size)
        write(start, mapping.read(start, size))
    reserve(TABLE, len(body)); write(TABLE, body)
    reserve(0x802d2694, 0x20)
    write(0x802d2694, mapping.read(0x802d2694, 0x20))
    stubs = (0x800efc30, 0x800f023c, 0x80020980,
             0x802c60e0, 0x802c60c8, 0x802c6fac)
    for address in (0x802d1134, 0x808ce9d4, 0x83000000, *stubs):
        reserve(address, 4)
    for start, end in writable:
        reserve(start, end - start)
    write(0x802d1134, struct.pack("<I", flag))
    write(0x808ce9d4, struct.pack("<I", TABLE))
    heap, allocations, selections = 0x81000000, [], []
    instructions = 0
    pending_return = None

    def on_write(engine, access, address, size, value, user):
        virtual = (address & 0x1fffffff) | 0x80000000
        if not any(start <= virtual and virtual + size <= end for start, end in writable):
            raise ValueError("Native ZST wrote outside synthetic stack/heap")

    def on_code(engine, address, size, user):
        nonlocal heap, instructions, pending_return
        instructions += 1
        arguments = [engine.reg_read(getattr(r, f"UC_MIPS_REG_A{i}")) for i in range(4)]
        if address == 0x800efc30:
            start, value, length = arguments[:3]
            if length > 0x10000 or not any(a <= start and start + length <= b for a, b in writable):
                raise ValueError("Unbounded memset stub")
            write(start, bytes([value & 255]) * length); result = start
        elif address == 0x800f023c:
            result = int(cstring(arguments[0]) != cstring(arguments[1]))
        elif address == 0x80020980:
            length = arguments[1]
            if not 0 < length <= 0x10000 or heap + length > 0x81010000:
                raise ValueError("Native ZST allocation exceeds budget")
            result = heap; heap += (length + 15) & ~15
            allocations.append({"address": result, "bytes": length})
            write(result, bytes(length))
        elif address in (0x802c60e0, 0x802c60c8):
            result = 0
        elif address == 0x802c6fac:
            selections.append(arguments[1]); result = 0x3300
        elif any(start <= address < start + extent for start, extent in ranges):
            return
        else:
            raise ValueError(f"Unexpected native ZST execution at {address:#x}")
        engine.reg_write(r.UC_MIPS_REG_V0, result)
        pending_return = engine.reg_read(r.UC_MIPS_REG_RA)
        engine.emu_stop()

    machine.hook_add(uc_api.UC_HOOK_MEM_WRITE, on_write)
    machine.hook_add(uc_api.UC_HOOK_CODE, on_code)

    def call(address, args):
        nonlocal pending_return
        initial_sp = 0x8200ff00
        machine.reg_write(r.UC_MIPS_REG_SP, initial_sp)
        machine.reg_write(r.UC_MIPS_REG_RA, 0x83000000)
        for i in range(4):
            machine.reg_write(getattr(r, f"UC_MIPS_REG_A{i}"), args[i] if i < len(args) else 0)
        for i, argument in enumerate(args[4:]):
            write(initial_sp + 16 + i * 4, struct.pack("<I", argument))
        next_address = address
        for _ in range(100):
            pending_return = None
            try:
                machine.emu_start(next_address, 0x83000000, timeout=5_000_000, count=500000)
            except uc_api.UcError as error:
                raise ValueError(f"Native ZST emulator failed at PC={machine.reg_read(r.UC_MIPS_REG_PC):#x}") from error
            if pending_return is None:
                break
            next_address = pending_return
        else:
            raise ValueError("Native ZST stub-call budget exceeded")
        if (machine.reg_read(r.UC_MIPS_REG_PC) != 0x83000000 or
                machine.reg_read(r.UC_MIPS_REG_SP) != initial_sp):
            raise ValueError("Native ZST did not return within bounded execution")
        return machine.reg_read(r.UC_MIPS_REG_V0)

    handle = call(0x802c0d28, [0, 0, 0])
    if word(handle) != parsed["count"] or word(handle + 4) != parsed["first_id"]:
        raise ValueError("Native ZST header disagrees with independent parser")
    pointers = word(handle + 16)
    for index, record in enumerate(parsed["records"]):
        if word(pointers + index * 4) != record["data_address"]:
            raise ValueError("Native ZST record pointer differs from independent parser")
    selected = []
    by_id = {record["id"]: record for record in parsed["records"]}
    for string_id in ids:
        before = len(selections)
        result = call(0x802c73fc, [handle, 0x82000000, 0, 0x82000040, 0, string_id])
        if string_id not in by_id:
            if result != 0 or len(selections) != before:
                raise ValueError("Native string lookup did not reject invalid ID")
            selected.append({"id": string_id, "rejected": True})
        else:
            record = by_id[string_id]
            if result != 0x3300 or selections[before:] != [record["data_address"]]:
                raise ValueError(f"Native string lookup differs: id={string_id} result={result:#x} selected={selections[before:]} expected={record['data_address']:#x}")
            selected.append({"id": string_id, "data_address": record["data_address"],
                             "text_projection": record["text_projection"]})
    return {"engine": "Unicorn", "version": uc_api.__version__, "embedded_selector": flag,
            "all_record_pointers_checked": parsed["count"], "allocations": allocations,
            "instructions_executed": instructions, "selected": selected,
            "writes_bounded_to_synthetic_stack_and_heap": True,
            "camera_executed": False, "font_rasterizer_executed": False,
            "scope": "Two original MIPS helpers; declared host stubs, synthetic memory only"}


def build(*, emulate=False, candidate=None):
    workspace = ROOT / "derived/unpacked-v1.1-indexed"
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw, manifest["regions"])
    source = ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    if sha(source.read_bytes()) != BASELINE:
        raise ValueError("Original firmware identity differs")
    dossiers, proofs = {}, []
    for address in FUNCTIONS:
        row, proof = authenticate_dossier(NATIVE / f"{address:08x}.json", mapping)
        dossiers[address] = row; proofs.append(proof)
    body = mapping.read(TABLE, TABLE_BYTES)
    parsed = records(body)
    document = decode_zst(body)
    if len(document["entries"]) != parsed["count"] - 1:
        raise ValueError("Independent resource codec count differs")
    for entry, record in zip(document["entries"], parsed["records"][1:]):
        if (entry["ordinal"], entry["text_projection"], entry["resource_offset"] + 2) != (
                record["ordinal"], record["text_projection"], record["data_address"] - TABLE):
            raise ValueError("Independent resource codec record differs")
    ids = struct.unpack("<5H", mapping.read(0x8065a6b6, 10))
    if ids != (560, 561, 562, 563, 564) or parsed["records"][563]["data_address"] != LABEL:
        raise ValueError("Color Options label IDs/location differ")
    by_site = {int(i["address"], 16): i["text"] for row in dossiers.values() for i in row["instructions"]}
    assertions = {
        0x8000c368: "li s0,0x729e",
        0x801f2bb4: "jal 0x8000c300", 0x801f2bc4: "jal 0x802c0c40",
        0x801f2be0: "jal 0x802c0d28", 0x805b82cc: "addiu v0,v0,-0x59b6",
        0x805b82dc: "_sw v0,0x10(t0)", 0x805c09d4: "jal 0x805b7f04",
        0x80596138: "jal 0x806fb780", 0x802c74c0: "jal 0x802c6fac",
    }
    for site, expected in assertions.items():
        if by_site.get(site) != expected:
            raise ValueError(f"Reviewed label instruction differs at {site:#x}: {by_site.get(site)}")
    report = {"schema_version": 1, "source_sha256": BASELINE, "analysis_sha256": sha(raw),
              "evidence_class": "Direct source-authenticated Ghidra/Capstone; not REA Evidence",
              "method": "Retained dossiers, exact original bytes, independent ZST parsing and optional bounded host emulation",
              "native_proofs": proofs, "reviewed_instructions_checked": len(assertions),
              "english_table": {"address": TABLE, "bytes": TABLE_BYTES, "sha256": sha(body),
                                "count_including_default": parsed["count"], "first_id": parsed["first_id"],
                                "bits_per_code_unit": parsed["bits"],
                                "maximum_record_bytes": parsed["maximum_record_bytes"]},
              "color_options": {"descriptor_builder": 0x805b7f04, "category": 0, "submenu": 4,
                                "draw_callback": 0x805c099c, "text_id_array": 0x8065a6b6,
                                "labels": [parsed["records"][n] for n in ids],
                                "lookup_helper": 0x802c73fc,
                                "id_mapping": "pointer_table[(requested_id - header.first_id)] within header.count",
                                "draw_chain": [0x805c099c, 0x805bfc54, 0x80595f60, 0x806fb780,
                                               0x802436b8, 0x801f211c, 0x802c73fc, 0x802c6fac]},
              "loader": {"entry": 0x801f2b14, "embedded_dispatch": 0x8000c300,
                         "category": 12, "state_setter": 0x802c0c40, "parser": 0x802c0d28,
                         "returned_0x729e_used_as_nonzero_embedded_selector": True,
                         "returned_0x729e_is_not_parser_byte_limit": True,
                         "record_pointer_lifetime": "Embedded records are borrowed source pointers; allocated pointer index/header separately owned",
                         "filesystem_fallback": "Used when embedded lookup returns zero; not executed in host emulation"},
              "development_gates": {"static_english_color_label_path_verified": True,
                                    "runtime_amber_label_fixed": False, "executable_trials_allowed": False},
              "remaining_unknowns": ["Exact installed image bytes are unverified.",
                  "Full live UI route and font rasterization were not observed by this tool.",
                  "Static lookup correctness does not explain the user's retained Sepia label.",
                  "No candidate, device command or firmware update is produced."]}
    candidate_body = None
    if candidate:
        candidate_body, report["reviewed_candidate"] = inspect_reviewed_candidate(Path(candidate), mapping)
    if emulate:
        changed = bytearray(body)
        offset = LABEL - TABLE
        if changed[offset:offset + 10] != "Sepia".encode("utf-16-be"):
            raise ValueError("Original label span differs")
        changed[offset:offset + 10] = "Amber".encode("utf-16-be")
        report["host_emulation"] = {
            "original": emulate_loader(mapping, body, ids=(*ids, parsed["count"], 0xffffffff)),
            "simulated_amber_span": emulate_loader(mapping, bytes(changed), ids=(*ids, parsed["count"])),
            "nonzero_selector_one": emulate_loader(mapping, body, flag=1, ids=(563,)),
            "simulated_change_is_not_a_candidate_or_installed_image": True}
        if candidate_body:
            report["host_emulation"]["reviewed_candidate"] = emulate_loader(mapping, candidate_body, ids=ids)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--emulate", action="store_true")
    parser.add_argument("--candidate", type=Path, help="Optional exact reviewed Amber image, read-only")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a new metadata evidence path")
    report = build(emulate=args.emulate, candidate=args.candidate)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2); handle.write("\n")
    print(json.dumps({"output": str(args.output), "labels": report["color_options"]["labels"],
                      "gates": report["development_gates"], "host_emulation": args.emulate}, indent=2))


if __name__ == "__main__":
    main()
