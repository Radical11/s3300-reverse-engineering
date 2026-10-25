"""Reproduce the authenticated command15 -> IPU matrix application trace.

No firmware is executed or patched. Native dossiers are direct Ghidra static
analysis, separately labelled from REA Evidence. Listings remain local.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, checked_table, Cs, CS_ARCH_MIPS,
    CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)

WINDOWS = (
    ("scheduler_apply_gate", 0x802e8df4, 0x70),
    ("scheduler_commands", 0x802e69bc, 0x300),
    ("filter_group_dispatch", 0x802d508c, 0x334),
    ("filter_command_decode_dispatch", 0x802d4304, 0x130),
    ("factory_forward", 0x802f21cc, 0x14),
    ("matrix_constructor", 0x802d2ac8, 0x6c),
    ("matrix_command_decode", 0x802d5d74, 0x178),
    ("matrix_subtype15_decode", 0x802d5ccc, 0x44),
    ("matrix_direct_upload", 0x802d2c88, 0x178),
    ("matrix_write_list", 0x802d2e00, 0x2f4),
)
NATIVE_FUNCTIONS = (0x80008f80,0x80009644,0x801fbc8c,0x801fbb3c,
    0x80192e04,0x802e57a8,0x802e69bc,0x802d2ac8,0x802d5d74,
    0x802d5ccc,0x802d2c88,0x802d2e00,0x806af434)
ASSERTIONS = {
    0x802e8e58: ("jal", "0x802e69bc"),
    0x802d50ac: ("move", "$s4, $a3"),
    0x802d50d4: ("sltiu", "$v0, $s4, 0x1e"),
    0x802d524c: ("lw", "$v1, ($s1)"),
    0x802d5254: ("addiu", "$v0, $zero, 0xf"),
    0x802d5100: ("sw", "$v0, 0x14($sp)"),
    0x802d5104: ("sw", "$s4, 0x10($sp)"),
    0x802d430c: ("lw", "$s1, 0x44($sp)"),
    0x802d4334: ("addu", "$s0, $v1, $a3"),
    0x802d4378: ("lw", "$s0, 0x24($a2)"),
    0x802d437c: ("jalr", "$s0"),
    0x802d43dc: ("lw", "$a1, 0x40($sp)"),
    0x802f21cc: ("lw", "$a0, 4($a0)"),
}


def subtype15_register_values(command):
    """Pure host interpretation of internal command15 subtype15 payload.

    This does not validate camera buffer ownership or provide an MMIO writer.
    Internal size is 0x30, unlike the external 0x34-byte command structure.
    """
    if len(command) != 0x30:
        raise ValueError("Expected a 0x30-byte retained command")
    size, command_id, subtype = struct.unpack_from("<III", command)
    if (size, command_id, subtype) != (0x30, 15, 15):
        raise ValueError("Only retained command15 subtype15 is verified")
    coefficients = struct.unpack_from("<9h", command, 0x14)
    offsets = struct.unpack_from("<2h", command, 0x26)
    values = list(coefficients) + list(offsets)
    result = [{"address": 0xb60000c0 + 4*i,
               "value_u32": value & 0xffffffff} for i,value in enumerate(values)]
    result.append({"address": 0xb60000fc,
                   "value_u32": struct.unpack_from("<I", command, 0x2c)[0]})
    return result


def crosscheck_native(mapping, analysis_hash, directory):
    image_path = directory / "image.json"
    image = json.loads(image_path.read_text(encoding="utf-8"))
    if image.get("executable_sha256") != analysis_hash:
        raise ValueError("Native dossiers belong to a different analysis image")
    if image.get("language") != "MIPS:LE:32:default":
        raise ValueError("Native dossier architecture mismatch")
    records = []
    for address in NATIVE_FUNCTIONS:
        path = directory/"functions"/f"{address:08x}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if int(data["address"],16) != address or not data["decompilation_completed"]:
            raise ValueError(f"Native decompilation incomplete at {address:#x}")
        instructions = data["instructions"]
        if not instructions or not data.get("pseudocode", "").strip():
            raise ValueError("Empty native dossier")
        for row in instructions:
            body = bytes.fromhex(row["bytes"])
            if mapping.read(int(row["address"],16),len(body)) != body:
                raise ValueError("Native imported bytes disagree with authenticated ELF")
        records.append({"address": address,"dossier": str(path.relative_to(ROOT)),
            "dossier_sha256": digest(path.read_bytes()),
            "instruction_count_bytes_verified":len(instructions),
            "pseudocode_sha256":digest(data["pseudocode"].encode()),
            "signature_status":"decompiler inference; not a verified public ABI"})
    return {"evidence_class":"direct Ghidra static analysis; not REA Evidence",
            "image_metadata_sha256":digest(image_path.read_bytes()),"records":records}


def build_report(workspace, source, native):
    if digest(source.read_bytes()) != BASELINE:
        raise ValueError("Unsupported vendor source identity")
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw,manifest["regions"])
    decoder = Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    windows, instructions = [],{}
    for label,address,size in WINDOWS:
        body = mapping.read(address,size)
        decoded = list(decoder.disasm(body,address))
        if sum(i.size for i in decoded) != size:
            raise ValueError(f"Incomplete decode at {address:#x}")
        instructions.update({i.address:(i.mnemonic,i.op_str) for i in decoded})
        windows.append({"label":label,"address":address,"bytes":size,
            "sha256":digest(body),"boundary":"bounded analyst window; no complete-function assertion"})
    for address,expected in ASSERTIONS.items():
        if instructions.get(address) != expected:
            raise ValueError(f"Reviewed instruction changed at {address:#x}")
    tables = {
        "matrix_vtable":checked_table(mapping,0x802fdcb8,[0x802d2b34,0x802d2b5c,
            0x802d2c88,0x802d558c,0x802d2e00,0x802ff208,0x802ff200,
            0x802ff1f0,0x802ff1f8,0x802d5d74,0x802ff1e8,0x802ff1e0]),
        "group11_dispatch":checked_table(mapping,0x802fb3e0+11*4,[0x802d524c]),
        "factory11_dispatch":checked_table(mapping,0x802fd908+11*4,[0x802f5e84]),
    }
    return {"schema_version":1,"source_sha256":BASELINE,"analysis_sha256":digest(raw),
        "method":"Independent authenticated Capstone checks plus separately labelled direct Ghidra corroboration",
        "rea_evidence":False,"camera_commands_issued":False,"target_executed":False,
        "reviewed_windows":windows,"instruction_assertions":len(ASSERTIONS),"checked_tables":tables,
        "native_corroboration":crosscheck_native(mapping,digest(raw),native),
        "contracts":[
          {"id":"image.matrix_scheduler","status":"static-route-verified",
           "entry":0x802e69bc,"gate":0x802e8e58,"gate_bit":"driver+0x324 bit1",
           "group_count":30,"group":11,"dispatcher":0x802d508c,
           "command_slot":15,"factory_id":11,"slot_rule":"driver+0x48+12*command_id",
           "decode_dispatch":0x802d4304,"factory_ctor":0x802d2ac8,
           "argument_warning":"dispatcher stack arg5 is factory/group ID; arg6 is command slot ID; these differ",
           "lifecycle":"first/shared pass then per-output pass according to bitmap; group object retained through 802dde1c; slot+9 bit0 cleared after scheduling",
           "unknowns":["active numeric context ordinary saved-still identity","asynchronous ownership/cache/DMA completion"]},
          {"id":"image.matrix_decode","status":"static-contract-verified","address":0x802d5d74,
           "arguments":{"a0":"filter object","a1":"retained command pointer"},
           "accepted_id":15,"accepted_subtypes":[0,6,12,13,15],
           "return":{"success":0,"unsupported_subtype":6,"unsupported_command":7},
           "side_effects":"decode fields, mark object+0x30 dirty, update generation via802df29c",
           "subtype15_decoder":0x802d5ccc,"subtype15_layout":{"coefficients":"9 halfwords command+0x14 -> object+0x34","offsets":"halfwords command+0x26/+0x28 -> object+0x46/+0x48","auxiliary_word":"command+0x2c -> object+0x4c","ignored_alignment":"command+0x2a/+0x2b not read by this decoder"},
           "subtype6_difference":"coefficients <<2; offsets*8+0x800; auxiliary word0; do not apply this scaling to subtype15"},
          {"id":"image.matrix_register_application","status":"static-contract-verified",
           "direct_entry":0x802d2c88,"queued_list_entry":0x802d2e00,
           "vtable":0x802fdcb8,"dirty_field":0x30,
           "registers":[hex(0xb60000c0+4*i) for i in range(11)]+["0xb60000fc"],
           "encoding":"eleven signed halfwords sign-extended to32-bit; auxiliary word unchanged",
           "bypass_register":0xb60000ec,"bypass_entry":0x802df300,
           "bypass_rule":"object+0x28 zero selects value+0x10=1; nonzero selects+0x14=0",
           "ownership":"object-owned decoded fields; direct entry writes MMIO, queued entry appends address/value records to caller-owned list",
           "limits":"static upload behavior verified; trigger timing, register hardware units, DMA synchronization, list submission completion not a public adapter"},
          {"id":"recovery.reachability","status":"blocked",
           "ordinary_rollback":"requires running application and menu update path",
           "unbootable_recovery":"boot downloader and monitor implementations do not establish an externally accessible recovery route",
           "backup":"Nanddn fixed65536-sector loop is incomplete on read errors; physical geometry/calibration/ECC/writeback remain unresolved",
           "code_trial_allowed":False,
           "unknowns":["actual updater physical erase/write ranges","installed boot entry and activation controls","complete calibration and settings backup scope","verified restoration without executing damaged application"]}],
        "development_gates":{"static_matrix_application_route_verified":True,
            "saved_photo_buffer_abi_verified":False,"software_unbootable_recovery_verified":False,
            "code_trial_allowed":False},
        "evidence_limits":["Native inferred parameter lists are not authoritative ABIs; independent stack/instruction tracing establishes the group/slot distinction.",
            "No runtime sample or installed-image identity is asserted by this static artifact.",
            "Factory15/b6000484 handles command32 and is a different filter; do not conflate it with command15.",
            "The three indirect-dispatch entry windows were not recognized functions in the initial Ghidra inventory; their bounds remain analyst-selected."]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace",type=Path,default=WORKSPACE)
    parser.add_argument("--source",type=Path,default=ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin")
    parser.add_argument("--native",type=Path,default=ROOT/"derived/native-analysis-complete/application")
    parser.add_argument("--output",type=Path,default=ROOT/"evidence/matrix-application.json")
    parser.add_argument("--listings",type=Path,default=ROOT/"derived/matrix-application")
    args=parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise FileExistsError("Choose new output and listing paths")
    report=build_report(args.workspace,args.source,args.native)
    manifest,raw=load_analysis(args.workspace)
    mapping=AddressMap(raw,manifest["regions"])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    args.listings.mkdir(parents=True)
    for row in report["reviewed_windows"]:
        text="; Authenticated bounded static analyst window; not target execution.\n"
        text+="\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in decoder.disasm(mapping.read(row["address"],row["bytes"]),row["address"]))+"\n"
        (args.listings/(row["label"]+".asm")).write_text(text,encoding="utf-8")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as handle:
        json.dump(report,handle,indent=2);handle.write("\n")
    print(json.dumps({"contracts":len(report["contracts"]),"native_dossiers":len(report["native_corroboration"]["records"]),"code_trial_allowed":False}))


if __name__ == "__main__":
    main()
