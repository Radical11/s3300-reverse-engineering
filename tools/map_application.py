"""Map source-bound S3300 application strings and MIPS address references.

Offline static evidence only. Instruction-like pairs in mixed code/data are
candidates, not recovered symbols, proven function boundaries or ready hooks.
"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
RULES = {
    "processing_resources": ["GAMMALUT", "LCLUT", "GAMMADDE1", "LoadGammaResource",
                             "Unsupported Gamma resource", "DLCD gamma", "IPP Gamma update"],
    "capture_pipeline": ["<scale from raw to 422>", "Main Image IPU RAW-YUV",
                         "Main Image Compression", "Main Image Pre-YUV",
                         "Capture time %", "Capture timing Start", "Capture timing Finish",
                         "DirectConvertRawToYuvEx", "StillOnSetCaptureSequence",
                         "AeSetCaptureExpLimit", "OnSetCaptureExpLimit"],
    "profiling": ["CPU load checker", "CPU performance counters",
                  "Print CPU load statistics", "Performance counters are stopped",
                  "Performance counters will be reset"],
    "controls_and_menu": ["ButtonsServer", "ButtonsEvent", "ButtonsTrig",
                          "ViewMenuHandlerISO", "PBMenuHandlerFilterEffect",
                          "PBMenuHandlerSelectColor", "Ui/Setup/ui_SetupLib.c"],
}
REVIEWED_TARGETS = {
    0x8021c7a8: "gamma_resource_loader_candidate",
    0x8021bd3c: "gamma_resource_converter_candidate",
    0x8021cbec: "lclut_resource_loader_candidate",
    0x8022a5a4: "dlcd_gamma_loader_candidate",
    0x801fe350: "ipp_gamma_mode_validation_candidate",
    0x801fe3c8: "ipp_gamma_still_validation_candidate",
}


def words(data):
    n = len(data)//4
    return struct.unpack("<"+"I"*n, data[:n*4])


def address_pairs(base, data, targets):
    """Recognize bounded LUI + ADDIU/ORI pairs, with common clobbers checked.

    Six-instruction span covers observed compiler scheduling. Does not prove
    control-flow reachability or resolve every possible register operation.
    """
    w = words(data)
    result = []
    for i, x in enumerate(w):
        if x >> 26 != 15:
            continue
        reg = (x >> 16) & 31
        if reg == 0:
            continue
        hi = (x & 65535) << 16
        for j in range(i+1, min(i+7, len(w))):
            y = w[j]
            op, rs, rt = y >> 26, (y >> 21) & 31, (y >> 16) & 31
            if op in (9, 13) and rs == reg:
                lo = y & 65535
                lo = lo-65536 if op == 9 and lo & 32768 else lo
                value = (hi+lo if op == 9 else hi | lo) & 0xffffffff
                if value in targets:
                    result.append({"target": value, "lui_address": base+i*4,
                                   "low_address": base+j*4,
                                   "instructions_hex": [f"{x:08x}", f"{y:08x}"],
                                   "span_instructions": j-i,
                                   "confidence": "Static address-materialization candidate; control flow unverified"})
                if rt == reg:
                    break
            elif op in (9, 13, 15, 35, 36, 37, 32, 33) and rt == reg:
                break
            elif op == 0 and ((y >> 11) & 31) == reg and (y & 63) not in (8, 9):
                break
    return result


def candidate_prologue(base, data, address):
    w = words(data)
    end = (address-base)//4
    for i in range(end, max(-1, end-0x400), -1):
        value = w[i]
        if value & 0xffff0000 != 0x27bd0000 or not value & 0x8000:
            continue
        allocation = 0x10000-(value & 0xffff)
        if allocation > 0x2000 or allocation % 8:
            continue
        # SW $ra, offset($sp), within 16 instructions strengthens the cue.
        saved_ra = any(v & 0xffff0000 == 0xafbf0000 for v in w[i+1:i+17])
        if saved_ra:
            return {"virtual_address": base+i*4, "stack_allocation": allocation,
                    "distance_to_reference": address-(base+i*4),
                    "confidence": "Heuristic preceding stack allocation and saved-ra pattern; not a proven function boundary"}
    return None


def main():
    sys.path.insert(0, str(ROOT / "tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    manifest_path = ROOT/"derived/v1.1-decoded/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    mapping = json.loads((ROOT/"derived/v1.1-mapped/map.json").read_text())
    source = Path(mapping["input_path"]).read_bytes()
    if hashlib.sha256(source).hexdigest() != EXPECTED or manifest["source_sha256"] != EXPECTED:
        raise ValueError("Source identity mismatch")
    regions = []
    image = next(i for i in mapping["images"] if i["root_offset"] == 0x1026c0)
    for segment in image["segments"]:
        offset = image["root_offset"]+segment["p_offset"]
        body = source[offset:offset+segment["p_filesz"]]
        regions.append({"virtual_start": segment["p_vaddr"], "data": body,
                        "binding": {"type": "unpacked_file_backed", "carrier_offset": offset,
                                    "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}})
    comparisons = []
    for segment in manifest["segments"]:
        path = Path(segment["file"])
        body = path.read_bytes()
        independent = ROOT/"derived/v1.1-independent"/f"segment-{segment['virtual_start']:08x}.bin"
        digest = hashlib.sha256(body).hexdigest()
        if digest != segment["sha256"] or len(body) != segment["decoded_bytes"]:
            raise ValueError("Decoded segment changed")
        if independent.read_bytes() != body:
            raise ValueError("Independent decoder disagreement")
        comparisons.append({"virtual_start": segment["virtual_start"], "sha256": digest,
                            "size": len(body), "independent_bytes_match": True})
        regions.append({"virtual_start": segment["virtual_start"], "data": body,
                        "binding": {"type": "decoded_segment", "file": str(path.relative_to(ROOT)),
                                    "packed_carrier_offset": segment["carrier_offset"],
                                    "size": len(body), "sha256": digest}})
    selected = []
    for region in regions:
        body, base = region["data"], region["virtual_start"]
        for match in re.finditer(rb"[ -~]{6,}", body):
            text = match.group().decode("ascii")
            categories = [category for category, terms in RULES.items() if any(t in text for t in terms)]
            if not categories:
                continue
            selected.append({"text": text, "virtual_address": base+match.start(),
                             "region_offset": match.start(), "categories": categories,
                             "source_binding": region["binding"], "references": [], "pointer_words": []})
    by_va = {s["virtual_address"]: s for s in selected}
    targets = set(by_va)
    windows = {}
    reviewed_direct_call_candidates = []
    output = ROOT/"derived/application-landmarks"
    output.mkdir(exist_ok=True)
    for region in regions:
        base, body = region["virtual_start"], region["data"]
        for offset, value in enumerate(words(body)):
            if value in targets:
                by_va[value]["pointer_words"].append({"virtual_address": base+offset*4,
                                                     "classification": "Raw aligned pointer-valued word; table/function role unverified"})
            if value >> 26 == 3:
                address = base+offset*4
                target = ((address+4) & 0xf0000000) | ((value & 0x3ffffff) << 2)
                if target in REVIEWED_TARGETS:
                    reviewed_direct_call_candidates.append({
                        "instruction_address": address, "target": target,
                        "analyst_label": REVIEWED_TARGETS[target],
                        "instruction_bytes_hex": body[offset*4:offset*4+4].hex(),
                        "source_binding": region["binding"],
                        "candidate_preceding_prologue": candidate_prologue(base, body, address),
                        "confidence": "Aligned JAL encoding; needs code/data and control-flow validation"})
        for ref in address_pairs(base, body, targets):
            point = ref["lui_address"]
            ref["source_binding"] = region["binding"]
            ref["candidate_preceding_prologue"] = candidate_prologue(base, body, point)
            start = max(base, point-0x100)
            end = min(base+len(body), point+0x180)
            start -= (start-base) % 4
            selected_body = body[start-base:end-base]
            instructions = list(Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN).disasm(selected_body, start))
            # A skip-data or incomplete linear decode is not silently labelled
            # complete, and string/mixed-data regions can legitimately fail.
            complete = sum(i.size for i in instructions) == len(selected_body)
            name = f"reference-{point:08x}.asm"
            rows = ["; Bounded static window; not recovered function boundaries. Branch delay slots matter."]
            calls = []
            for i in instructions:
                rows.append(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}")
                if i.mnemonic in ("j", "jal"):
                    calls.append({"instruction_address": i.address, "kind": i.mnemonic,
                                  "target": int(i.op_str, 0), "status": "Direct static transfer; callee role unverified"})
            (output/name).write_text("\n".join(rows)+"\n")
            windows[name] = {"start": start, "end_exclusive": end,
                             "sha256": hashlib.sha256(selected_body).hexdigest(),
                             "complete_linear_decode": complete}
            ref["window"] = str((output/name).relative_to(ROOT))
            ref["nearby_direct_transfers"] = calls
            by_va[ref["target"]]["references"].append(ref)
    report = {"method": "Source-bound decoded strings, aligned words, bounded MIPS LUI+ADDIU/ORI scans and static windows",
              "source_sha256": EXPECTED, "decoded_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
              "independent_decode_comparisons": comparisons, "landmarks": selected, "windows": windows,
              "reviewed_direct_call_candidates": reviewed_direct_call_candidates,
              "counts": {"strings": len(selected), "materialization_candidates": sum(len(s['references']) for s in selected),
                         "raw_pointer_words": sum(len(s['pointer_words']) for s in selected), "windows": len(windows)},
              "limitations": ["String names are diagnostics, not recovered symbols.",
                              "Mixed code/data regions can contain instruction-like data; address references require control-flow review.",
                              "Prologues are heuristic and may point into a different function; supplied listings are bounded windows only.",
                              "Indirect calls, relocations and interior/ANSI-prefixed string pointers are not exhaustively resolved.",
                              "No patch points, calling conventions, structure layouts or runtime behavior are validated.",
                              "DDE errors explicitly mention DLCD; do not assume these tables modify captured photographs.",
                              "No target execution, camera connection, memory access, patching, repacking or firmware writes."]}
    (ROOT/"evidence/application-landmarks.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
