"""Trace existing Color Options state into effect command construction, offline.

Source-bound static evidence only. No saved-photo effect, persistence contract,
target execution, complete hardware dispatch or patch safety is established.
"""
import argparse
import json
from pathlib import Path
import struct

from build_patch_candidate import ROOT, BASELINE, sha
from map_development_interfaces import AddressMap
from workspace_functions import load_analysis, listing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/color-options-map.json")
    parser.add_argument("--listings", type=Path, default=ROOT/"derived/color-options-map-01")
    args = parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise ValueError("Use fresh evidence and listing paths")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Unsupported baseline")
    workspace = ROOT/"derived/unpacked-v1.1-indexed"
    manifest, raw = load_analysis(workspace)
    mapped = AddressMap(raw, manifest["regions"])
    if mapped.text(0x80383a94) != "nColorEffect:%d;" or "AWB_SetWBMode" not in mapped.text(0x80382f78):
        raise ValueError("Diagnostic binding differs")
    menu_dispatch = struct.unpack("<18I", mapped.read(0x80382920, 72))
    effect_dispatch = struct.unpack("<11I", mapped.read(0x80377b98, 44))
    if menu_dispatch[2:5] != (0x80713498, 0x807134a4, 0x80713464):
        raise ValueError("Color option dispatcher differs")
    if effect_dispatch[2:5] != (0x806ac87c, 0x806ac860, 0x806ac844):
        raise ValueError("Effect dispatcher differs")
    presets = []
    for name, address, pair in (("cyanotype", 0x80882d20, (24, 0)),
                                ("sepia", 0x80882d24, (-30, 30)),
                                ("neutral", 0x80882d28, (0, 0))):
        body = mapped.read(address, 4)
        if struct.unpack("<hh", body) != pair:
            raise ValueError("Original offset pair differs")
        presets.append({"analyst_label": name, "address": address, "bytes": 4,
                        "sha256": sha(body), "signed_halfword_pair": list(pair)})
    args.listings.mkdir(parents=True)
    windows = []
    for address in (0x805ac85c, 0x807132d0, 0x806ac4dc, 0x806ac078, 0x806af434,
                    0x806af380, 0x806d2b60):
        text, row = listing(workspace, address)
        path = args.listings/f"{address:08x}.asm"
        path.write_text(text, encoding="utf-8")
        windows.append({**row, "path": path.relative_to(ROOT).as_posix()})
    report = {"source_sha256": BASELINE, "analysis_sha256": sha(raw),
              "method": "Authenticated data and compiler-unwind-bounded MIPS32 listings; manual delay-slot-aware trace",
              "rea_evidence": False, "target_executed": False,
              "settings_pointer_global": 0x808918ac, "color_option_byte_offset": 0x1a,
              "menu_store_site": 0x805ac8cc, "menu_apply_call": 0x805ac934,
              "selection_dispatch": 0x807132d0,
              "selected_cases": [
                  {"ui_value": 2, "effect_id": 4, "separate_awb_mode": 12},
                  {"ui_value": 3, "effect_id": 3, "separate_awb_mode": 13},
                  {"ui_value": 4, "effect_id": 2, "separate_awb_mode": 17}],
              "effect_dispatcher": 0x806ac4dc, "effect_dispatch_table": list(effect_dispatch),
              "offset_presets": presets, "active_offset_pair": 0x8087b8e4,
              "chroma_multiplier_u16": 0x80835a10,
              "matrix_adjuster": 0x806ac078,
              "command_builder": {"address": 0x806af434, "id": 15, "bytes": 0x34,
                                  "matrix_signed_halfwords": 9, "first_two_offsets_bias": 128,
                                  "enqueue": 0x802233e8},
              "listings": windows,
              "limitations": [
                  "UI names to serialized numeric selections need runtime confirmation; ordinals alone are not proven UI IDs.",
                  "The byte store establishes in-memory state, not nonvolatile persistence or a safe settings writer.",
                  "AWB mode and chroma effect are separate branches; AWB numbers are not creative-look IDs.",
                  "Effect IDs 2/3/4 zero chroma multiplier and select constant tint offsets; this is a tinted-monochrome lead, not full-color Amber Days.",
                  "Command 15 enqueue is traced; hardware dispatch and live-view versus saved-still context still require tracing.",
                  "Other users of shared offset constants and input/output color domain remain unresolved.",
                  "No effect preset, executable instruction or firmware candidate was changed by this mapper."],
              "ready_for_saved_photo_patch": False}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"output": str(args.output), "offset_presets": presets,
                      "ready_for_saved_photo_patch": False}, indent=2))


if __name__ == "__main__":
    main()
