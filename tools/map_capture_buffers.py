"""Recover shared image-frame and temporary-buffer contracts from v1.1 bytes.

Uses retained direct Ghidra dossiers only after comparing every selected
instruction with the authenticated analysis ELF. Pseudocode remains inferred;
the descriptor models below transcribe reviewed byte-bound guards, not a safe
camera API. No device requests, patches or firmware execution are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from map_development_interfaces import AddressMap
from workspace_functions import load_analysis

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
U32_MASK = 0xffffffff
FRAME_FIELDS = ("data_address", "frame_width", "frame_height", "left", "top", "width", "height")
NATIVE_ENTRIES = (0x801a4490, 0x8018e9f4, 0x8018ff74, 0x8018f200,
                  0x8018f184, 0x8018f6e4, 0x80197ac8, 0x801978f0, 0x80191fd4)
STRINGS = {
    0x801abef8: "(psImageFrame->uiHeight != 0) && (psImageFrame->uiWidth != 0)",
    0x801abff8: "(psImageChromaFrame->uiHeight != 0) && (psImageChromaFrame->uiWidth != 0)",
    0x801ac094: "Image position is outside frame.",
    0x801a0188: "(puiFrameWidth != NULL) && (puiFrameHeight != NULL)",
    0x802540f0: "DirectConvertRawToYuvEx:",
}
FACTS = {
    0x801a4524: "08000d8e",  # Descriptor pointer at JPEG options+8
    0x801a4528: "0c00098e",  # Frame width at descriptor+4
    0x801a4530: "1400088e",  # Left at descriptor+0xc
    0x801a4538: "1c00068e",  # Width at descriptor+0x14
    0x801a453c: "2000038e",  # Height at descriptor+0x18
    0x801a4558: "03006010",  # Zero height rejection
    0x801a4560: "7400c054",  # Width required nonzero
    0x801a4564: "2158c800",  # Width+left with unsigned 32-bit wrap
    0x801a4734: "2b302b01",  # Frame width < computed right edge
    0x801a4738: "8f00c014",  # Reject branch
    0x801a48ec: "01001231",  # Chroma left odd bit
    0x801a4930: "01002331",  # Chroma top odd bit
    0x8018ea24: "1e006011",  # Zero height in generic geometry setter
    0x8018ea2c: "1d00a050",  # Zero width full-frame fallback
    0x8018ea34: "1400e5ac",  # Store selected width
    0x8018ea38: "1800ebac",  # Store selected height
    0x8018ff80: "080085ac",  # Store caller input buffer pointer
    0x8018ff98: "280086ac",  # Store caller output buffer pointer
    0x8018f4a8: "02f82473",  # Width*height, low32
    0x8018f4b0: "02c0f773",  # Product*format-dependent multiplier, low32
    0x8018f4dc: "6082000c",  # Allocator call
    0x8018f4e4: "000042ae",  # Result into descriptor.data
    0x8018f1a0: "0d00a410",  # Cleanup only when path differs
    0x8018f1b4: "d138060c",  # Temporary path deletion
    0x8018f1d0: "a583000c",  # Free temporary buffer
    0x8018f830: "3c5e060c",  # Start/run path
    0x8018f838: "b25e060c",  # Completion wait helper
    0x8018f864: "613c060c",  # Cleanup after completion helper returns
    0x80197b68: "0504030c",  # Conditional event wait
    0x80197b80: "09f84002",  # Driver completion callback, target indirect
    0x80192010: "0f006325",  # Width+15 for alignment
    0x80192020: "00c91f00",  # Width rounded to multiple16
    0x80205918: "21608000",  # Source descriptor pointer held in t4
    0x80205c40: "9342060c",  # Descriptor input routed through setter selector7
    0x80205c60: "9342060c",  # Descriptor output routed through setter selector9
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require_u32(value):
    if type(value) is not int or not 0 <= value <= U32_MASK:
        raise ValueError("Field must be a u32 integer")
    return value


def decode_frame(raw):
    """Parse exactly seven little-endian u32 values; never dereference data."""
    if len(raw) != 28:
        raise ValueError("Image descriptor must contain exactly28 bytes")
    return dict(zip(FRAME_FIELDS, struct.unpack("<7I", raw)))


def jpeg_reviewed_guard(frame, *, chroma420=False):
    """Model only the checks reviewed in JPEG setup0x801a4490.

    No allocation size, data-pointer validity or vertical-containment guarantee
    is supplied. The actual addition wraps; expose overflow instead of hiding it.
    """
    values = {key: require_u32(frame[key]) for key in FRAME_FIELDS}
    right = values["left"] + values["width"]
    nonzero = values["width"] != 0 and values["height"] != 0
    horizontal = values["frame_width"] >= (right & U32_MASK)
    chroma_even = not chroma420 or (values["left"] & 1 == 0 and values["top"] & 1 == 0)
    return {"reviewed_guards_pass": nonzero and horizontal and chroma_even,
            "nonzero_roi": nonzero, "horizontal_target_compare_pass": horizontal,
            "horizontal_addition_overflow": right > U32_MASK,
            "chroma420_origin_even": chroma_even,
            "vertical_containment_established": False,
            "buffer_address_or_capacity_validated": False}


def effective_geometry(frame):
    """Generic path setter: either zero ROI dimension falls back to full frame."""
    values = {key: require_u32(frame[key]) for key in FRAME_FIELDS}
    if values["width"] == 0 or values["height"] == 0:
        values["width"], values["height"] = values["frame_width"], values["frame_height"]
    return values


def temporary_allocation_extent(width, height, multiplier):
    """Low32 arithmetic used at0x8018f4a8/0x8018f4b0, not a safe allocation API."""
    width, height = require_u32(width), require_u32(height)
    if type(multiplier) is not int or multiplier not in (2, 3):
        raise ValueError("Only reviewed numeric multipliers2 and3 are modeled")
    product = width * height * multiplier
    return {"target_requested_bytes": product & U32_MASK,
            "mathematical_product": product, "arithmetic_overflow": product > U32_MASK,
            "allocation_success_established": False}


def validate_facts(mapped, facts=FACTS):
    for address, expected in facts.items():
        if mapped.read(address, 4).hex() != expected:
            raise ValueError(f"Reviewed instruction differs at{address:#x}")


def verify_dossier(row, mapped):
    """Authenticate retained native instructions independently of pseudocode."""
    if not row.get("instructions"):
        raise ValueError("Native dossier has no instructions")
    checked = 0
    for instruction in row["instructions"]:
        body = bytes.fromhex(instruction["bytes"])
        if not body or mapped.read(int(instruction["address"], 16), len(body)) != body:
            raise ValueError("Retained native instruction differs from original analysis bytes")
        checked += 1
    return checked


def reference_scan(manifest, raw, target):
    """Bounded negative search of aligned direct-encoding and pointer words."""
    calls, pointers = [], []
    for region in manifest["regions"]:
        body = raw[region["analysis_elf_offset"]:region["analysis_elf_offset"] + region["size"]]
        for index, (word,) in enumerate(struct.iter_unpack("<I", body[:len(body)//4*4])):
            site = region["virtual_start"] + index * 4
            if word == target:
                pointers.append(site)
            if word >> 26 in (2, 3) and (((site + 4) & 0xf0000000) | ((word & 0x03ffffff) << 2)) == target:
                calls.append(site)
    return {"target": target, "direct_j_jal_encoding_candidates": calls,
            "aligned_pointer_words": pointers, "region_count": len(manifest["regions"]),
            "scope": "Aligned words in the eight authenticated mapped application regions only; computed/unaligned/runtime references not resolved"}


def build_report(workspace, native):
    source_path = ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    if sha(source_path.read_bytes()) != SOURCE_SHA:
        raise ValueError("Original firmware identity differs")
    manifest, raw = load_analysis(workspace)
    mapped = AddressMap(raw, manifest["regions"])
    validate_facts(mapped)
    diagnostic_bindings = []
    for address, prefix in STRINGS.items():
        value = mapped.text(address)
        if not value.startswith(prefix):
            raise ValueError(f"Diagnostic identity differs at{address:#x}")
        diagnostic_bindings.append({"address": address, "text": value})
    native_rows = []
    for address in NATIVE_ENTRIES:
        path = native / "application/functions" / f"{address:08x}.json"
        body = path.read_bytes()
        dossier = json.loads(body)
        if int(dossier["address"], 16) != address:
            raise ValueError("Native function identity differs")
        checked = verify_dossier(dossier, mapped)
        native_rows.append({"entry": address, "dossier_sha256": sha(body),
                            "instructions_byte_compared": checked,
                            "decompilation_completed": dossier.get("decompilation_completed", False),
                            "ranges": dossier["ranges"],
                            "pseudocode_sha256": sha((dossier.get("pseudocode") or "").encode()),
                            "source_file": path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)})
    profile = json.loads((native / "profile.json").read_text())
    if profile["analysis_sha256"] != sha(raw) or profile["source_sha256"] != SOURCE_SHA:
        raise ValueError("Native source profile differs")
    descriptor = [{"offset": index * 4, "width": 4, "name": name,
                   "meaning": "Stored buffer/address token; not proof of CPU accessibility" if index == 0 else
                              "Parent frame coordinate extent, not established byte pitch" if index in (1, 2) else
                              "ROI coordinate inferred from checked guard diagnostics and field copies"}
                  for index, name in enumerate(FRAME_FIELDS)]
    report = {
        "schema_version": 1, "source_sha256": SOURCE_SHA, "analysis_sha256": sha(raw),
        "method": "Authenticated Capstone instructions corroborated by retained direct Ghidra dossiers; not native REA Evidence",
        "target_executed": False, "device_commands_issued": False,
        "instruction_assertions": len(FACTS), "native_dossiers": native_rows,
        "diagnostic_bindings": diagnostic_bindings,
        "contracts": [
            {"id": "capture.shared_frame_descriptor", "evidence_type": "instructions-plus-explicit-guard-diagnostics",
             "size": 28, "byte_order": "little", "fields": descriptor,
             "jpeg_setup_entry": 0x801a4490, "jpeg_option_offsets": {"image_descriptor": 8, "chroma_descriptor": 0x24},
             "reviewed_guards": {"width_height_nonzero": [0x801a4558, 0x801a4560],
                                 "frame_width_vs_wrapped_left_plus_width": [0x801a4564, 0x801a4734, 0x801a4738],
                                 "chroma420_even_left_top": [0x801a48ec, 0x801a4930]},
             "limits": ["No physical allocation size, byte stride, pixel packing/bit depth or cache ownership is established.",
                        "Horizontal addition has no overflow check in this guard; reviewed guard does not establish vertical containment."]},
            {"id": "capture.descriptor_retention", "setter": 0x80190a4c,
             "driver_type_zero": {"selector7": {"destination": "driver+8", "bytes_copied": 28},
                                  "selector9": {"destination": "driver+0x28", "bytes_copied": 28},
                                  "selector8": {"destination": "driver+0x860", "bytes_copied": 28, "flag": "byte+0x87c=1"}},
             "geometry_setter": 0x8018e9f4, "fallback": "If ROI width or height is zero, both are replaced by parent frame dimensions; left/top retained",
             "buffer_setter": 0x8018ff74, "pointer_fields": [8, 0x28, 0x48],
             "ownership": "Descriptor words are copied, including an address token. The described buffer bytes are not deep-copied by these setters; caller lifetime remains required."},
            {"id": "capture.temporary_scale_buffer", "prepare": 0x8018f200,
             "allocator_site": 0x8018f4dc, "allocator": 0x80020980,
             "requested_size": "low32(width * height * numeric_format_multiplier), with observed multiplier2 or3",
             "descriptor_output": "allocation result at descriptor+0; dimensions copied into descriptor+4/+8 and+0x14/+0x18; left/top zeroed",
             "overflow_or_null_protection": "No overflow check or immediate null-result branch in reviewed allocation window0x8018f4a0..0x8018f4f8",
             "free_route": {"cleanup": 0x8018f184, "condition": "temporary_path != original_path",
                            "restore_buffers": 0x8018ff74, "delete_temporary_path": 0x8018e344,
                            "free_site": 0x8018f1d0, "free": 0x80020e94,
                            "restore_geometry": 0x8018e9f4},
             "ownership": "Temporary scale buffer is internally allocated and freed by this helper lifecycle; it is not an additional user-owned frame slot."},
            {"id": "capture.path_execution_completion", "wrapper": 0x8018f6e4,
             "sequence": [0x8018f200, 0x801975c8, 0x801978f0, 0x80197ac8, 0x8018f184],
             "completion_helper": {"entry": 0x80197ac8, "wait_site": 0x80197b68,
                                   "wait": 0x800c1014, "timeout_field": "path+0xac", "completion_callback_site": 0x80197b80},
             "limits": "Conditional event wait and type-specific indirect callback precede cleanup; full event semantics, interrupts, callback success and cache/DMA coherence are not established."},
            {"id": "capture.frame_alignment", "entry": 0x80191fd4,
             "mode0": "round frame width up to16, height up to8", "mode1": "round width and height up to16",
             "other_modes": "diagnostic rejection", "limits": "Normal nonoverflowing arithmetic only; this helper does not establish universal sensor dimensions or bytes per pixel."},
            {"id": "capture.raw_to_yuv_reachability", "analyst_entry": 0x80205918,
             "descriptor_setter_sites": [0x80205c40, 0x80205c60],
             "native_dossier_present": (native / "application/functions/80205918.json").is_file(),
             "reference_scan": reference_scan(manifest, raw, 0x80205918),
             "limits": "The wrapper has no aligned J/JAL or direct pointer references in the scanned regions. Dynamic/external/runtime reachability remains unknown; this is not a verified ordinary saved-photo hook."}
        ],
        "unresolved": ["Ordinary saved-JPEG caller and active buffer values/colour domain",
                       "CPU versus device address domains, pitch units, planar/interleaved packing, Bayer/bit depth",
                       "Caller-owned capture buffer allocation/free lifetime, aliasing and shared consumers",
                       "Cache maintenance, DMA synchronization and permitted hook execution context",
                       "Verified software recovery and safe executable placement/hook"],
        "safe_capture_adapter_established": False, "ready_for_executable_trial": False,
    }
    if sha(source_path.read_bytes()) != SOURCE_SHA:
        raise ValueError("Original source changed during analysis")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT / "derived/unpacked-v1.1-indexed")
    parser.add_argument("--native", type=Path, default=ROOT / "derived/native-analysis-complete")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/capture-buffers.json")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Choose a new evidence path")
    report = build_report(args.workspace.resolve(), args.native.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"contracts": len(report["contracts"]), "instruction_assertions": report["instruction_assertions"],
                      "native_dossiers_byte_checked": len(report["native_dossiers"]),
                      "safe_capture_adapter_established": False}))


if __name__ == "__main__":
    main()
