"""Offline source-bound startup/branding map; creates analysis, never firmware.

Requires the validated synthesized application ELF. Resources remain ignored;
the report contains metadata, hashes and analyst-reviewed static observations.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import wave

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
from map_application import address_pairs, candidate_prologue, words, EXPECTED

WINDOWS = [
    ("welcome_menu_creator", 0x8061c0cc, 0xc0),
    ("welcome_menu_event", 0x8061c18c, 0x140),
    ("welcome_selected_image_creator", 0x8061c5a8, 0xb8),
    ("startup_sound_load", 0x8074050c, 0x3c),
    ("welcome_image_preview", 0x807415c8, 0x208),
    ("welcome_image_present", 0x807417d0, 0x210),
    ("welcome_image_callers", 0x806a9a4c, 0x80),
    ("welcome_image_second_caller", 0x806a9ca8, 0x68),
    ("startup_sound_play_gate", 0x80740e50, 0xe4),
    ("sound_option_dispatch", 0x807414d8, 0xf0),
    ("welcome_settings_readback", 0x8061f770, 0x30),
    ("menu_selection_updater", 0x806fbfa8, 0xd8),
    ("display_image_wrapper", 0x802219e0, 0x40),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def jpeg_frame(data):
    if data[:2] != b"\xff\xd8":
        raise ValueError("Not a JPEG")
    cursor = 2
    while cursor < len(data):
        if data[cursor] != 0xff:
            raise ValueError("Invalid JPEG marker alignment")
        while cursor < len(data) and data[cursor] == 0xff:
            cursor += 1
        if cursor == len(data):
            raise ValueError("Truncated JPEG marker")
        marker = data[cursor]
        cursor += 1
        if marker in (0xd8, 0xd9) or 0xd0 <= marker <= 0xd7:
            continue
        if cursor+2 > len(data):
            raise ValueError("Truncated JPEG segment")
        size = struct.unpack_from(">H", data, cursor)[0]
        if size < 2 or cursor+size > len(data):
            raise ValueError("Invalid JPEG segment size")
        if marker in (0xc0, 0xc1, 0xc2):
            if size < 8:
                raise ValueError("Short JPEG frame")
            precision, height, width, components = struct.unpack_from(">BHHB", data, cursor+2)
            return {"sof_marker": marker, "precision_bits": precision,
                    "width": width, "height": height, "components": components}
        if marker == 0xda:
            break
        cursor += size
    raise ValueError("No supported JPEG frame found")


def english_records(data):
    """Bounded local table read; ordinal is deliberately not called runtime ID."""
    if data[:4] != b"ZST\0":
        raise ValueError("Not a ZST table")
    count = struct.unpack_from("<I", data, 4)[0]
    width = struct.unpack_from("<H", data, 20)[0]
    if width not in (1, 2):
        raise ValueError("Unsupported string width")
    cursor = 22+2*width
    result = []
    for ordinal in range(count-1):
        if cursor+2 > len(data):
            raise ValueError("Truncated string length")
        length = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if cursor+length+width > len(data):
            raise ValueError("Truncated string")
        body = data[cursor:cursor+length]
        if data[cursor+length:cursor+length+width] != bytes(width):
            raise ValueError("Invalid terminator")
        text = body.decode("utf-16be" if width == 2 else "latin1")
        if text in ("Welcome screen", "None", "Nikon", "Select an image", "Quick startup", "Sound settings"):
            result.append({"ordinal_zero_based": ordinal, "text": text,
                           "runtime_id_verified": False})
        cursor += length+width
    if cursor != len(data):
        raise ValueError("String table trailing bytes")
    return result


def main():
    sys.path.insert(0, str(ROOT/"tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    path = ROOT/"derived/v1.1-analysis-final/manifest.json"
    manifest = json.loads(path.read_text())
    firmware = Path(ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    elf = Path(manifest["elf_file"]).read_bytes()
    if sha(firmware) != EXPECTED or manifest["source_sha256"] != EXPECTED:
        raise ValueError("Firmware identity mismatch")
    if sha(elf) != manifest["elf_sha256"] or not manifest["elf_parser_roundtrip_verified"] or not manifest["original_elf_program_headers_verified"]:
        raise ValueError("Unvalidated analysis ELF")
    regions = []
    for region in manifest["regions"]:
        body = elf[region["analysis_elf_offset"]:region["analysis_elf_offset"]+region["size"]]
        if len(body) != region["size"] or sha(body) != region["sha256"]:
            raise ValueError("Analysis region changed")
        regions.append((region["virtual_start"], body, region))
    def read(address, size):
        base, data, binding = next(r for r in regions if r[0] <= address and address+size <= r[0]+len(r[1]))
        return data[address-base:address-base+size], binding
    strings = []
    for base, body, binding in regions:
        for match in re.finditer(rb"[ -~]{5,}", body):
            text = match.group().decode()
            if any(t in text.lower() for t in ("startup1", "setupcreatorwelcome", "quickstartup", "nikon")):
                strings.append({"text": text, "virtual_address": base+match.start(),
                                "region_sha256": binding["sha256"], "references": []})
    targets = {s["virtual_address"]: s for s in strings}
    for base, body, _ in regions:
        for reference in address_pairs(base, body, set(targets)):
            reference["preceding_prologue_candidate"] = candidate_prologue(base, body, reference["lui_address"])
            targets[reference["target"]]["references"].append(reference)
    out = ROOT/"derived/branding-analysis"
    out.mkdir(exist_ok=True)
    listings = []
    for label, address, size in WINDOWS:
        body, binding = read(address, size)
        decoded = list(Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN).disasm(body, address))
        if sum(i.size for i in decoded) != size:
            raise ValueError("Incomplete selected decode")
        listing = out/f"{label}.asm"
        listing.write_text("; Analyst-selected static window, not recovered symbols. Branch delay slots matter.\n"+
                           "\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in decoded)+"\n")
        listings.append({"analyst_label": label, "address": address, "size": size,
                         "sha256": sha(body), "source_region_sha256": binding["sha256"],
                         "listing": str(listing.relative_to(ROOT)), "complete_linear_decode": True})
    resource_report = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    resources = []
    for name in ("JPG/Startup1.jpg", "Wav/Startup1.wav", "String/Res_Str_Eng_New.bst"):
        resource = ROOT/"derived/resources-v1.1"/name
        data = resource.read_bytes()
        # Validate local resource content against the previously source-bound
        # extractor inventory, with original cluster ranges retained there.
        item = next(x for x in resource_report["files"] if x["path"] == name) if "files" in resource_report else next(x for x in resource_report["entries"] if x["path"] == name)
        if sha(data) != item["sha256"] or len(data) != item["size"]:
            raise ValueError("Resource changed")
        record = {"path": name, "size": len(data), "sha256": sha(data),
                  "directory_entry_offset": item["directory_entry_offset"],
                  "source_cluster_chunks": item["chunks"]}
        if name.endswith(".jpg"):
            record["jpeg_frame"] = jpeg_frame(data)
        if name.endswith(".wav"):
            with wave.open(str(resource), "rb") as sound:
                record["wave"] = {"channels": sound.getnchannels(), "sample_rate": sound.getframerate(),
                                  "sample_width_bytes": sound.getsampwidth(), "frames": sound.getnframes(),
                                  "duration_seconds": sound.getnframes()/sound.getframerate()}
        if name.endswith(".bst"):
            record["english_options"] = english_records(data)
        resources.append(record)
    calls = []
    known_targets = {a for _, a, _ in WINDOWS}
    for base, body, _ in regions:
        for n, word in enumerate(words(body)):
            address = base+n*4
            if word in known_targets:
                calls.append({"type": "pointer_valued_word", "address": address, "target": word,
                              "runtime_dispatch_verified": False})
            if word >> 26 in (2, 3):
                target = ((address+4)&0xf0000000)|((word&0x3ffffff)<<2)
                if target in known_targets:
                    calls.append({"type": "jal_or_j_candidate", "address": address, "target": target,
                                  "runtime_reachability_verified": False})
    report = {"source_sha256": EXPECTED, "analysis_elf_sha256": sha(elf),
              "analysis_manifest_sha256": sha(path.read_bytes()), "resources": resources,
              "strings": strings, "static_windows": listings, "direct_and_pointer_candidates": calls,
              "observations": [
                  {"site": "0x807417d0..0x807419dc", "finding": "Presentation candidate returns before image decode when low8(a0)==0; nonzero path passes A:\\JPG\\Startup1.jpg into 0x802219e0. Caller ABI/policy remains unresolved."},
                  {"site": "0x807415c8..0x807415f4", "finding": "Preview candidate handles a1 values 1 and 2 only; value zero returns without image presentation. Branch 1 uses Startup1.jpg; branch 2 uses B:\\IMG00000.jpg."},
                  {"site": "0x8061c1c0..0x8061c228", "finding": "Welcome menu confirm events write selected menu value into object-pointer *(0x80891ebc) byte +0x19; no safe standalone settings write API established."},
                  {"site": "0x8074050c..0x80740544", "finding": "Startup WAV path is passed to 0x8020926c with a1=0; returned handle stored at 0x809f0024."},
                  {"site": "0x80740e64..0x80740f20", "finding": "Sound playback candidate gated by a0!=0, byte 0x80892144!=0, byte 0x8089185a==0, and audio-init byte 0x80897fba. Sets active byte 0x80897fbc and calls 0x802092b4."}],
              "stock_settings_status": "Menu and zero-value skip behavior exist, but complete mapping from user choice to power-on presentation argument remains unresolved; no camera setting changed.",
              "candidate_changes": ["Resource-only custom startup JPEG respecting resource boundaries and decoder compatibility", "Route the verified no-presentation branch through a future validated welcome-policy setting", "Keep startup sound optional through existing gates"],
              "limitations": ["No executable patch generated, no firmware repacked or installed.",
                              "Pointer-valued data and instruction pairs are static candidates, not proof of reachable code.",
                              "Removing JPEG branding is cosmetic; does not establish flash/RAM/latency gains.",
                              "Nikon EXIF, USB identity, filesystem and update model identifiers are compatibility data; not all occurrences are display branding.",
                              "200 and 500 scheduler-helper arguments found in menu flows are not measured boot delays or safe removal targets.",
                              "No recovery route or runtime memory layout is demonstrated."]}
    (ROOT/"evidence/branding-map.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"resources": len(resources), "branding_strings": len(strings), "static_windows": len(listings), "installed_changes": 0}))


if __name__ == "__main__":
    main()
