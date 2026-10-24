"""Source-bound offline startup JPEG/audio map; no device access or writes."""
import argparse
from io import BytesIO
import json
from pathlib import Path
import struct
import sys
import wave

from build_startup_asset import jpeg_contract
from map_embedded_resources import BASELINE, ROOT, sha, exact_matches
from workspace_functions import load_analysis, listing
from map_development_interfaces import AddressMap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/startup-assets.json")
    parser.add_argument("--listings", type=Path, default=ROOT/"derived/startup-resource-map-01")
    args = parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise ValueError("Use new evidence and listing paths")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Unsupported baseline")
    manifest, raw = load_analysis(ROOT/"derived/unpacked-v1.1-indexed")
    mapped = AddressMap(raw, manifest["regions"])
    regions = [(r["virtual_start"], raw[r["analysis_elf_offset"]:r["analysis_elf_offset"]+r["size"]])
               for r in manifest["regions"]]
    filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    if filesystem["input_sha256"] != BASELINE:
        raise ValueError("Filesystem source binding differs")
    files = []
    for name in ("JPG/Startup1.jpg", "Wav/Startup1.wav"):
        entry = next(f for f in filesystem["entries"] if f["path"] == name)
        content = b"".join(source[c["carrier_offset"]:c["carrier_offset"]+c["file_bytes"]]
                           for c in entry["chunks"])
        if len(content) != entry["size"] or sha(content) != entry["sha256"]:
            raise ValueError("Resource source binding differs")
        matches, complete = exact_matches(content, regions)
        row = {"path": name, "size": len(content), "sha256": sha(content),
               "embedded_exact_matches": matches, "embedded_search_complete": complete,
               "directory_entry_carrier_offset": entry["directory_entry_offset"],
               "file_bytes_carrier_ranges": [[c["carrier_offset"], c["carrier_offset"]+c["file_bytes"]]
                                             for c in entry["chunks"]]}
        if name.endswith(".jpg"):
            row["format"] = jpeg_contract(content)
        else:
            with wave.open(BytesIO(content)) as sound:
                row["format"] = {"channels": sound.getnchannels(), "sample_width_bytes": sound.getsampwidth(),
                                 "sample_rate_hz": sound.getframerate(), "frames": sound.getnframes(),
                                 "compression": sound.getcomptype(),
                                 "duration_seconds": sound.getnframes()/sound.getframerate()}
        files.append(row)
    if mapped.text(0x803878f4) != "A:\\JPG\\Startup1.jpg" or mapped.text(0x803876fc) != "A:\\Wav\\Startup1.wav":
        raise ValueError("Startup path literals differ")
    table = list(struct.unpack("<14I", mapped.read(0x8037630c, 56)))
    if table != [0x8000c498, 0x8000c484, 0x8000c470, 0x8000c45c, 0x8000c4c0,
                 0x8000c4ac, 0x8000c448, 0x8000c420, 0x8000c40c, 0x8000c3f8,
                 0x8000c36c, 0x8000c3b8, 0x8000c344, 0x8000c38c]:
        raise ValueError("HCE dispatcher table differs")
    sys.path.insert(0, str(ROOT/"tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    args.listings.mkdir(parents=True)
    listing_rows = []
    for start, size, name in ((0x8000c300, 0x25c, "hce_resource_dispatch"),
                               (0x802219e0, 0x40, "startup_image_wrapper_window"),
                               (0x80233cb0, 0x44, "image_wrapper_window"),
                               (0x8023393c, 0x374, "image_loader_window"),
                               (0x80237a34, 0x48, "image_dispatch_wrapper_window")):
        body = mapped.read(start, size)
        instructions = list(decoder.disasm(body, start))
        if sum(i.size for i in instructions) != size:
            raise ValueError("Incomplete static listing")
        path = args.listings/(name+".asm")
        path.write_text("; Static window; function boundaries/reachability unverified; delay slots matter.\n"+
                        "\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}"
                                  for i in instructions)+"\n")
        listing_rows.append({"start": start, "size": size, "sha256": sha(body),
                             "path": path.relative_to(ROOT).as_posix(), "boundary_source": "analyst-selected window"})
    for start in (0x807415c8, 0x807417d0):
        text, row = listing(ROOT/"derived/unpacked-v1.1-indexed", start)
        path = args.listings/f"{start:08x}.asm"
        path.write_text(text)
        listing_rows.append({**row, "path": path.relative_to(ROOT).as_posix(), "boundary_source": "compiler unwind range"})
    report = {"source_sha256": BASELINE, "analysis_sha256": sha(raw), "method": "source-bound Python/Capstone static analysis; not REA Evidence",
              "files": files, "path_literals": {"startup_jpeg": 0x803878f4, "startup_wav": 0x803876fc},
              "hce": {"dispatcher": 0x8000c300, "table": 0x8037630c,
                      "category_handlers": table, "startup_image_or_sound_case_in_reviewed_dispatcher": False},
              "jpeg_calls": [{"call": call, "callee": 0x802219e0, "path": 0x803878f4}
                             for call in (0x8074171c, 0x80741888, 0x807419b0)],
              "jpeg_loader_chain": [0x802219e0, 0x80233cb0, 0x8023393c, 0x80237a34, 0x80237698],
              "listings": listing_rows,
              "limitations": ["Static calls and exact-copy searches do not establish current runtime selection or loading.",
                              "The reviewed HCE dispatcher has no startup JPEG/audio case; other caches or copies are not excluded.",
                              "No full camera JPEG parser equivalence or hardware decoder acceptance established.",
                              "Audio consumer/timing not traced; no chime modification recommended by this map.",
                              "Exact-size replacement avoids FAT metadata/cluster-chain or encoded-code changes.",
                              "No update, restoration, timing or battery result is established."]}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"files": [{k: f[k] for k in ("path", "size", "sha256", "format")} for f in files],
                      "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
