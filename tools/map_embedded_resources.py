"""Find filesystem-resource copies in the authenticated decoded application.

Static evidence only. Exact copies do not prove that a resource is active.
Also records the source-bound HCE dispatcher for the English table and gamma.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from workspace_functions import load_analysis
from map_development_interfaces import AddressMap

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact_matches(needle, regions, limit=16):
    if not needle or limit < 1:
        raise ValueError("Nonempty resource and positive match limit required")
    result = []
    for address, body in regions:
        offset = 0
        while True:
            offset = body.find(needle, offset)
            if offset < 0:
                break
            result.append({"virtual_start": address+offset, "size": len(needle)})
            if len(result) == limit:
                return result, False
            offset += 1
    return result, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"evidence/embedded-resources.json")
    parser.add_argument("--listings", type=Path, default=ROOT/"derived/embedded-resource-analysis")
    args = parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise ValueError("Use new evidence and listing paths")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Source identity differs")
    manifest, raw = load_analysis(ROOT/"derived/unpacked-v1.1-indexed")
    address_map = AddressMap(raw, manifest["regions"])
    regions = [(r["virtual_start"], raw[r["analysis_elf_offset"]:r["analysis_elf_offset"]+r["size"]])
               for r in manifest["regions"]]
    filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    if filesystem["input_sha256"] != BASELINE:
        raise ValueError("Resource evidence identity differs")
    files = []
    for entry in filesystem["entries"]:
        if entry["kind"] != "file":
            continue
        content = b"".join(source[c["carrier_offset"]:c["carrier_offset"]+c["file_bytes"]]
                           for c in entry["chunks"])
        if len(content) != entry["size"] or sha(content) != entry["sha256"]:
            raise ValueError("Source resource reconstruction failed")
        matches, complete = exact_matches(content, regions) if len(content) >= 16 else ([], False)
        files.append({"path": entry["path"], "size": len(content), "sha256": sha(content),
                      "embedded_exact_matches": matches, "match_search_complete": complete})
    english = next(f for f in files if f["path"] == "String/Res_Str_Eng_New.bst")
    if english["embedded_exact_matches"] != [{"virtual_start": 0x8036add4, "size": 46392}]:
        raise ValueError("English embedded-resource identity differs")
    table = struct.unpack("<14I", address_map.read(0x8037630c, 56))
    if table[12] != 0x8000c344 or table[8] != 0x8000c40c:
        raise ValueError("HCE dispatch table differs")
    gamma = next(f for f in filesystem["entries"] if f["path"] == "GammaLut0.bin")
    gamma_file = b"".join(source[c["carrier_offset"]:c["carrier_offset"]+c["file_bytes"]]
                          for c in gamma["chunks"])
    gamma_embedded = address_map.read(0x80348344, 960)
    gamma_difference = sum(a != b for a, b in zip(gamma_file, gamma_embedded))
    import sys
    sys.path.insert(0, str(ROOT/"tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    args.listings.mkdir(parents=True)
    listings = []
    for name, start, size in (("hce_resource_dispatch", 0x8000c300, 0x25c),
                               ("gamma_preferred_embedded_path", 0x8021c7a8, 0x1b8)):
        body = address_map.read(start, size)
        instructions = list(decoder.disasm(body, start))
        if sum(i.size for i in instructions) != size:
            raise ValueError("Incomplete selected MIPS32 listing")
        path = args.listings/(name+".asm")
        path.write_text("; Static analyst window; branch delay slots matter.\n"+
                        "\n".join(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in instructions)+"\n")
        listings.append({"name": name, "start": start, "size": size,
                         "sha256": sha(body), "path": str(path.relative_to(ROOT))})
    report = {"source_sha256": BASELINE, "analysis_sha256": sha(raw),
              "method": "Whole-file exact matches against authenticated application regions; reviewed static dispatcher",
              "resources_checked": len(files), "resources_with_exact_embedded_copy": sum(bool(f["embedded_exact_matches"]) for f in files),
              "files": files, "listings": listings,
              "english": {"path": english["path"], "embedded_virtual_start": 0x8036add4,
                          "full_copy_bytes": 46392, "full_copy_sha256": english["sha256"],
                          "label_virtual_start": 0x8036e14c,
                          "dispatcher_category": 12, "dispatcher_case": 0x8000c344,
                          "path_literal_va": 0x80347cbc,
                          "path_literal": address_map.text(0x80347cbc),
                          "pointer_materialization": [0x8000c35c, 0x8000c360],
                          "returned_size_raw": 0x729e,
                          "returned_size_differs_from_whole_resource": True},
              "gamma": {"dispatcher_category": 8, "dispatcher_case": 0x8000c40c,
                        "embedded_virtual_start": 0x80348344, "bytes": 960,
                        "embedded_sha256": sha(gamma_embedded), "filesystem_sha256": sha(gamma_file),
                        "differing_bytes": gamma_difference,
                        "loader_prefers_successful_embedded_lookup_to_file_fallback": True},
              "hardware_observation": "User reports v1.1 after update, but no Welcome studio label",
              "limitations": ["Only exact file copies are inventoried; differing or partial embedded resources may exist.",
                              "Static resource dispatch and the observed missing label suggest fallback-only patching; active UI call chain remains to be completed.",
                              "The English dispatch returns raw size 0x729e, smaller than the 46392-byte matched resource; its units/consumer handling remain unresolved.",
                              "No new firmware output, flash, camera command or speed improvement occurs."]}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({k: report[k] for k in ("resources_checked", "resources_with_exact_embedded_copy", "english", "gamma")}))


if __name__ == "__main__":
    main()
