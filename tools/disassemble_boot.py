"""Save focused static MIPS32 listings with source offsets and symbolized calls.

No execution or emulation. Requires tools/vendor/capstone and existing pyelftools.
Does not decode MIPS16 or prove actual hardware behavior.
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN


def main():
    root = Path(__file__).resolve().parents[1]
    mapping = json.loads((root / "derived/v1.1-mapped/map.json").read_text())
    source = Path(mapping["input_path"])
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != mapping["sha256"]:
        raise RuntimeError("Firmware identity changed")
    image = mapping["images"][0]
    symbols = [s for s in image["symbols"] if s["section"] != "SHN_UNDEF"]
    names = {s["value"]: s["name"] for s in symbols if s["type"] == "STT_FUNC"}
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    selected = [
        "main", "Burn", "BurnMain", "BurnGetSectionsMap", "BurnHashInit",
        "BurnHashUpdate", "BurnHashFanalize", "BurnHashManager", "md5_init",
        "md5_append", "md5_finish", "DebugConsoleMain", "MonitorPreParse",
        "CpuPerformanceMonitorStart", "CpuPerformanceMonitorRead",
    ]
    records = []
    for name in selected:
        symbol = next(s for s in symbols if s["name"] == name)
        if len(symbol["firmware_offsets"]) != 1:
            raise RuntimeError(f"Ambiguous or unbacked symbol: {name}")
        offset, size = symbol["firmware_offsets"][0], symbol["size"]
        instructions = list(decoder.disasm(data[offset:offset + size], symbol["value"]))
        decoded_size = sum(i.size for i in instructions)
        calls, lines = [], []
        for instruction in instructions:
            location = offset + instruction.address - symbol["value"]
            annotation = ""
            if instruction.mnemonic in ("jal", "j"):
                try:
                    target = int(instruction.op_str, 0)
                    annotation = names.get(target, "unresolved symbol")
                    calls.append({"site": instruction.address, "target": target,
                                  "symbol": names.get(target),
                                  "kind": instruction.mnemonic})
                except ValueError:
                    pass
            lines.append(f"{instruction.address:08x} file:{location:08x}  "
                         f"{instruction.bytes.hex():8}  {instruction.mnemonic:10} "
                         f"{instruction.op_str}" + (f"  # {annotation}" if annotation else ""))
        path = root / "derived/v1.1-mapped" / f"{name}.asm"
        path.write_text("; Static Capstone MIPS32 little-endian listing.\n"
                        "; Branch delay-slot semantics require analyst interpretation.\n"
                        + "\n".join(lines) + "\n", encoding="utf-8")
        records.append({"name": name, "address": hex(symbol["value"]),
                        "firmware_offset": hex(offset), "symbol_size": size,
                        "decoded_size": decoded_size, "complete_linear_decode": decoded_size == size,
                        "bytes_sha256": hashlib.sha256(data[offset:offset + size]).hexdigest(),
                        "calls": calls})
    output = root / "evidence/boot-function-analysis.json"
    output.write_text(json.dumps({"method": "Capstone 5.0.6, not REA decompilation",
                                 "firmware_sha256": mapping["sha256"], "functions": records,
                                 "limitations": ["Static linear decoding only; no runtime observation.",
                                                 "Direct calls are identified; indirect calls remain unresolved.",
                                                 "Coverage is limited to the selected boot-image symbols."]}, indent=2))
    print(json.dumps({"functions": len(records),
                      "complete_linear_decodes": sum(r["complete_linear_decode"] for r in records),
                      "output": str(output)}, indent=2))


if __name__ == "__main__":
    main()
