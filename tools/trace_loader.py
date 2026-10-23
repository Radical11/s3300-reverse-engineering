"""Retain source-bound MIPS32 disassembly windows for packed loader research.

Names below are analyst labels inferred from nearby diagnostics and operations,
not recovered symbols. No emulator, camera or firmware writer is involved.
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
        raise RuntimeError("Firmware identity mismatch")
    image = next(i for i in mapping["images"] if i["root_offset"] == 0x1026c0)
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    selections = [("segment_inflater_worker_candidate", 0x800dfcd8, 0x290),
                  ("inflate_stream_loop_candidate", 0x800edb74, 0x360),
                  ("inflate_word_feed_mmio", 0x800ee0d0, 0xbc),
                  ("inflate_processor_init_candidate", 0x800ee29c, 0x1b4)]
    output = root / "derived/loader-pass-2"
    output.mkdir(exist_ok=True)
    records = []
    for label, address, size in selections:
        segments = [s for s in image["segments"]
                    if s["p_vaddr"] <= address
                    and address + size <= s["p_vaddr"] + s["p_filesz"]]
        if len(segments) != 1:
            raise ValueError("Window is not uniquely file-backed")
        segment = segments[0]
        offset = image["root_offset"] + segment["p_offset"] + address - segment["p_vaddr"]
        selected = data[offset:offset+size]
        instructions = list(decoder.disasm(selected, address))
        if sum(i.size for i in instructions) != size:
            raise ValueError("Incomplete window decode")
        rows = [f"{i.address:08x} file:{offset+i.address-address:08x} "
                f"{i.bytes.hex():8} {i.mnemonic:10} {i.op_str}" for i in instructions]
        (output / f"{label}.asm").write_text(
            "; Analyst-labelled static window, not recovered function boundaries.\n"
            "; MIPS branch delay slots require interpretation.\n" + "\n".join(rows) + "\n")
        records.append({"analyst_label": label, "virtual_start": address,
                        "virtual_start_hex": hex(address), "firmware_offset": offset,
                        "firmware_offset_hex": hex(offset), "byte_count": size,
                        "sha256": hashlib.sha256(selected).hexdigest(),
                        "instruction_count": len(instructions),
                        "listing": str(output / f"{label}.asm")})
    report = {"method": "Capstone 5.0.6 static MIPS32 little-endian windows",
              "input_sha256": mapping["sha256"], "windows": records,
              "observations": [
                  {"window": "inflate_word_feed_mmio", "instruction_address": "0x800ee150",
                   "instruction": "addiu $v1, $v1, -1"},
                  {"window": "inflate_word_feed_mmio", "instruction_address": "0x800ee154",
                   "instruction": "sw $v0, ($a1)",
                   "context": "a1 set to 0xb9800024 by lui/ori at 0x800ee140/144; loop loads words from a2"}],
              "limitations": ["No device MMIO was accessed.",
                              "No compressed output was decoded by this script.",
                              "Window labels/boundaries are analyst selections, not original symbols.",
                              "The static feed loop does not identify the entropy/table encoding."]}
    (root / "evidence/loader-pass-2.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"windows": len(records), "source_hash_verified": True}))


if __name__ == "__main__":
    main()
