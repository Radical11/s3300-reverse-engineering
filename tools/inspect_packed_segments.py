"""Validate observed type-2 packed ELF framing without decompressing or executing.

Run from the workspace root:
  python tools/inspect_packed_segments.py

The evidence output must be new. The four observed header words are interpreted
only after exact segment consumption and output-length sums validate the model.
No entropy decoder, firmware patch, or device interaction is implemented here.
"""
from pathlib import Path
import hashlib
import json
import struct


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    mapping_path = root / "derived/v1.1-mapped/map.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    source = Path(mapping["input_path"])
    carrier = source.read_bytes()
    source_hash = digest(carrier)
    if source_hash != mapping["sha256"]:
        raise ValueError("Carrier identity does not match the mapped evidence")
    destination = root / "evidence/packed-segments.json"
    if destination.exists():
        raise ValueError("Evidence output already exists; refusing to overwrite")
    expected_offsets = {0x220314, 0x3BD9FC, 0x5C2BEC, 0x6B55A0}
    segments = []
    for image in mapping["images"]:
        for segment in image["segments"]:
            start = image["root_offset"] + segment["p_offset"]
            if start not in expected_offsets:
                continue
            end = start + segment["p_filesz"]
            if start < 0 or end > len(carrier):
                raise ValueError("Mapped packed segment extends beyond the carrier")
            cursor = start
            total_output = 0
            blocks = []
            while cursor < end:
                if end - cursor < 16:
                    raise ValueError(f"Incomplete packed header at {cursor:#x}")
                kind, output_size, payload_size, table_word = struct.unpack_from("<4I", carrier, cursor)
                table_a_size = table_word & 0xFFFF
                table_b_size = table_word >> 16
                if kind != 2 or not output_size or not payload_size:
                    raise ValueError(f"Unexpected packed header at {cursor:#x}")
                if (not table_a_size or not table_b_size
                        or table_a_size % 4 or table_b_size % 4):
                    raise ValueError(f"Invalid table word lengths at {cursor:#x}")
                a_start = cursor + 16
                b_start = a_start + table_a_size
                payload_start = b_start + table_b_size
                block_end = payload_start + payload_size
                if block_end > end:
                    raise ValueError(f"Packed block exceeds segment at {cursor:#x}")
                next_output = total_output + output_size
                if next_output > segment["p_memsz"]:
                    raise ValueError("Declared block outputs exceed mapped segment memory size")

                def region(offset, size):
                    return {"carrier_offset": offset, "size": size,
                            "sha256": digest(carrier[offset:offset + size])}

                blocks.append({
                    "index": len(blocks), "header": region(cursor, 16),
                    "header_words_le": [kind, output_size, payload_size, table_word],
                    "observed_type": kind, "declared_output_bytes": output_size,
                    "table_a": {**region(a_start, table_a_size), "word_count": table_a_size // 4},
                    "table_b": {**region(b_start, table_b_size), "word_count": table_b_size // 4},
                    "payload": region(payload_start, payload_size),
                    "carrier_end_exclusive": block_end,
                    "inferred_destination": {
                        "basis": "Consecutive declared block output lengths relative to ELF PT_LOAD; not an observed runtime write",
                        "virtual_start": segment["p_vaddr"] + total_output,
                        "virtual_end_exclusive": segment["p_vaddr"] + next_output,
                        "physical_start": segment["p_paddr"] + total_output,
                        "physical_end_exclusive": segment["p_paddr"] + next_output}})
                total_output = next_output
                cursor = block_end
            if cursor != end or total_output != segment["p_memsz"]:
                raise ValueError("Framing model does not exactly match ELF sizes")
            segments.append({
                "elf_root_offset": image["root_offset"],
                "carrier_offset": start, "carrier_end_exclusive": end,
                "packed_bytes": segment["p_filesz"], "packed_sha256": digest(carrier[start:end]),
                "elf_p_vaddr": segment["p_vaddr"], "elf_p_paddr": segment["p_paddr"],
                "elf_p_memsz": segment["p_memsz"], "elf_p_flags": segment["p_flags"],
                "block_count": len(blocks), "sum_declared_output_bytes": total_output,
                "exact_segment_consumption": True, "output_sum_equals_elf_memsz": True,
                "blocks": blocks})
    if {s["carrier_offset"] for s in segments} != expected_offsets:
        raise ValueError("Expected packed segments are missing or duplicated")
    if digest(source.read_bytes()) != source_hash:
        raise ValueError("Carrier changed during inspection")
    report = {
        "method": "Python static type-2 block framing inference and bounded validation; not REA decompilation or runtime execution",
        "input_path": str(source), "input_sha256": source_hash,
        "mapping_path": str(mapping_path), "input_hash_unchanged_after_inspection": True,
        "inferred_header": {
            "header_size": 16, "endianness": "little",
            "offset_0_u32": "Observed block type; all inspected blocks equal 2",
            "offset_4_u32": "Declared output byte count, inferred from exact sum equal to ELF p_memsz",
            "offset_8_u32": "Payload byte count, validated by exact next-block and segment boundary",
            "offset_12_u16": "Table A byte length; all are nonzero multiples of 4",
            "offset_14_u16": "Table B byte length; all are nonzero multiples of 4",
            "layout": "16-byte header, table A, table B, payload; next header immediately follows payload"},
        "segment_count": len(segments), "total_block_count": sum(s["block_count"] for s in segments),
        "total_packed_bytes": sum(s["packed_bytes"] for s in segments),
        "total_declared_output_bytes": sum(s["sum_declared_output_bytes"] for s in segments),
        "all_segments_exactly_consumed": True, "all_output_sums_equal_elf_memsz": True,
        "entropy_decoder_status": "Unknown; no decompressed output has been produced by this tool",
        "field_inference_evidence": "The same framing exhausts all four mapped file-backed segments with no remainder and sums exactly to each segment memory size across every block. Table and payload hashes preserve the source boundaries for independent checking.",
        "limitations": [
            "The table labels describe structured regions, not a confirmed Huffman implementation or instruction encoding.",
            "Declared output spans are inferred from ELF layout and block lengths; they are not runtime observations.",
            "Checksums or signatures required for modified firmware are not identified by this framing.",
            "No extracted region is represented as decompressed machine code.",
            "No repacking, source mutation, flash write, emulation, or camera command occurs."],
        "segments": segments}
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({k: report[k] for k in ["segment_count", "total_block_count", "total_packed_bytes",
                                           "total_declared_output_bytes", "all_segments_exactly_consumed",
                                           "all_output_sums_equal_elf_memsz", "entropy_decoder_status"]}, indent=2))


if __name__ == "__main__":
    main()
