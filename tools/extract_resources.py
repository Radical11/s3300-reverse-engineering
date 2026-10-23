"""Read-only FAT16 resource extraction from a firmware carrier; never repacks it.

Example (run from the workspace root):
  python tools/extract_resources.py sources/extracted-v1.1/S3300Update/firmware/firmware.bin --offset 0x6fe2c0 --output derived/resources-v1.1 --evidence evidence/resource-filesystem.json

The output directory and evidence file must not exist. Logical volume completeness
and completeness of allocated regular-file extraction are reported separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_component(name: str) -> str:
    if (not name or name in (".", "..") or name[-1:] in (" ", ".")
            or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name)
            or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", name, re.I)):
        raise ValueError(f"Unsafe resource filename: {name!r}")
    return name


def analyze_processing_resources(output: Path) -> dict:
    """Numerical observations only; these do not identify firmware consumers."""
    names = ["GammaDDE1.bin", "GammaDDE2.bin", "GammaDDE3.bin", "GammaDDE4.bin",
             "GammaLut0.bin", "Lclut0.bin", "Lclut1.bin", "Lclut2.bin",
             "Dlut.bin", "Ylut.bin", "BaseNlgf0.bin", "CTLut1.bin"]
    result = {}
    for name in names:
        path = output / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        item = {"bytes": len(raw), "sha256": sha256(raw), "candidates": {}}
        for label, width, fmt in [("u8", 1, "B"), ("u16_le", 2, "<H"),
                                  ("u16_be", 2, ">H"), ("u32_le", 4, "<I")]:
            if len(raw) % width or not raw:
                continue
            v = [struct.unpack_from(fmt, raw, i)[0] for i in range(0, len(raw), width)]
            delta = [b - a for a, b in zip(v, v[1:])]
            item["candidates"][label] = {
                "count": len(v), "minimum": min(v), "maximum": max(v),
                "distinct_values": len(set(v)), "first_eight": v[:8], "last_eight": v[-8:],
                "nondecreasing": all(d >= 0 for d in delta),
                "nonincreasing": all(d <= 0 for d in delta),
                "minimum_step": min(delta, default=0), "maximum_step": max(delta, default=0),
                "decrease_count": sum(d < 0 for d in delta),
                "first_decrease_indices": [i + 1 for i, d in enumerate(delta) if d < 0][:16]}
        if name.startswith("GammaDDE"):
            item["equals_u8_identity_ramp"] = raw == bytes(range(256))
            item["first_index_value_255"] = raw.index(255) if 255 in raw else None
            item["u8_samples"] = {str(i): raw[i] for i in [0, 16, 32, 64, 96, 128, 160, 192, 224, 255]}
            item["interpretation"] = "256-byte monotone lookup-table candidate. Runtime use and channel/domain mapping are unverified; monotonicity alone does not rule out wider encodings."
        elif name.startswith("Lclut"):
            v = struct.unpack("<256H", raw)
            item["equals_16_times_index"] = all(x == 16 * i for i, x in enumerate(v))
            item["equals_4080_minus_16_times_index"] = all(x == 4080 - 16 * i for i, x in enumerate(v))
            item["interpretation"] = "256 little-endian 16-bit values form a plausible 12-bit-output LUT; actual consumer and index domain are unverified."
        result[name] = item
    comic = output / "Comic.bin"
    if comic.is_file():
        result["Comic.bin"] = {"bytes": comic.stat().st_size,
                                "first_ascii_string": comic.read_bytes().split(b"\0", 1)[0].decode("ascii"),
                                "interpretation": "Font candidate based on Comic Sans MS prefix; do not treat filename as an image-effect algorithm."}
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("--offset", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--evidence", required=True, type=Path)
    ap.add_argument("--max-total-bytes", type=int, default=128 * 1024 * 1024)
    args = ap.parse_args()
    source = args.input.resolve(strict=True)
    output = args.output.resolve()
    evidence = args.evidence.resolve()
    if output.exists() or evidence.exists():
        raise ValueError("Output directory and evidence file must both be new")
    if source == evidence or source == output or source.is_relative_to(output):
        raise ValueError("Output must not contain or replace the input")
    if evidence.is_relative_to(output):
        raise ValueError("Keep evidence outside the extracted resource directory")
    carrier = source.read_bytes()
    original_hash = sha256(carrier)
    base = args.offset
    warnings: list[str] = []

    def read_at(offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(carrier):
            raise ValueError(f"Carrier bounds violation: {offset:#x}+{size:#x}")
        return carrier[offset:offset + size]

    boot = read_at(base, 512)
    if boot[510:512] != b"\x55\xaa" or boot[0] not in (0xE9, 0xEB):
        raise ValueError("Invalid FAT boot signature or jump instruction")
    u16 = lambda off: struct.unpack_from("<H", boot, off)[0]
    u32 = lambda off: struct.unpack_from("<I", boot, off)[0]
    bps, spc, reserved, nfats = u16(11), boot[13], u16(14), boot[16]
    root_entries, total16, spf, total32 = u16(17), u16(19), u16(22), u32(32)
    total = total16 or total32
    if bps not in (512, 1024, 2048, 4096) or not spc or spc & (spc - 1):
        raise ValueError("Invalid sector or cluster geometry")
    if not reserved or not nfats or not root_entries or not spf or not total:
        raise ValueError("Missing FAT16 geometry")
    root_sectors = math.ceil(root_entries * 32 / bps)
    data_sectors = total - reserved - nfats * spf - root_sectors
    cluster_count = data_sectors // spc
    if not 4085 <= cluster_count < 65525:
        raise ValueError(f"BPB describes {cluster_count} clusters, not FAT16")
    cluster_bytes = bps * spc
    fat_offset = base + reserved * bps
    fat = read_at(fat_offset, spf * bps)
    if len(fat) < (cluster_count + 2) * 2:
        raise ValueError("FAT cannot address the declared volume")
    if struct.unpack_from("<H", fat, 2)[0] < 0xFFF8:
        raise ValueError("Invalid reserved FAT entry 1")
    if fat[0] != boot[21]:
        # This carrier contains ff f8 ff ff, while its BPB media byte is f8.
        # Keep normal little-endian chain decoding; do not silently normalize it.
        warnings.append(f"Reserved FAT entry 0 {fat[:2].hex()} does not encode BPB "
                        f"media byte {boot[21]:02x} in the standard low byte. "
                        "All live chains are independently validated as little-endian FAT16.")
    for index in range(1, nfats):
        if read_at(fat_offset + index * spf * bps, len(fat)) != fat:
            raise ValueError("FAT copies differ")
    root_offset = fat_offset + nfats * spf * bps
    data_offset = root_offset + root_sectors * bps
    logical_end = base + total * bps
    volume_complete = logical_end <= len(carrier)
    if not volume_complete:
        warnings.append("The declared logical FAT16 volume extends beyond the carrier. "
                        "This is an incomplete volume image; a trimmed unused tail is a "
                        "hypothesis. Allocated file extraction is validated separately.")
    owners: dict[int, str] = {}
    records: list[dict] = []
    volume_labels: list[dict] = []
    names_seen: set[str] = set()

    def cluster_offset(c: int) -> int:
        if not 2 <= c <= cluster_count + 1:
            raise ValueError(f"Invalid cluster {c}")
        return data_offset + (c - 2) * cluster_bytes

    def chain(start: int, owner: str) -> list[int]:
        result: list[int] = []
        seen: set[int] = set()
        c = start
        while c < 0xFFF8:
            if c in seen:
                raise ValueError(f"FAT loop in {owner}: {c}")
            if not 2 <= c <= cluster_count + 1 or c >= 0xFFF0:
                raise ValueError(f"Invalid/reserved/bad chain cluster in {owner}: {c:#x}")
            seen.add(c)
            if c in owners:
                raise ValueError(f"Cross-linked cluster {c}: {owner} and {owners[c]}")
            owners[c] = owner
            read_at(cluster_offset(c), cluster_bytes)
            result.append(c)
            c = struct.unpack_from("<H", fat, c * 2)[0]
        return result

    def checksum(short: bytes) -> int:
        value = 0
        for c in short:
            value = (((value & 1) << 7) | (value >> 1)) + c
            value &= 255
        return value

    def entries(chunks: list[tuple[int, int]]):
        for off, size in chunks:
            raw = read_at(off, size)
            for i in range(0, len(raw), 32):
                yield off + i, raw[i:i + 32]

    def walk(chunks: list[tuple[int, int]], parent: tuple[str, ...], depth: int = 0):
        if depth > 64:
            raise ValueError("Directory nesting exceeds safety limit")
        lfns: list[bytes] = []
        for entry_offset, d in entries(chunks):
            if len(d) != 32 or not d[0]:
                break
            if d[0] == 0xE5:
                lfns = []
                continue
            attr = d[11]
            if attr == 0x0F:
                lfns.append(d)
                continue
            rawshort = d[:11]
            short = (rawshort[:8].decode("cp437").rstrip() +
                     ("." + rawshort[8:].decode("cp437").rstrip() if rawshort[8:].strip() else ""))
            if short in (".", ".."):
                lfns = []
                continue
            name = short
            if lfns:
                n = len(lfns)
                valid = (n <= 20 and lfns[0][0] == (0x40 | n)
                         and [x[0] & 0x1F for x in lfns] == list(range(n, 0, -1))
                         and all(x[12] == 0 and x[13] == checksum(rawshort)
                                 and x[26:28] == b"\0\0" for x in lfns))
                if not valid:
                    raise ValueError(f"Invalid LFN sequence at {entry_offset:#x}")
                encoded = b"".join(x[1:11] + x[14:26] + x[28:32] for x in reversed(lfns))
                name = encoded.decode("utf-16le").split("\0", 1)[0].rstrip("\uffff")
            lfns = []
            if attr & 8:
                volume_labels.append({"short_name": short, "directory_entry_offset": entry_offset})
                continue
            safe_component(name)
            parts = parent + (name,)
            path = "/".join(parts)
            if path.casefold() in names_seen:
                raise ValueError(f"Duplicate case-insensitive output path: {path}")
            names_seen.add(path.casefold())
            start = struct.unpack_from("<H", d, 26)[0]
            if struct.unpack_from("<H", d, 20)[0]:
                raise ValueError("Unexpected nonzero high cluster in FAT16 entry")
            size = struct.unpack_from("<I", d, 28)[0]
            is_dir = bool(attr & 16)
            if start == 0 and (size or is_dir):
                raise ValueError(f"Missing start cluster: {path}")
            cs = chain(start, path) if start else []
            if len(cs) * cluster_bytes < size:
                raise ValueError(f"File chain is shorter than file size: {path}")
            provenance = []
            remaining = size
            for c in cs:
                used = 0 if is_dir else min(remaining, cluster_bytes)
                provenance.append({"cluster": c, "carrier_offset": cluster_offset(c),
                                   "allocated_bytes": cluster_bytes, "file_bytes": used})
                remaining -= used
            item = {"path": path, "kind": "directory" if is_dir else "file",
                    "short_name": short, "attributes": attr,
                    "directory_entry_offset": entry_offset, "start_cluster": start,
                    "size": size, "clusters": cs, "chunks": provenance}
            records.append(item)
            if is_dir:
                walk([(cluster_offset(c), cluster_bytes) for c in cs], parts, depth + 1)
            else:
                raw = b"".join(read_at(cluster_offset(c), cluster_bytes) for c in cs)[:size]
                item["sha256"] = sha256(raw)

    walk([(root_offset, root_entries * 32)], ())
    files = [x for x in records if x["kind"] == "file"]
    total_file_bytes = sum(x["size"] for x in files)
    if total_file_bytes > args.max_total_bytes:
        raise ValueError(f"Extraction exceeds byte limit: {total_file_bytes}")
    orphan_clusters = [c for c in range(2, cluster_count + 2)
                       if struct.unpack_from("<H", fat, c * 2)[0] and c not in owners]
    if orphan_clusters:
        warnings.append(f"{len(orphan_clusters)} allocated/unavailable clusters are not referenced by parsed entries.")
    # All validation above happens before any output mutation.
    output.mkdir(parents=True, exist_ok=False)
    for item in records:
        destination = output.joinpath(*item["path"].split("/"))
        if not destination.resolve().is_relative_to(output):
            raise ValueError("Output path escaped the extraction root")
        if item["kind"] == "directory":
            destination.mkdir(parents=True, exist_ok=False)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            raw = b"".join(read_at(chunk["carrier_offset"], chunk["file_bytes"])
                           for chunk in item["chunks"])
            with destination.open("xb") as handle:
                handle.write(raw)
            if sha256(destination.read_bytes()) != item["sha256"]:
                raise ValueError(f"Written file hash mismatch: {item['path']}")
    if sha256(source.read_bytes()) != original_hash:
        raise ValueError("Input carrier changed during extraction")
    highlights = [x for x in files if x["path"] in {
        "JPG/Startup1.jpg", "Wav/Startup1.wav", "String/Res_Str_Eng_New.bst",
        "GammaDDE1.bin", "GammaDDE2.bin", "GammaDDE3.bin", "GammaDDE4.bin",
        "GammaLut0.bin", "Lclut0.bin", "Lclut1.bin", "Lclut2.bin"}]
    report = {
        "method": "Read-only Python FAT16 BPB/LFN/chain validation and extraction; static evidence, not runtime proof",
        "input_path": str(source), "input_size": len(carrier), "input_sha256": original_hash,
        "input_hash_unchanged_after_extraction": True, "output_path": str(output),
        "filesystem_offset": base, "oem": boot[3:11].decode("ascii", "replace"),
        "boot_volume_label": boot[43:54].decode("ascii", "replace"),
        "filesystem_type_label": boot[54:62].decode("ascii", "replace"),
        "bpb": {"bytes_per_sector": bps, "sectors_per_cluster": spc,
                "reserved_sectors": reserved, "fat_count": nfats,
                "sectors_per_fat": spf, "root_entries": root_entries,
                "total_sectors": total, "hidden_sectors": u32(28),
                "cluster_count": cluster_count},
        "fat_offset": fat_offset, "root_directory_offset": root_offset,
        "data_offset": data_offset, "logical_volume_end": logical_end,
        "logical_volume_complete_in_carrier": volume_complete,
        "logical_volume_missing_tail_bytes": max(0, logical_end - len(carrier)),
        "allocated_regular_file_extraction_complete": True,
        "meaning_of_file_completeness": "Every parsed live regular file has a validated FAT chain, all allocated clusters inside the carrier, extracted byte count equal to directory size, and a verified output SHA256. This does not establish that the entire logical volume is present or runnable.",
        "regular_file_count": len(files), "directory_count": len(records) - len(files),
        "regular_file_bytes": total_file_bytes, "referenced_cluster_count": len(owners),
        "highest_referenced_cluster": max(owners, default=None),
        "highest_referenced_cluster_end": max((cluster_offset(c) + cluster_bytes for c in owners), default=data_offset),
        "orphan_allocated_or_unavailable_clusters": orphan_clusters,
        "volume_labels": volume_labels, "warnings": warnings,
        "highlights": highlights, "entries": records,
        "processing_resource_observations": analyze_processing_resources(output),
        "limitations": ["Resource names do not prove runtime use or unlocked features.",
                        "No firmware repacking, checksum/signature repair, flash writes, or camera commands were performed."]}
    evidence.parent.mkdir(parents=True, exist_ok=True)
    with evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"files": len(files), "directories": len(records) - len(files),
                      "bytes": total_file_bytes, "input_sha256": original_hash,
                      "logical_volume_complete": volume_complete,
                      "allocated_file_extraction_complete": True,
                      "warnings": warnings, "evidence": str(evidence)}, indent=2))


if __name__ == "__main__":
    main()
