"""Index and inspect compiler-provided function ranges in a local workspace.

Authenticates the analysis ELF and reparses its headers and unwind records.
The index supplies boundaries, not recovered names or reconstructed C source.
"""
import argparse
from contextlib import closing
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import sys

from elftools.elf.elffile import ELFFile
from map_unwind import BASELINE, SECTION_START, SECTION_END, parse_headers, sha

ANALYSIS_HASH = "15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040"


def load_analysis(workspace):
    manifest = json.loads((workspace/"analysis/manifest.json").read_text())
    raw = (workspace/"analysis/s3300-v1.1-analysis-only.elf").read_bytes()
    if manifest["source_sha256"] != BASELINE or manifest["elf_sha256"] != ANALYSIS_HASH or sha(raw) != ANALYSIS_HASH:
        raise ValueError("Unsupported or modified analysis ELF")
    actual = ELFFile(BytesIO(raw))
    segments = list(actual.iter_segments())
    if len(segments) != len(manifest["regions"]):
        raise ValueError("Region/program-header count differs")
    for segment, region in zip(segments, manifest["regions"]):
        if (segment["p_vaddr"], segment["p_filesz"], segment["p_flags"], segment["p_offset"]) != (
                region["virtual_start"], region["size"], region["permissions"], region["analysis_elf_offset"]):
            raise ValueError("Region metadata differs from authenticated ELF")
        if sha(segment.data()) != region["sha256"]:
            raise ValueError("Region bytes differ from metadata")
    return manifest, raw


def recover_ranges(workspace):
    manifest, raw = load_analysis(workspace)
    matching = [r for r in manifest["regions"] if r["virtual_start"] <= SECTION_START and SECTION_END+4 <= r["virtual_start"]+r["size"]]
    if len(matching) != 1:
        raise ValueError("Unwind section is not uniquely mapped")
    region = matching[0]
    offset = region["analysis_elf_offset"]+SECTION_START-region["virtual_start"]
    size = SECTION_END-SECTION_START
    if raw[offset+size:offset+size+4] != bytes(4):
        raise ValueError("Unwind terminator missing")
    cies, functions = parse_headers(raw[offset:offset+size], SECTION_START, manifest["regions"])
    if len(cies) != 279 or len(functions) != 5798:
        raise ValueError("Unexpected unwind coverage")
    return functions, manifest, raw


def add_function_index(database, workspace):
    functions, _, _ = recover_ranges(workspace)
    database.execute("""
      CREATE TABLE functions(start INTEGER PRIMARY KEY, end_exclusive INTEGER NOT NULL,
        size INTEGER NOT NULL, fde_address INTEGER NOT NULL, cie_address INTEGER NOT NULL,
        source_region_start INTEGER NOT NULL, source_region_sha256 TEXT NOT NULL)
    """)
    database.execute("CREATE INDEX function_end ON functions(end_exclusive)")
    database.executemany("INSERT INTO functions VALUES (?,?,?,?,?,?,?)", [(
        f["start"], f["end_exclusive"], f["size"], f["fde_address"], f["cie_address"],
        f["source_region_start"], f["source_region_sha256"]) for f in functions])
    return {"unwind_function_ranges": len(functions), "unwind_function_range_bytes": sum(f["size"] for f in functions)}


def containing(functions, address):
    matches = [f for f in functions if f["start"] <= address < f["end_exclusive"]]
    if len(matches) != 1:
        raise ValueError("No unique compiler-provided function range at this address")
    return matches[0]


def listing(workspace, address):
    functions, manifest, raw = recover_ranges(workspace)
    function = containing(functions, address)
    if function["size"] > 256*1024:
        raise ValueError("Function exceeds bounded listing budget")
    region = next(r for r in manifest["regions"] if r["virtual_start"] == function["source_region_start"])
    offset = region["analysis_elf_offset"]+function["start"]-region["virtual_start"]
    body = raw[offset:offset+function["size"]]
    sys.path.insert(0, str(Path(__file__).resolve().parent/"vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    instructions = list(Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN).disasm(body, function["start"]))
    if sum(i.size for i in instructions) != len(body):
        raise ValueError("Function range is not completely decoded by this MIPS32 profile")
    rows = ["; Compiler-unwind range; original name and control-flow reachability unknown.",
            "; Static MIPS32 little-endian listing; branch delay slots matter. No target execution.",
            f"; FDE {function['fde_address']:#x}; range {function['start']:#x}..{function['end_exclusive']:#x}; SHA256 {sha(body)}"]
    rows.extend(f"{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}" for i in instructions)
    return "\n".join(rows)+"\n", {**function, "function_sha256": sha(body), "complete_linear_decode": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--listing", type=lambda s:int(s,0), help="Address inside a recovered function")
    parser.add_argument("--output", type=Path, help="New .asm output file for --listing")
    args = parser.parse_args()
    if args.listing is not None:
        if args.output is None or args.output.exists():
            raise ValueError("Listing needs a new --output file")
        text, evidence = listing(args.workspace, args.listing)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(text)
        print(json.dumps(evidence))
    else:
        if args.output is not None:
            raise ValueError("--output applies only to --listing")
        path = args.workspace/"research.sqlite"
        with closing(sqlite3.connect(path.resolve(strict=True).as_uri()+"?mode=rw", uri=True)) as db:
            identity = db.execute("SELECT value FROM metadata WHERE key='source_sha256'").fetchone()
            if identity != (BASELINE,):
                raise ValueError("Workspace database identity differs")
            try:
                db.execute("BEGIN")
                result = add_function_index(db, args.workspace)
                db.commit()
            except Exception:
                db.rollback()
                raise
        print(json.dumps(result))


if __name__ == "__main__":
    main()
