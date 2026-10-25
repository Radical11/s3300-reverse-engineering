"""Build a reusable static atlas of the authenticated S3300 v1.1 application.

This is independent Python/Capstone evidence following the REA investigation
workflow. Address pairs, strings and raw pointers remain candidates; this is
not an original-source reconstruction or an observed runtime call graph.
"""
import argparse
from bisect import bisect_right
from contextlib import closing
import csv
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys

from elftools.elf.elffile import ELFFile
from map_application import address_pairs
from workspace_functions import load_analysis, recover_ranges

ROOT = Path(__file__).resolve().parents[1]
SOURCE_HASH = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
SUBSYSTEMS = {
    "sensor": r"Sensor|ConfigSensor|\bCCD\b|\bCIS\b|FRAME_TIME_US",
    "capture": r"Capture|StillOn|RawTo|raw.to.yuv|Main Image|CaptureSequence",
    "image_processing": r"GAMMA|LCLUT|\bIPP\b|\bIPU\b|Demosaic|Denois|ColorEffect|Chroma|WhiteBalance|AWB_",
    "jpeg_video": r"JPEG|\bJPG\b|\bMJPG\b|MPEG|\bAVI\b|Movie|VideoRecord|Compression",
    "display_preview": r"\bDLCD\b|\bLCD\b|\bOSD\b|Display|Preview|Viewfinder|LiveView",
    "ui_controls": r"MenuHandler|Buttons|Ui/|UI_|ViewMenu|Touch|KeyEvent",
    "settings": r"Setting|UserStore|UserData|EEPROM|NVRAM|Nvm|Factory|Calibration",
    "memory": r"\bDRAM\b|\bSDRAM\b|\bSRAM\b|Heap|Malloc|MemAlloc|MemPool|MemoryPool|dramsize",
    "rtos": r"ThreadX|FileX|\b_tx_|Semaphore|Mutex|MessageQueue|ThreadCreate|TaskCreate|Watchdog",
    "storage": r"\bNAND\b|\bNOR\b|FileSystem|FileX|\bFAT\b|SDCard|SD card|CardServer|Disk|Storage|DCIM",
    "usb": r"\bUSB\b|\bPTP\b|\bMTP\b|Ptp|GetMem|SetMem|VendorRequest",
    "power_clock": r"Battery|PowerOff|PowerOn|PowerSave|Charging|\bClock\b|\bCGU\b|PLL|Voltage",
    "lens_flash": r"Lens|Focus|Strobe|FlashCharge|ZoomMotor|Shutter|Vibration",
    "update_recovery": r"Firmware|BurnHash|BurnMain|Upgrade|UpdateCheck|Nanddn|Recovery|BootLoader",
    "debug_profiling": r"DebugConsole|Monitor|UART|\bJTAG\b|CpuLoad|Performance|Profil|Assert|\bTrace\b",
    "peripherals": r"\bGPIO\b|\bI2C\b|\bSPI\b|\bDMA\b|\bADC\b|\bPWM\b|Interrupt",
    "resources_audio": r"Resource|Res_Str_|Startup|\.wav|\.zbm|\.bst|Audio|Sound|VoiceMemo",
}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def classify(text):
    return [name for name, pattern in SUBSYSTEMS.items() if re.search(pattern, text, re.I)]


def owner(functions, starts, address):
    index = bisect_right(starts, address) - 1
    if index >= 0 and address < functions[index]["end_exclusive"]:
        return functions[index]["start"]
    return None


def transfer(word, pc):
    """Decode only direct J/JAL/BAL and unresolved register calls/jumps."""
    opcode = word >> 26
    if opcode in (2, 3):
        return ("call" if opcode == 3 else "jump", ((pc + 4) & 0xf0000000) | ((word & 0x03ffffff) << 2))
    if opcode == 1 and (word >> 21) & 31 == 0 and (word >> 16) & 31 == 17:
        signed = word & 65535
        if signed & 32768:
            signed -= 65536
        return "call", (pc + 4 + signed * 4) & 0xffffffff
    if opcode == 0 and word & 63 == 9:
        return "indirect_call", None
    if opcode == 0 and word & 63 == 8 and (word >> 21) & 31 != 31:
        return "indirect_jump", None
    return None


def build(workspace, output):
    from unpack_workspace import verify_partition
    verify_partition(workspace)
    manifest = json.loads((workspace / "unpacked.json").read_text(encoding="utf-8"))
    # verify_partition already checked these paths, bounds, coverage and digest.
    source = b"".join((workspace / part["file"]).read_bytes() for part in manifest["carrier_parts"])
    if sha(source) != SOURCE_HASH:
        raise ValueError("Source digest differs")
    analysis, raw = load_analysis(workspace)
    functions, _, _ = recover_ranges(workspace)
    functions.sort(key=lambda f: f["start"])
    starts = [f["start"] for f in functions]
    function_starts = set(starts)
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(ROOT / "tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    disassembler = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    database = output / "atlas.sqlite"
    db = sqlite3.connect(database)
    try:
        db.executescript("""
          CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE regions(name TEXT PRIMARY KEY,start INTEGER,size INTEGER,permissions INTEGER,sha256 TEXT);
          CREATE TABLE functions(start INTEGER PRIMARY KEY,end_exclusive INTEGER,size INTEGER,
            sha256 TEXT,decoded_bytes INTEGER,complete_linear_decode INTEGER,assembly TEXT);
          CREATE TABLE strings(address INTEGER PRIMARY KEY,region TEXT,text TEXT,categories TEXT);
          CREATE TABLE transfers(site INTEGER PRIMARY KEY,source_function INTEGER,kind TEXT,
            target INTEGER,target_function INTEGER,instruction_hex TEXT);
          CREATE TABLE address_refs(site INTEGER,lui_site INTEGER,source_function INTEGER,target INTEGER,
            span_instructions INTEGER,PRIMARY KEY(site,lui_site,target));
          CREATE TABLE pointer_words(site INTEGER PRIMARY KEY,target INTEGER,target_kind TEXT);
          CREATE TABLE associations(function_start INTEGER,subsystem TEXT,string_address INTEGER,
            reference_site INTEGER,PRIMARY KEY(function_start,subsystem,string_address,reference_site));
          CREATE TABLE artifacts(carrier_offset INTEGER PRIMARY KEY,entry INTEGER,flags INTEGER,machine TEXT);
          CREATE TABLE symbols(artifact_offset INTEGER,name TEXT,address INTEGER,size INTEGER,type TEXT);
          CREATE INDEX transfers_target ON transfers(target);
          CREATE INDEX transfers_source ON transfers(source_function);
          CREATE INDEX refs_target ON address_refs(target);
          CREATE INDEX associations_subsystem ON associations(subsystem);
          CREATE INDEX symbols_address ON symbols(artifact_offset,address);
        """)
        db.executemany("INSERT INTO metadata VALUES (?,?)", [
            ("source_sha256", SOURCE_HASH), ("analysis_sha256", sha(raw)),
            ("evidence_type", "independent static Python/Capstone; not native REA Evidence"),
            ("mapping_scope", "known unwind ranges plus mixed-region strings/address/pointer candidates")])
        regions = analysis["regions"]
        strings = {}
        for region in regions:
            start, offset, size = region["virtual_start"], region["analysis_elf_offset"], region["size"]
            db.execute("INSERT INTO regions VALUES (?,?,?,?,?)", (region["name"], start, size, region["permissions"], region["sha256"]))
            for match in re.finditer(rb"[ -~]{5,}", raw[offset:offset + size]):
                address, text = start + match.start(), match.group().decode("ascii")
                categories = classify(text)
                strings[address] = categories
                db.execute("INSERT INTO strings VALUES (?,?,?,?)", (address, region["name"], text, json.dumps(categories)))
        targets = set(strings)
        for function in functions:
            region = next(r for r in regions if r["virtual_start"] == function["source_region_start"])
            offset = region["analysis_elf_offset"] + function["start"] - region["virtual_start"]
            body = raw[offset:offset + function["size"]]
            instructions = list(disassembler.disasm_lite(body, function["start"]))
            decoded_bytes = sum(instruction[1] for instruction in instructions)
            assembly = "\n".join(f"{pc:08x}: {mnemonic:10} {operands}" for pc, _, mnemonic, operands in instructions)
            db.execute("INSERT INTO functions VALUES (?,?,?,?,?,?,?)", (function["start"], function["end_exclusive"],
                       function["size"], sha(body), decoded_bytes, decoded_bytes == len(body), assembly))
            # Instruction-encoding scan is confined to compiler-provided ranges.
            for offset in range(0, len(body) - 3, 4):
                word, pc = struct.unpack_from("<I", body, offset)[0], function["start"] + offset
                edge = transfer(word, pc)
                if edge:
                    kind, target = edge
                    db.execute("INSERT INTO transfers VALUES (?,?,?,?,?,?)", (pc, function["start"], kind,
                               target, owner(functions, starts, target) if target is not None else None, f"{word:08x}"))
        for region in regions:
            base, offset, size = region["virtual_start"], region["analysis_elf_offset"], region["size"]
            body = raw[offset:offset + size]
            if region["permissions"] & 1:
                for reference in address_pairs(base, body, targets):
                    site, target = reference["low_address"], reference["target"]
                    containing = owner(functions, starts, site)
                    db.execute("INSERT OR IGNORE INTO address_refs VALUES (?,?,?,?,?)", (site, reference["lui_address"],
                               containing, target, reference["span_instructions"]))
                    if containing is not None:
                        for category in strings[target]:
                            db.execute("INSERT OR IGNORE INTO associations VALUES (?,?,?,?)", (containing, category, target, site))
            for index, (value,) in enumerate(struct.iter_unpack("<I", body[:len(body)//4*4])):
                if value in targets or value in function_starts:
                    db.execute("INSERT INTO pointer_words VALUES (?,?,?)", (base + index * 4, value,
                               "string_candidate" if value in targets else "function_entry_candidate"))
        for carrier_offset in (0x200, 0x1006c0, 0x1026c0, 0x2202c0, 0x3bd9a8, 0x5c2b78):
            elf = ELFFile(BytesIO(source[carrier_offset:]))
            db.execute("INSERT INTO artifacts VALUES (?,?,?,?)", (carrier_offset, elf.header["e_entry"], elf.header["e_flags"], elf.header["e_machine"]))
            for section in elf.iter_sections():
                if section["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    continue
                for symbol in section.iter_symbols():
                    db.execute("INSERT INTO symbols VALUES (?,?,?,?,?)", (carrier_offset, symbol.name,
                               symbol["st_value"], symbol["st_size"], symbol["st_info"]["type"]))
        db.commit()
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Atlas database failed integrity check")
        counts = {table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in (
            "regions", "functions", "strings", "transfers", "address_refs", "pointer_words", "associations", "artifacts", "symbols")}
        counts["fully_decoded_function_listings"] = db.execute("SELECT count(*) FROM functions WHERE complete_linear_decode=1").fetchone()[0]
        counts["function_bytes"] = sum(f["size"] for f in functions)
        counts["direct_calls"] = db.execute("SELECT count(*) FROM transfers WHERE kind='call'").fetchone()[0]
        counts["unresolved_register_calls"] = db.execute("SELECT count(*) FROM transfers WHERE kind='indirect_call'").fetchone()[0]
        subsystem_counts = {name: {"string_candidates": db.execute("SELECT count(*) FROM strings WHERE categories LIKE ?", ('%"'+name+'"%',)).fetchone()[0],
                                  "associated_function_ranges": db.execute("SELECT count(DISTINCT function_start) FROM associations WHERE subsystem=?", (name,)).fetchone()[0]}
                            for name in SUBSYSTEMS}
        for table, order in (("functions", "start"), ("transfers", "site"), ("address_refs", "site")):
            columns = "start,end_exclusive,size,sha256,decoded_bytes,complete_linear_decode" if table == "functions" else "*"
            result = db.execute(f"SELECT {columns} FROM {table} ORDER BY {order}")
            with (output / f"{table}.csv").open("x", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow([item[0] for item in result.description])
                writer.writerows(result)
    finally:
        db.close()
    report = {"schema_version": 1, "source_sha256": SOURCE_HASH, "analysis_sha256": sha(raw),
              "database_sha256": sha(database.read_bytes()), "counts": counts, "subsystems": subsystem_counts,
              "evidence_type": "Independent source-bound Python/Capstone static analysis following REA skill",
              "limitations": [
                  "Known function boundaries come from compiler unwind records, not complete function discovery.",
                  "Linear disassembly is not CFG or runtime reachability; incomplete decode is explicitly counted.",
                  "Raw transfer encodings inside ranges are static candidates; register calls remain unresolved.",
                  "String associations derive from bounded LUI/ADDIU/ORI candidates with partial clobber checks, not semantic proof.",
                  "Mixed-region pointer words and printable byte sequences may be incidental data; no automatic API names assigned.",
                  "Original symbols retain artifact scope; updater names are not assigned to overlapping application addresses.",
                  "No original C source, full hardware specification, target execution or recovery demonstration is supplied."]}
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# S3300 static firmware atlas", "", "All files in this directory contain local firmware-derived analysis.",
             "Use atlas.sqlite for function listings, references and subsystem leads. CSV exports retain addresses as decimal integers.",
             "", "## Coverage", "", *[f"- {name}: {value}" for name, value in counts.items()], "",
             "## Interpretation limits", "", *[f"- {limitation}" for limitation in report["limitations"]], ""]
    (output / "README.md").write_text("\n".join(lines), encoding="utf-8")
    return report


def query(database, *, address=None, term=None, subsystem=None, limit=20, include_assembly=False):
    if not 1 <= limit <= 1000:
        raise ValueError("Limit must be 1..1000")
    with closing(sqlite3.connect(database.resolve(strict=True).as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        if db.execute("SELECT value FROM metadata WHERE key='source_sha256'").fetchone()[0] != SOURCE_HASH:
            raise ValueError("Atlas source identity differs")
        if address is not None:
            function = db.execute("SELECT * FROM functions WHERE start<=? AND end_exclusive>?", (address, address)).fetchone()
            start = function["start"] if function else address
            function_info = dict(function) if function else None
            if function_info and not include_assembly:
                del function_info["assembly"]
            return {"function": function_info,
                    "incoming_transfers": [dict(r) for r in db.execute("SELECT * FROM transfers WHERE target=? OR target_function=? LIMIT ?", (address, start, limit))],
                    "outgoing_transfers": [dict(r) for r in db.execute("SELECT * FROM transfers WHERE source_function=? LIMIT ?", (start, limit))],
                    "diagnostic_associations": [dict(r) for r in db.execute("SELECT a.*,s.text FROM associations a JOIN strings s ON s.address=a.string_address WHERE function_start=? LIMIT ?", (start, limit))],
                    "address_references": [dict(r) for r in db.execute("SELECT * FROM address_refs WHERE target=? LIMIT ?", (address, limit))],
                    "pointer_candidates": [dict(r) for r in db.execute("SELECT * FROM pointer_words WHERE target=? LIMIT ?", (address, limit))]}
        if subsystem is not None:
            if subsystem not in SUBSYSTEMS:
                raise ValueError("Unknown subsystem; choose " + ", ".join(SUBSYSTEMS))
            return {"subsystem": subsystem, "associations": [dict(r) for r in db.execute(
                "SELECT a.*,s.text FROM associations a JOIN strings s ON s.address=a.string_address WHERE subsystem=? ORDER BY function_start LIMIT ?", (subsystem, limit))]}
        pattern = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return {"string_candidates": [dict(r) for r in db.execute("SELECT * FROM strings WHERE text LIKE ? ESCAPE '\\' LIMIT ?", (pattern, limit))],
                "artifact_scoped_symbols": [dict(r) for r in db.execute("SELECT * FROM symbols WHERE name LIKE ? ESCAPE '\\' LIMIT ?", (pattern, limit))]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory under derived/")
    parser.add_argument("--workspace", type=Path, default=ROOT / "derived/unpacked-v1.1-indexed")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "derived").resolve()):
        raise ValueError("Firmware-derived atlas must stay under ignored derived/")
    report = build(args.workspace.resolve(), output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
