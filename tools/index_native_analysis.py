"""Index retained Ghidra dossiers with byte checks against the analysis ELF."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3

from workspace_functions import load_analysis
from map_unwind import BASELINE

ROOT=Path(__file__).resolve().parents[1]


def build(native, output, workspace):
    native=native.resolve();output=output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/"derived").resolve()):
        raise ValueError("Native index must be a new directory under derived/")
    profile=json.loads((native/"profile.json").read_text())
    manifest,raw=load_analysis(workspace)
    if profile["analysis_sha256"]!=hashlib.sha256(raw).hexdigest():
        raise ValueError("Native analysis source profile differs")
    summary=json.loads((native/"application/verified-summary.json").read_text())
    if not summary["all_discovered_functions_exported"] or not summary["source_unchanged"]:
        raise ValueError("Native application export incomplete or changed")
    output.mkdir(parents=True)
    database=output/"native.sqlite"
    checked=0;unbacked=0;failed=0;initial_failed=0;recovered=0;failure_entries=[]
    with closing(sqlite3.connect(database)) as db:
        db.executescript("""
          CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
          CREATE TABLE functions(address INTEGER PRIMARY KEY,name TEXT,pseudocode TEXT,decompiled INTEGER,
            warning TEXT,signature TEXT,ranges_json TEXT,source_file TEXT);
          CREATE TABLE references_from(site INTEGER,target TEXT,type TEXT,function_address INTEGER);
          CREATE TABLE edges(source INTEGER,target TEXT,type TEXT);
          CREATE TABLE indirect_transfers(site INTEGER,function_address INTEGER,instruction TEXT,resolved_targets_json TEXT);
          CREATE INDEX references_target ON references_from(target);
        """)
        db.executemany("INSERT INTO metadata VALUES (?,?)",[("source_sha256",profile["source_sha256"]),
            ("analysis_sha256",profile["analysis_sha256"]),("evidence_class","direct Ghidra static analysis; inferred semantics")])
        dossiers=sorted((native/"application/functions").glob("*.json"))
        if len(dossiers)!=summary["discovered_functions"]:raise ValueError("Native dossier set incomplete")
        for path in dossiers:
            row=json.loads(path.read_text())
            initial_failed+=not row.get("decompilation_completed",False)
            retried=native/"application/retry-functions"/path.name
            if retried.is_file():
                replacement=json.loads(retried.read_text())
                if replacement.get("initial_decompilation")!=row:
                    raise ValueError("Retry dossier is not bound to the exact retained initial failure")
                if replacement.get("decompilation_completed"):
                    row=replacement;recovered+=1
            address=int(row["address"],16)
            for instruction in row["instructions"]:
                site=int(instruction["address"],16);body=bytes.fromhex(instruction["bytes"])
                regions=[r for r in manifest["regions"] if r["virtual_start"]<=site and site+len(body)<=r["virtual_start"]+r["size"]]
                if len(regions)!=1:
                    unbacked+=1;continue
                region=regions[0];offset=region["analysis_elf_offset"]+site-region["virtual_start"]
                if raw[offset:offset+len(body)]!=body:raise ValueError("Ghidra instruction bytes differ from authenticated ELF")
                checked+=1
                operation=instruction["text"].split(None,1)
                if operation and operation[0].lower() in ("jalr","jr","jalrc","jrc") and not (len(operation)>1 and operation[1].strip() in ("ra","$ra")):
                    targets=[r["to"] for r in row["references"] if r["from"]==instruction["address"] and any(t in r["type"].upper() for t in ("CALL","JUMP"))]
                    db.execute("INSERT INTO indirect_transfers VALUES (?,?,?,?)",(site,address,instruction["text"],json.dumps(targets)))
            success=bool(row.get("decompilation_completed"));failed+=not success
            if not success:failure_entries.append(row["address"])
            db.execute("INSERT INTO functions VALUES (?,?,?,?,?,?,?,?)",(address,row["name"],row.get("pseudocode"),success,
                row.get("decompiler_message"),row.get("signature_inferred"),json.dumps(row["ranges"]),path.relative_to(ROOT).as_posix()))
            db.executemany("INSERT INTO references_from VALUES (?,?,?,?)",[(int(r["from"],16),r["to"],r["type"],address)
                for r in row["references"] if all(c in "0123456789abcdefABCDEF" for c in r["from"])])
            db.executemany("INSERT INTO edges VALUES (?,?,?)",[(address,target,"resolved_static_call") for target in row["callees"]])
        db.commit()
        if db.execute("PRAGMA integrity_check").fetchone()[0]!="ok":raise ValueError("Native index integrity failed")
        counts={table:db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in ("functions","references_from","edges","indirect_transfers")}
    report={"schema_version":1,"source_sha256":profile["source_sha256"],"analysis_sha256":profile["analysis_sha256"],
        "database_sha256":hashlib.sha256(database.read_bytes()).hexdigest(),"counts":counts,
        "instructions_byte_checked":checked,"instructions_without_original_file_backing":unbacked,
        "decompilation_failures":failed,"initial_decompilation_failures":initial_failed,
        "focused_retry_successes":recovered,"target_executed":False,
        "decompiler_failure_entries":failure_entries,
        "evidence_class":"direct Ghidra analysis indexed after independent byte comparison",
        "limitations":["Auto-discovered functions/types may be wrong; counts are not semantic completeness.",
                      "Byte equality verifies import, not inferred signatures, indirect targets or runtime behavior."]}
    (output/"manifest.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


def query(database,*,address=None,term=None,limit=20):
    if not 1<=limit<=1000:raise ValueError("Limit must be1..1000")
    with closing(sqlite3.connect(database.resolve(strict=True).as_uri()+"?mode=ro",uri=True)) as db:
        db.row_factory=sqlite3.Row;db.execute("PRAGMA query_only=ON")
        identity=db.execute("SELECT value FROM metadata WHERE key='source_sha256'").fetchone()
        if not identity or identity[0]!=BASELINE:raise ValueError("Native index source identity differs")
        has_indirect=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='indirect_transfers'").fetchone()
        if address is not None:
            target=f"{address:08x}"
            row=db.execute("SELECT * FROM functions WHERE address=?",(address,)).fetchone()
            return {"function":dict(row) if row else None,
                "incoming_calls":[dict(r) for r in db.execute("SELECT * FROM edges WHERE target=? LIMIT ?",(target,limit))],
                "indirect_transfers":[dict(r) for r in db.execute("SELECT * FROM indirect_transfers WHERE function_address=? LIMIT ?",(address,limit))] if has_indirect else [],
                "data_or_flow_references":[dict(r) for r in db.execute("SELECT * FROM references_from WHERE target=? LIMIT ?",(target,limit))]}
        if not term:raise ValueError("Supply a search term or function entry")
        pattern="%"+term.replace("\\","\\\\").replace("%","\\%").replace("_","\\_")+"%"
        return {"functions":[dict(r) for r in db.execute("SELECT address,name,decompiled,warning,signature,source_file FROM functions WHERE name LIKE ? ESCAPE '\\' OR pseudocode LIKE ? ESCAPE '\\' LIMIT ?",(pattern,pattern,limit))]}
