"""Retained, resumable direct Ghidra analysis of authenticated local firmware."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from io import BytesIO
from elftools.elf.elffile import ELFFile
from native_tools import CACHE, environment, digest_file
from workspace_functions import recover_ranges

ROOT = Path(__file__).resolve().parents[1]
PRIORITIES = (0x80008f80,0x80009644,0x801fbc8c,0x801fbb3c,0x80192e04,0x802e57a8,
              0x80205918,0x80234d4c,0x8023db0c,0x80737664,0x80796108,0x8079de34,
              0x805810c0,0x8003c3ac,0x80025198,0x806ac078,0x806af434)


def profile(workspace, tools):
    functions, manifest, raw = recover_ranges(workspace)
    scripts = {p.name: digest_file(p) for p in (ROOT / "tools/ghidra").glob("*.java")}
    return {"schema_version":1,"workflow_version":2,"analysis_sha256":hashlib.sha256(raw).hexdigest(),
            "source_sha256":manifest["source_sha256"],"scripts":scripts,"tools":tools,
            "runner_sha256":digest_file(Path(__file__)),
            "caller_seed_count":len(functions),"target_executed":False,
            "evidence_class":"direct Ghidra static analysis, separate from REA Evidence"},functions,manifest


def verify_loaded(image, manifest):
    if not image["language"].startswith("MIPS:LE:32"):
        raise ValueError("Ghidra imported application with an unexpected language")
    # ELF section overlays (for example .shstrtab::00000000) are separate
    # Ghidra spaces, not addresses in the application's default RAM space.
    blocks=[block for block in image["memory"] if all(c in "0123456789abcdefABCDEF" for c in block["start"])]
    for region in manifest["regions"]:
        matches=[block for block in blocks if int(block["start"],16)==region["virtual_start"] and block["size"]==region["size"]]
        if len(matches)!=1 or matches[0].get("sha256")!=region["sha256"]:
            raise ValueError(f"Imported memory differs: {region['name']}")
    return True


def compatible_profile(previous, current):
    # The workflow version commits import behavior; runner hashes retain the
    # verifier implementation provenance without forcing another decompilation
    # after a verification-only fix. Script/tool/source changes remain fatal.
    return {k:v for k,v in previous.items() if k!="runner_sha256"} == {k:v for k,v in current.items() if k!="runner_sha256"}


def complete_export(exported):
    summary=exported/"export-summary.json"
    if not summary.is_file():return False
    data=json.loads(summary.read_text())
    return data["processed_this_run"]+data["reused"]==data["inventory"] and len(list((exported/"functions").glob("*.json")))==data["inventory"]


def analyze(output, workspace, *, resume=False, limit=-1, selected=None, cache=CACHE):
    output=output.resolve();workspace=workspace.resolve()
    if not output.is_relative_to((ROOT/"derived").resolve()):
        raise ValueError("Native vendor-derived analysis must stay under derived/")
    env,tools=environment(cache)
    expected,functions,manifest=profile(workspace,tools)
    identity=output/"profile.json"
    if output.exists():
        if not resume or not identity.is_file() or not compatible_profile(json.loads(identity.read_text()),expected):
            raise ValueError("Existing analysis needs --resume and the exact source/tools/scripts profile")
    else:
        output.mkdir(parents=True)
        identity.write_text(json.dumps(expected,indent=2)+"\n")
    (output/"project").mkdir(exist_ok=True)
    priority_file=output/"priority.txt"
    priority_file.write_text("".join(f"{address:08x}\n" for address in PRIORITIES))
    seeds=output/"seeds.tsv"
    seeds.write_text("".join(f"{f['start']:x}\t{f['end_exclusive']:x}\n" for f in functions))
    inputs=[("application",workspace/"analysis/s3300-v1.1-analysis-only.elf")]
    inputs.extend((path.stem,path) for path in sorted((workspace/"elf-original").glob("*.elf")))
    if selected:
        inputs=[item for item in inputs if item[0] in selected]
        if len(inputs)!=len(set(selected)):raise ValueError("Unknown analysis image selection")
    results=[]
    for name,path in inputs:
        exported=output/name;exported.mkdir(exist_ok=True)
        project_name="s3300_"+name.replace("-","_")
        exists=(output/"project"/(project_name+".gpr")).is_file()
        command=[tools["paths"]["headless"],str(output/"project"),project_name,
                 "-scriptPath",str(ROOT/"tools/ghidra"),"-max-cpu","2"]
        if exists:
            command.extend(["-process",path.name,"-noanalysis"])
        else:
            command.extend(["-import",str(path),"-overwrite","-analysisTimeoutPerFile","900"])
            if name in ("image-002202c0", "image-003bd9a8", "image-005c2b78"):
                # These file-backed representations contain packed payloads, not
                # executable instructions. Their decoded application is separate.
                command.append("-noanalysis")
            if name=="application":command.extend(["-preScript","S3300Seed.java",str(seeds)])
        command.extend(["-postScript","S3300Export.java",str(exported),str(limit),str(priority_file)])
        returncode=0
        if not (exists and complete_export(exported)):
            with (output/(name+".log")).open("a",encoding="utf-8") as log:
                completed=subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=14400)
                returncode=completed.returncode
        if returncode or not (exported/"image.json").exists():
            raise ValueError(f"Native import/export failed for {name}; inspect {output/(name+'.log')}")
        image=json.loads((exported/"image.json").read_text())
        if name=="application":verify_loaded(image,manifest)
        elif image["executable_sha256"].lower()!=digest_file(path):
            raise ValueError("Original executable identity differs after Ghidra import")
        dossiers=list((exported/"functions").glob("*.json"))
        failed=sum(not json.loads(p.read_text()).get("decompilation_completed",False) for p in dossiers)
        summary={"image":name,"input_sha256":digest_file(path),"language":image["language"],
                 "representation":"packed carrier ELF; inventory only" if name in ("image-002202c0", "image-003bd9a8", "image-005c2b78") else "unpacked executable/analysis image",
                 "discovered_functions":image["function_inventory_count"],"exported_functions":len(dossiers),
                 "decompilation_failures":failed,"all_discovered_functions_exported":len(dossiers)==image["function_inventory_count"],
                 "source_unchanged":digest_file(path)==image["executable_sha256"].lower(),"target_executed":False}
        if not summary["source_unchanged"]:
            raise ValueError("Input changed after native import; preserving project without validating the run")
        results.append(summary)
        (exported/"verified-summary.json").write_text(json.dumps(summary,indent=2)+"\n")
        print(json.dumps(summary),flush=True)
    return {"profile":expected,"images":results,"native_rea_evidence":False,"retained_project":str(output/"project")}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output",type=Path)
    parser.add_argument("--workspace",type=Path,default=ROOT/"derived/unpacked-v1.1-indexed")
    parser.add_argument("--cache",type=Path,default=CACHE)
    parser.add_argument("--resume",action="store_true")
    parser.add_argument("--decompile-limit",type=int,default=-1)
    parser.add_argument("--image",action="append")
    args=parser.parse_args()
    result=analyze(args.output,args.workspace,resume=args.resume,limit=args.decompile_limit,selected=args.image,cache=args.cache)
    (args.output/"verified-run.json").write_text(json.dumps(result,indent=2)+"\n")
    images=[json.loads(path.read_text()) for path in sorted(args.output.glob("*/verified-summary.json"))]
    (ROOT/"evidence/native-analysis.json").write_text(json.dumps({
        "schema_version":1,"source_sha256":result["profile"]["source_sha256"],
        "analysis_sha256":result["profile"]["analysis_sha256"],
        "evidence_class":"direct Ghidra static observations; not native REA Evidence",
        "output":args.output.resolve().relative_to(ROOT).as_posix(),"images":images,
        "target_executed":False,"original_inputs_changed":False,
        "limits":"Decompiler pseudocode and inferred types are not original C or a proved camera ABI"
    },indent=2)+"\n")


if __name__=="__main__":main()
