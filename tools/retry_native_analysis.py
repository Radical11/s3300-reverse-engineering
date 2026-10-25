"""Retry only explicit failed Ghidra functions, preserving original dossiers."""
import argparse
import json
from pathlib import Path
import subprocess
from native_tools import environment,digest_file
from workspace_functions import load_analysis
from native_analysis import verify_loaded

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis",type=Path)
    parser.add_argument("--address",required=True,type=lambda text:int(text,0))
    parser.add_argument("--timeout",type=int,default=120)
    args=parser.parse_args();analysis=args.analysis.resolve();address=f"{args.address:08x}"
    if not analysis.is_relative_to((ROOT/"derived").resolve()) or not 1<=args.timeout<=300:
        raise ValueError("Choose an existing local analysis and timeout1..300seconds")
    manifest,_=load_analysis(ROOT/"derived/unpacked-v1.1-indexed")
    verify_loaded(json.loads((analysis/"application/image.json").read_text()),manifest)
    original=json.loads((analysis/"application/functions"/(address+".json")).read_text())
    if original.get("decompilation_completed"):raise ValueError("This function already decompiled; no retry needed")
    env,tools=environment()
    command=[tools["paths"]["headless"],str(analysis/"project"),"s3300_application","-process","s3300-v1.1-analysis-only.elf",
             "-noanalysis","-scriptPath",str(ROOT/"tools/ghidra_retry"),"-postScript","S3300Retry.java",str(analysis/"application"),address,str(args.timeout)]
    log=analysis/("retry-"+address+".log")
    with log.open("x",encoding="utf-8") as handle:
        process=subprocess.run(command,cwd=ROOT,env=env,stdout=handle,stderr=subprocess.STDOUT,timeout=args.timeout+180)
    result=analysis/"application/retry-functions"/(address+".json")
    if process.returncode or not result.is_file():raise ValueError("Retry failed; original dossier and log retained")
    record=json.loads(result.read_text())
    provenance={"source_sha256":manifest["source_sha256"],"address":address,"timeout_seconds":args.timeout,
        "direct_ghidra":True,"native_rea_evidence":False,"target_executed":False,
        "original_dossier_sha256":digest_file(analysis/"application/functions"/(address+".json")),
        "retry_dossier_sha256":digest_file(result),"retry_script_sha256":digest_file(ROOT/"tools/ghidra_retry/S3300Retry.java"),
        "decompilation_completed":record["decompilation_completed"],"original_failure_preserved":True}
    (analysis/("retry-"+address+"-provenance.json")).write_text(json.dumps(provenance,indent=2)+"\n")
    print(json.dumps({"address":address,"decompiled":record["decompilation_completed"],"message":record["decompiler_message"],
                      "original_failure_preserved":True,"target_executed":False}))


if __name__=="__main__":main()
