"""Create a separate, bounded direct-Ghidra project for one missing writer.

Caller-seeded entry; no claim of an authenticated unwind boundary. The existing
application project, global Java and source bytes are left unchanged.
"""
import argparse
import json
from pathlib import Path
import subprocess

from map_development_contracts import ROOT, WORKSPACE, BASELINE, digest, load_analysis
from native_tools import environment, digest_file

ENTRIES=('803d73dc','803d9fb8','803d6878','803d6990','803d6b30','803d6c88',
         '803d7100','803e17bc','803e1c28','803e26b0','803e2a40','80064744')


def build(output,workspace=WORKSPACE):
    output=Path(output).resolve()
    if output.exists() or not output.is_relative_to((ROOT/'derived').resolve()):
        raise ValueError('Choose a new focused project directory under derived/')
    source=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin'
    if digest(source.read_bytes())!=BASELINE: raise ValueError('Source identity differs')
    manifest,raw=load_analysis(workspace)
    input_path=workspace/'analysis/s3300-v1.1-analysis-only.elf'
    if digest(input_path.read_bytes())!=digest(raw): raise ValueError('Analysis input differs')
    env,host=environment()
    output.mkdir(parents=True);(output/'project').mkdir()
    (output/'seeds.tsv').write_text('\n'.join(ENTRIES)+'\n')
    (output/'priorities.txt').write_text('803d73dc\n')
    command=[host['paths']['headless'],str(output/'project'),'s3300_application_writer',
        '-import',str(input_path),'-processor','MIPS:LE:32:default','-noanalysis',
        '-scriptPath',str(ROOT/'tools/ghidra'),'-preScript','S3300Seed.java',str(output/'seeds.tsv'),
        '-postScript','S3300Export.java',str(output/'application'),'-1',str(output/'priorities.txt')]
    report={'source_sha256':BASELINE,'analysis_sha256':digest(raw),'tools':host,
        'command':command,'caller_seeded_entries':list(ENTRIES),
        'entry_source':'application callback at803e28d8/803e28ec; neighboring retained entries',
        'new_writer_boundary':'Caller-seeded; not an authenticated unwind range or recovered original source',
        'scripts':{name:digest_file(ROOT/'tools/ghidra'/name) for name in ('S3300Seed.java','S3300Export.java')},
        'target_executed':False,'retained_application_project_modified':False,'timeout_seconds':180}
    (output/'input-profile.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        with (output/'headless.log').open('x',encoding='utf-8') as stream:
            result=subprocess.run(command,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=180)
        report['returncode']=result.returncode
    except subprocess.TimeoutExpired:
        report['returncode']=None;report['timed_out']=True
        (output/'provenance.json').write_text(json.dumps(report,indent=2)+'\n')
        raise ValueError('Focused analysis timed out; inputs, partial database and log preserved')
    (output/'provenance.json').write_text(json.dumps(report,indent=2)+'\n')
    if result.returncode: raise ValueError('Focused analysis failed; project and log preserved')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    args=parser.parse_args()
    report=build(args.output,args.workspace)
    print(json.dumps({'output':str(args.output),'returncode':report['returncode'],
                      'caller_seeded':True,'camera_executed':False}))


if __name__=='__main__': main()
