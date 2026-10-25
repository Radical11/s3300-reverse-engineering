"""Bound USB mode entry callers and their configuration dependencies offline."""
import argparse
import json
from pathlib import Path
import sqlite3
import struct

from map_development_contracts import (ROOT,WORKSPACE,BASELINE,AddressMap,load_analysis,
    digest,Cs,CS_ARCH_MIPS,CS_MODE_MIPS32,CS_MODE_LITTLE_ENDIAN,checked_table)
from map_recovery_transport import check_dossiers

CALLS={0x8059ba8c:(0x8059b99c,5),0x806384e4:(0x80638378,7),
    0x80639a74:(0x806398d8,7),0x80639aa4:(0x806398d8,7),
    0x806a87dc:(0x806a87ac,0),0x806f9148:(0x806f8e60,0),
    0x806f9670:(0x806f93fc,0),0x80740050:(0x8073f858,0)}
FUNCTIONS=tuple(sorted({row[0]for row in CALLS.values()}|{
    0x80771c68,0x8078bd48,0x8079c590,0x80741cd8,0x8058af54,0x806a8a2c,
    0x807721f8,0x80772bfc,0x8078dc04,0x8078dc8c,0x8068be9c,0x80741e1c,0x80741d84}))
ASSERTIONS={0x80771c74:('andi','$a0, $a0, 0xff'),
    0x8079c59c:('andi','$a0, $a0, 0xff'),
    0x8078bd48:('andi','$a0, $a0, 0xff'),
    0x8078bd50:('move','$a2, $a0'),
    0x8078bd54:('lui','$a1, 0x10'),
    0x8078bd58:('addiu','$a0, $zero, 2'),
    0x8078bd60:('jal','0x801f5614'),
    0x80741cdc:('lhu','$a0, -0x76($a1)'),
    0x80741ce0:('andi','$v1, $a0, 0xf'),
    0x80741ce4:('xori','$v0, $v1, 8'),
    0x8058c098:('addiu','$a2, $zero, 6'),
    0x8058c09c:('beq','$a1, $a2, 0x8058c0e8'),
    0x8058c0a0:('addiu','$a0, $t3, -0x76'),
    0x8058c108:('sh','$v0, ($a0)'),
    0x8058c10c:('jal','0x80741e1c'),
    0x8058c11c:('jal','0x8000994c'),
    0x806a8b3c:('jal','0x8058af54'),
    0x806a8b40:('andi','$a0, $s4, 0xff')}


def jal_target(word,pc):
    if not all(isinstance(x,int)and 0<=x<=0xffffffff for x in (word,pc)):
        raise ValueError('Expected unsigned32 instruction and PC')
    if pc&3:raise ValueError('Expected aligned MIPS32 PC')
    return (((pc+4)&0xf0000000)|((word&0x3ffffff)<<2)) if word>>26==3 else None


def a0_delay_constant(word):
    """Only the exact constant-producing delay slot forms observed in this map."""
    if word==0x00002021:return 0 # addu a0,zero,zero
    if word>>16==0x2404:
        value=word&0xffff
        return value if value<0x8000 else value-0x10000
    raise ValueError('Delay slot is not a reviewed a0 constant producer')


def test_mode_flag(word):
    """Model predicate80741cd8, without reading or changing a camera setting."""
    if not isinstance(word,int)or not 0<=word<=0xffff:raise ValueError('Expected observed u16')
    return (word&15)!=8


def direct_sites(manifest,raw,target):
    sites=[]
    for region in manifest['regions']:
        body=raw[region['analysis_elf_offset']:region['analysis_elf_offset']+region['size']]
        for offset in range(0,len(body)-3,4):
            pc=region['virtual_start']+offset
            if jal_target(struct.unpack_from('<I',body,offset)[0],pc)==target:sites.append(pc)
    return sorted(sites)


def build_report(workspace,source,native,index):
    if digest(source.read_bytes())!=BASELINE:raise ValueError('Source identity differs')
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    assertions=[]
    for address,expected in ASSERTIONS.items():
        items=list(decoder.disasm(mapping.read(address,4),address))
        if len(items)!=1 or(items[0].mnemonic,items[0].op_str)!=expected:
            raise ValueError(f'Instruction differs at{address:#x}')
        assertions.append({'address':address,'sha256':digest(mapping.read(address,4))})
    connection=sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        references={}
        for target,expected in ((0x80771c68,sorted(CALLS)),(0x8078bd48,[0x80771c70,0x8079c598])):
            rows=connection.execute('select site,type,function_address from references_from where target=? order by site',(f'{target:08x}',)).fetchall()
            if [row[0]for row in rows]!=expected or direct_sites(manifest,raw,target)!=expected:
                raise ValueError('Indexed/direct raw call coverage differs; review new entry paths')
            references[f'{target:08x}']=[{'site':s,'type':t,'function':f}for s,t,f in rows]
    finally:connection.close()
    calls=[]
    for site,(caller,mode) in CALLS.items():
        if a0_delay_constant(struct.unpack('<I',mapping.read(site+4,4))[0])!=mode:
            raise ValueError('Delay-slot mode differs')
        if not any(row['site']==site and row['function']==caller for row in references['80771c68']):
            raise ValueError('Caller attribution differs')
        calls.append({'site':site,'function':caller,'mode':mode,'constant_in_delay_slot':True})
    table=checked_table(mapping,0x80899560,[0x8079c590,0])
    if mapping.read(0x8066b550,16)!=b'C:\\ColdData.bin\0':raise ValueError('Calibration path differs')
    native_proof=check_dossiers(native,mapping,digest(raw),FUNCTIONS)
    return {'schema_version':1,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
      'method':'Authenticated independent Capstone/raw-JAL checks and direct Ghidra dossiers, not REA Evidence',
      'camera_commands_issued':False,'target_executed':False,'instruction_checks':assertions,
      'native_corroboration':native_proof,'native_index_sha256':digest(index.read_bytes()),
      'direct_call_references':references,'wrapper_calls':calls,'debug_mode_record':table,
      'search_boundary':'All aligned words in eight authenticated decoded regions plus all indexed references to80771c68/8078bd48; excludes unresolved indirect transfers and other binaries',
      'contracts':[
       {'id':'usb.entry_direct_calls','status':'static-contract-verified',
        'wrapper':0x80771c68,'modes_observed':[0,5,7],'mode6_direct_calls_found':0,
        'limits':'No direct constant6 call in this bounded search; indirect activation is unresolved'},
       {'id':'usb.entry_application_mode0','status':'partial',
        'paths':[
          {'caller':0x806a87ac,'role':'internal Pure HCE initialization path; eventd181 reaches this routine'},
          {'caller':0x806f8e60,'role':'startup checks runtime80819296/808921ef; mode0 branch requires low nibble8000ff8a!=8 plus other guards'},
          {'caller':0x806f93fc,'role':'internal eventd112 START_ENTER_TEST_Mode path'},
          {'caller':0x8073f858,'role':'eventd001/12a branch uses mode0 when808921ef is zero'}],
        'predicate':{'entry':0x80741cd8,'word':0x8000ff8a,'rule':'returns(low_nibble!=8); startup808921ef=(return==0)'},
        'mode0_registration':'807721f8 stores slot0, creates UsbAgent via8078dc04;80772bfc uses8078dc8c debug-class interface descriptor with sub8068be9c returning0',
        'limits':['Application-state and event lifecycle required','No verified ordinary menu or physical-control entry','Mode0 and mode6 are distinct descriptor compositions','Neither path establishes boot-failure recovery']},
       {'id':'usb.entry_mode_config_mutation','status':'partial',
        'writer':0x8058af54,'branch':'UIDebugMsg case32/sub6 selects8000ff8a among calibration words',
        'effect':'Reads0x400-byte C:\\ColdData.bin; changes low nibble to4/8; writes file; updates settings/checksum state',
        'internal_entry':'806a8a2c dispatches event200 with parameter<80 to8058af54',
        'limits':['No verified host/public route to this event','Calibration modification is stateful and not a read-only probe','No runtime file version/integrity/rollback contract']},
       {'id':'usb.entry_debug_request','status':'static-route-partial',
        'handler':0x8079c590,'dispatcher_table_index':0xd3,'record':0x80899560,'receive_flag':0,
        'effect':'subcommand low8 passed to8078bd48; posts queue2 message100000 with mode as argument',
        'limit':'Requires existing application debug dispatch; circular as an independent entry into debug mode'}],
      'gates':{'independent_mode6_entry_verified':False,'safe_mode0_activation_verified':False,
          'software_unbootable_recovery_verified':False,'executable_trial_allowed':False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete/application')
    parser.add_argument('--index',type=Path,default=ROOT/'derived/native-index-final/native.sqlite')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/usb-entry-contracts.json')
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('Choose an unused output path')
    report=build_report(args.workspace,args.source,args.native,args.index)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as out:json.dump(report,out,indent=2);out.write('\n')
    print(json.dumps({'wrapper_calls':len(CALLS),'dossiers':len(FUNCTIONS),'mode6_direct_calls':0,'executable_trial_allowed':False}))


if __name__=='__main__':main()
