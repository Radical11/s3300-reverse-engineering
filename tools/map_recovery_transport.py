"""Authenticated offline debug-transport and update-startup investigation.

This map constructs no USB requests and performs no camera operations.
"""
import argparse
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import struct

from elftools.elf.elffile import ELFFile
from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, checked_table, Cs, CS_ARCH_MIPS,
    CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)

APP_FUNCTIONS=(0x80796108,0x80796310,0x80795fe0,0x80796070,0x80796424,
    0x8079651c,0x8079cd48,0x80203e54,0x8078d718,0x8078d768,
    0x8078d88c,0x8078fa3c,0x80791e0c,0x80771cdc,0x8038d90c,
    0x8038da28,0x80795ce0,0x80795e68)
BOOT_FUNCTIONS=(0x80010000,0x8009d64c,0x80010b40,0x800109c8,
    0x8001a3d0,0x8001a4e8,0x8001af70,0x8001b300,0x80012e84,0x8001bc84)
WINDOWS=(("usb_control_loop",0x8078d7b4,0xac),
    ("usb_command_queue_loop",0x8078d860,0x2c),
    ("uart_dispatch_loop",0x80791d10,0xfc),
    ("getmem_handler",0x8079de34,0x1d8),
    ("configmem_handler",0x8079cd48,0xb0),
    ("configmem_state",0x80203e54,0xa0),
    ("usb_setup_receiver",0x80796310,0x114))
ASSERTIONS={
    0x8078d850:("jal","0x80796108"),
    0x8078d87c:("jal","0x80796108"),
    0x8078d880:("addiu","$a2, $zero, 1"),
    0x80791da4:("jal","0x80796108"),
    0x80791dc0:("move","$a2, $zero"),
    0x807963a0:("lbu","$t3, 3($s1)"),
    0x807963a8:("lbu","$t2, 2($s1)"),
    0x8079cd60:("lw","$s2, 4($a1)"),
    0x8079cd90:("jal","0x80203e54"),
    0x80203e64:("sw","$a1, 4($t0)"),
    0x80203e68:("sw","$a2, 0x10($t0)"),
    0x8079dec4:("or","$s1, $t2, $t1"),
    0x8079def0:("jal","0x80796070"),
}


def describe_setup_bytes(data):
    """Decode an observed eight-byte setup record; never build/send requests.

    USB field names follow the eight-byte layout; acceptance/type semantics
    remain unknown. This helper does not promise device reachability.
    """
    if len(data)!=8:raise ValueError("Expected exactly eight observed setup bytes")
    request_type,request,value,index,length=struct.unpack("<BBHHH",data)
    return {"request_type":request_type,"request":request,
        "value":value,"index":index,"length":length,
        "internal_index":data[3],"subcommand":data[2]}


def describe_config_payload(payload,mode):
    if len(payload)<8:raise ValueError("ConfigMem handler reads two complete words")
    if not 0<=mode<=255:raise ValueError("Mode must be an observed byte")
    address,length=struct.unpack_from("<II",payload)
    return {"mode":mode,"address":address,"length":length,
        "getmem_mode1_alias":address|0x20000000 if mode==1 else None}


class ElfBytes:
    def __init__(self,raw):
        elf=ELFFile(BytesIO(raw))
        self.parts=[(int(s['p_vaddr']),s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    def read(self,address,size):
        matches=[body[address-start:address-start+size]for start,body in self.parts
            if start<=address and address+size<=start+len(body)]
        if len(matches)!=1:raise ValueError("ELF address is absent or ambiguous")
        return matches[0]


def check_dossiers(directory,mapping,expected_hash,addresses):
    meta_path=directory/'image.json';meta=json.loads(meta_path.read_text())
    if meta['executable_sha256']!=expected_hash or meta['language']!='MIPS:LE:32:default':
        raise ValueError("Native image identity or architecture differs")
    records=[]
    for address in addresses:
        path=directory/'functions'/f'{address:08x}.json';data=json.loads(path.read_text())
        if int(data['address'],16)!=address or not data['decompilation_completed']:
            raise ValueError("Incomplete or misaddressed native dossier")
        if not data['instructions'] or not data['pseudocode'].strip():
            raise ValueError("Empty native dossier")
        for row in data['instructions']:
            body=bytes.fromhex(row['bytes'])
            if mapping.read(int(row['address'],16),len(body))!=body:
                raise ValueError("Native instruction differs from authenticated image")
        records.append({"address":address,"dossier_sha256":digest(path.read_bytes()),
            "instructions_checked":len(data['instructions']),"name":data['name']})
    return {"class":"direct Ghidra static analysis; not REA Evidence",
        "image_metadata_sha256":digest(meta_path.read_bytes()),"records":records}


def build_report(workspace,source_path,native,index):
    source=source_path.read_bytes()
    if digest(source)!=BASELINE:raise ValueError("Unsupported source identity")
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    windows=[];instructions={}
    for label,address,size in WINDOWS:
        body=mapping.read(address,size);decoded=list(decoder.disasm(body,address))
        if sum(x.size for x in decoded)!=size:raise ValueError("Incomplete bounded decode")
        instructions.update({x.address:(x.mnemonic,x.op_str)for x in decoded})
        windows.append({"label":label,"address":address,"bytes":size,"sha256":digest(body),
            "boundary":"bounded analyst window; not an authenticated function boundary"})
    for address,expected in ASSERTIONS.items():
        if instructions.get(address)!=expected:raise ValueError(f"Instruction changed at {address:#x}")
    tables={"config_setmem_getmem":checked_table(mapping,0x80899650,
        [0x8079cd48,1,0x8079d74c,0,0x8079de34,0])}
    boot_path=workspace/'elf-original/image-00000200.elf';boot=boot_path.read_bytes()
    if source[0x200:0x200+len(boot)]!=boot:raise ValueError("Updater ELF differs from carrier slice")
    bootmap=ElfBytes(boot)
    connection=sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        refs=[]
        for target in ('8078d7b4','8078d860','80791d10'):
            rows=connection.execute('select site,target,type,function_address from references_from where target=? order by site',(target,)).fetchall()
            refs.extend({"site":s,"target":t,"type":k,"function":f}for s,t,k,f in rows)
    finally:connection.close()
    expected={(0x8078fd88,'8078d7b4',0x8078fa3c),(0x8078d908,'8078d860',0x8078d88c),(0x80791e28,'80791d10',0x80791e0c)}
    if not expected.issubset({(x['site'],x['target'],x['function'])for x in refs}):
        raise ValueError("Native startup reference chain differs")
    header_word=struct.unpack_from('<I',source,0x1000c0+0x14)[0]
    return {"schema_version":1,"source_sha256":BASELINE,"analysis_sha256":digest(raw),
      "camera_commands_issued":False,"target_executed":False,"rea_evidence":False,
      "reviewed_windows":windows,"instruction_assertions":len(ASSERTIONS),"checked_tables":tables,
      "native_application":check_dossiers(native/'application',mapping,digest(raw),APP_FUNCTIONS),
      "native_updater":check_dossiers(native/'image-00000200',bootmap,digest(boot),BOOT_FUNCTIONS),
      "native_index_sha256":digest(index.read_bytes()),"startup_callback_references":refs,
      "contracts":[
        {"id":"debug.configmem_to_getmem","status":"static-route-verified",
         "config_index":0xf1,"config_handler":0x8079cd48,"config_receive_flag":1,
         "arguments":{"a0":"mode low8 from dispatcher subcommand","a1":"payload beginning with address and length LE32 words"},
         "state_setter":0x80203e54,"state_base":0x800e113c,
         "state_layout":{"mode":0,"address":4,"length":0x10},
         "getmem_index":0xf3,"getmem_handler":0x8079de34,"getmem_receive_flag":0,
         "mode1":"address OR0x20000000; cache/memory preparation800b52e4; send80796070; status/timing updates",
         "limits":"not a passive public read API: no verified valid address map/length cap/installed correspondence; neighboringf2 mutates memory or invokes monitor"},
        {"id":"debug.usb_control_envelope","status":"partial",
         "setup_receiver":0x80796310,"setup_state":0x808c8568,
         "setup_layout":"byte3→internal table index; byte2→subcommand; bytes6/7→LE16 transfer length",
         "dispatcher":0x80796108,"transport_selector":1,
         "queue":"8078d768 posts two words to UsbCamCmd808c8530;8078d718 receives;8078d860 truncates low8 and dispatches",
         "special_index2":"control loop dispatches immediately; other indices queue",
         "usb_transport_calls":{"setup":"8038d90c with logical selector0","receive":"8038d720 selector2 normally; selector0 on length-bearing setup state","send":"8038da28 selector3 normally; selector1 for length-bearing control state"},
         "bounds":"dispatcher allocates0x2000; genericreceive defaults64bytes; setup-driven path takes received16-bit length; no complete bound/valid-index validation recovered",
         "unknowns":["accepted bmRequestType and bRequest combinations","endpoint-address mapping from logical selectors on active configuration","state timing and queue serialisation","confirmed installed firmware interface"]},
        {"id":"debug.application_startup","status":"partial",
         "usb_start":0x8078fa3c,"event":"USB configuration status1/connect creates control/vendor thread; queue thread conditional on80898ea8 and80898ea6",
         "uart_start":0x80771cdc,"uart_flag":"sub80000cf4 bit4 permits80791e0c to create UartAgent80791d10",
         "uart_transport_selector":0,"uart_framing":"80795ce0 sends even-rounded data in≤64-byte chunks with02/wordcount, requires54ack;04terminates; receive80795e68 handles02/04/43",
         "limits":"both debug loops live in normal application; neither proves availability after application boot failure"},
        {"id":"recovery.updater_entry","status":"partial",
         "carrier_elf_offset":0x200,"elf_sha256":digest(boot),
         "entry_chain":["entry80010000→main8009d64c","ThreadX kernel→tx_application_define80010b40","Burn Main thread→BurnMain800109c8"],
         "source_selection":"bfc095fc bit0x1000 forces0x1c USB, otherwise(low8>>3):3UART;1/4/6/ff card variants",
         "recovery_section_initializer":0x8001a3d0,"initializer_role":"section size/alignment metadata; not a reset recovery entry",
         "package_recover_flag_word":header_word,"package_recover_bit31_set":bool(header_word&0x80000000),
         "package_flag_scope":"BurnNand tests sign of payloadword+0x14; suppliedpackageword2 does not request that branch; installed recover area unknown",
         "write_range_dependency":"BurnGetSectionsMap8001a4e8 uses live sector count+1244 and erase unit+1240; upgrade copies existing boot-header sections; bad-block/physical write map unresolved",
         "unknowns":["reset-to-updater route independent of application","physical activation controls or software-only entry","existing recovery/calibration backup contents","actual physical erase/write ranges","tested restoration"]}],
      "gates":{"host_debug_read_validated":False,"complete_flash_backup_verified":False,
        "software_unbootable_recovery_verified":False,"code_trial_allowed":False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--index',type=Path,default=ROOT/'derived/native-index-final/native.sqlite')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/recovery-transport.json')
    parser.add_argument('--listings',type=Path,default=ROOT/'derived/recovery-transport')
    args=parser.parse_args()
    if args.output.exists()or args.listings.exists():raise FileExistsError('Choose unused output/listing paths')
    report=build_report(args.workspace,args.source,args.native,args.index)
    manifest,raw=load_analysis(args.workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    args.listings.mkdir(parents=True)
    for row in report['reviewed_windows']:
        text='; Authenticated bounded analyst window, not target execution.\n'
        text+='\n'.join(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}'for i in decoder.disasm(mapping.read(row['address'],row['bytes']),row['address']))+'\n'
        (args.listings/(row['label']+'.asm')).write_text(text,encoding='utf-8')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as handle:json.dump(report,handle,indent=2);handle.write('\n')
    print(json.dumps({'contracts':len(report['contracts']),'native_dossiers':len(APP_FUNCTIONS)+len(BOOT_FUNCTIONS),'code_trial_allowed':False}))


if __name__=='__main__':main()
