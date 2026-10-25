"""Authenticate separate boot carriers and delimit the missing reset/recovery chain.

Offline only. Address spaces remain per-image; no host/device requests are built.
"""
import argparse
from io import BytesIO
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from map_development_contracts import ROOT, WORKSPACE, BASELINE, digest
from map_recovery_transport import ElfBytes, check_dossiers

IMAGES = {'updater': (0x200, 'image-00000200', (0x80010000,0x800109c8,0x8001a4e8)),
          'tiny-loader': (0x1006c0, 'image-001006c0', (0x81000400,0x81000644,0x81000948,0x81000ad0,0x81000cc0,0x81000f90)),
          'primary': (0x1026c0, 'image-001026c0', (0x80000600,0x9fc08000,0x9fc08860))}
# MIPS16 instruction words are independently matched to carrier bytes, then
# corroborated against Ghidra. No unsupported Capstone MIPS16 decode is claimed.
TINY_ASSERTIONS = {
  0x8100040a: ('ba65','move sp,v0'),
  0x8100040e: ('40ea','jalr v0'),
  0x81000658: ('405a','sltiu v0,0x40'),
  0x81000668: ('48c1','sb v0,0x8(s1)'),
  0x81000674: ('f772','cmpi v0,0xf7'),
  0x8100067c: ('a2f3006a','li v0,0x13a0'),
  0x81000686: ('2972','cmpi v0,0x29'),
  0x8100068e: ('a2f3016a','li v0,0x13a1'),
  0x8100096a: ('439a','lw v0,0xc(v0)'),
  0x81000970: ('449a','lw v0,0x10(v0)'),
  0x81000976: ('489a','lw v0,0x20(v0)'),
  0x81000a60: ('40ea','jalr v0'),
  0x81000a68: ('40ea','jalr v0'),
  0x81000c88: ('469a','lw v0,0x18(v0)'),
}
LITERALS = {0x81000420:0x81002f28,0x81000424:0x81000949,
  0x810006a8:0x9fc00900,0x81000a8c:0xbfc09600,
  0x81000acc:0x81000ad1,0x81000ca0:0x81000cc1,
  0x81000ca4:0xbfbfffff,0x81000ca8:0xbfc07fff,
  0x81000cac:0xbfc00000,0x81000cb0:0x9000ffff,
  0x81000cb4:0x90000000,0x81000cb8:0x20000000,
  0x81000cbc:0x81000429}


def chip_selector(rom_bytes):
    """Model only the tiny loader's 64-byte sum, not a hardware identification API."""
    if len(rom_bytes)!=64: raise ValueError('Exactly 64 observed ROM bytes required')
    value=sum(rom_bytes)&255
    return {0xf7:0x13a0,0x29:0x13a1}.get(value,value)


def destination_class(address):
    """Model destination classification in81000ad0; no safety/placement approval."""
    if not isinstance(address,int) or not 0<=address<=0xffffffff:
        raise ValueError('Expected unsigned32 address')
    if 0xbfbfffff<address<=0xbfc07fff:
        return {'action':'skip','destination':None}
    if address&0xbfc00000==0xbfc00000:
        return {'action':'stage-then-copy','destination':address&0x9000ffff}
    if address&0x90000000==0x90000000:
        return {'action':'stage-then-copy','destination':address}
    return {'action':'direct-read','destination':address|0x20000000}


def file_backed_at(parts,address,size):
    """Find coverage within one image, accepting only the observed KSEG alias rule."""
    if not isinstance(size,int) or size<=0 or not 0<=address<=0xffffffff or address+size>0x100000000:
        raise ValueError('Invalid coverage range')
    start=address&0x1fffffff
    return any((base&0x1fffffff)<=start and start+size<=(base&0x1fffffff)+len(body)
               for base,body in parts)


def check_tiny(mapping,directory):
    instructions={}
    for address in IMAGES['tiny-loader'][2]:
        data=json.loads((directory/'functions'/f'{address:08x}.json').read_text())
        instructions.update({int(row['address'],16):row for row in data['instructions']})
    for address,(body,text) in TINY_ASSERTIONS.items():
        if mapping.read(address,len(bytes.fromhex(body))).hex()!=body:
            raise ValueError(f'Tiny carrier word differs at{address:#x}')
        row=instructions.get(address)
        if row is None or row['bytes']!=body or row['text']!=text:
            raise ValueError(f'Tiny imported decode differs at{address:#x}')
    for address,value in LITERALS.items():
        if struct.unpack('<I',mapping.read(address,4))[0]!=value:
            raise ValueError(f'Tiny literal differs at{address:#x}')
    return {'carrier_words':len(TINY_ASSERTIONS),'literal_words':len(LITERALS),
      'independent_mips16_disassembly':False,
      'limit':'Exact original bytes plus retained Ghidra decode; no MIPS16 CPU execution or second decoder'}


def build_report(workspace,source_path,native):
    source=source_path.read_bytes()
    if digest(source)!=BASELINE:raise ValueError('Source identity differs')
    images={};maps={}
    for label,(offset,name,functions) in IMAGES.items():
        path=workspace/'elf-original'/(name+'.elf');raw=path.read_bytes()
        if source[offset:offset+len(raw)]!=raw:raise ValueError('Separate ELF differs from carrier')
        elf=ELFFile(BytesIO(raw));mapping=ElfBytes(raw);maps[label]=mapping
        images[label]={'carrier_offset':offset,'elf_sha256':digest(raw),
            'entry':int(elf['e_entry']),'flags':int(elf['e_flags']),
            'file_backed_ranges':[{'start':a,'size':len(b)}for a,b in mapping.parts],
            'native':check_dossiers(native/name,mapping,digest(raw),functions)}
    checks=check_tiny(maps['tiny-loader'],native/IMAGES['tiny-loader'][1])
    # Coverage across every original ELF is kept image-specific; image addresses
    # overlap and cannot be merged as though all carriers were installed at once.
    coverage=[]
    for path in sorted((workspace/'elf-original').glob('*.elf')):
        body=path.read_bytes();offset=int(path.stem.removeprefix('image-'),16)
        if source[offset:offset+len(body)]!=body:raise ValueError('Coverage ELF differs from carrier')
        mapping=ElfBytes(body)
        coverage.append({'image':path.stem,'elf_sha256':digest(body),'carrier_offset':offset,
            'representation':'packed carrier; mapped bytes only' if offset>=0x2202c0 else 'executable carrier',
            'rom_fingerprint_9fc00900':file_backed_at(mapping.parts,0x9fc00900,64),
            'reset_vector_bfc00000':file_backed_at(mapping.parts,0xbfc00000,4),
            'boot_header_bfc09600':file_backed_at(mapping.parts,0xbfc09600,0x24)})
    if any(row['rom_fingerprint_9fc00900'] or row['reset_vector_bfc00000'] for row in coverage):
        raise ValueError('Previously absent ROM coverage changed; re-review reset chain')
    return {'schema_version':1,'source_sha256':BASELINE,
      'method':'Authenticated separate carrier bytes and direct Ghidra dossiers, not REA Evidence',
      'camera_commands_issued':False,'target_executed':False,'image_namespaces':images,
      'tiny_checks':checks,'original_elf_coverage':coverage,
      'contracts':[
       {'id':'reset.tiny_loader_entry','status':'static-route-partial',
        'chain':['ELF odd entry81000401, decoded at81000400','literal81000420 supplies stack81002f28',
          'literal81000424→81000949(MIPS16)','81000948 reads runtime headerbfc09600+0xc/+0x10/+0x20',
          '81000ad1 reads ELF header/program headers and copies PT_LOAD data; returns ELF entry+0x18',
          '81000948 calls returned entry; falls into loop if it returns'],
        'constraints':['No recovered reset-vector-to-loader caller','Headerbfc09600 is runtime state, not authenticated installed backup',
          'Calling loaded entry gives no rollback route if load or application fails',
          'Loader uses p_filesz; no complete BSS, bounds, integrity or placement contract established']},
       {'id':'reset.rom_dependency','status':'unresolved',
        'reader':0x81000644,'address':0x9fc00900,'bytes':64,
        'rule':'sum modulo256: f7→13a0;29→13a1;otherwise returns sum; caller loops forever for other values',
        'gap':'Neither reset vector atbfc00000 nor these ROM fingerprint bytes are file-backed in any original ELF',
        'interpretation':'Constants distinguish two low-level paths; no claim of actual CPU/chip model or installed ROM version'},
       {'id':'reset.primary_rom_address_region','status':'static-contract-partial',
        'address':0x9fc08000,'caller':0x9fc08860,
        'role':'Caller quiesces application hardware/cache, changes clock state, calls GPIO/status wait routine, then restores state and returns',
        'limit':'9fc/bfc-shaped address does not make packaged code immutable ROM or independently reachable recovery'},
       {'id':'reset.recovery_independence','status':'blocked',
        'known':'Separate updater entry80010000 and recovery-section code exist; package RecoverArea flagbit31 is clear',
        'required':['Authenticated installed boot/ROM routing independent of application',
          'Accessible software-only activation and matching safe transport',
          'Full installed flash geometry and calibration/settings/ECC/bad-block backup coverage',
          'Verified restoration procedure without deliberately damaging camera'],
        'limit':'Package ELF layout is not installed physical flash layout; normal firmware update is not unbootable recovery'}],
      'gates':{'reset_to_recovery_independent':False,'complete_backup_verified':False,
          'software_unbootable_recovery_verified':False,'executable_trial_allowed':False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/reset-recovery.json')
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('Choose an unused output path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as out:json.dump(report,out,indent=2);out.write('\n')
    print(json.dumps({'images':len(report['image_namespaces']),'instruction_words':len(TINY_ASSERTIONS),
        'literal_words':len(LITERALS),'executable_trial_allowed':False}))


if __name__=='__main__':main()
