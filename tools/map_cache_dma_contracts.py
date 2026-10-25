"""Source-bound cache, alias and narrowly observed DMA ownership sequences.

Pure models only; no target execution, DMA, MMIO or firmware patching.
"""
import argparse
import json
from pathlib import Path

from map_development_contracts import (ROOT,WORKSPACE,BASELINE,AddressMap,
    load_analysis,digest,Cs,CS_ARCH_MIPS,CS_MODE_MIPS32,CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS=(0x800b43bc,0x800b3a9c,0x800b52e4,0x800b4614,
    0x800b22fc,0x800b2364,0x800b256c,0x800ce880,0x8020561c,
    0x8018f6e4,0x80197ac8,0x8005df30,0x8005dc78,0x8005db18,
    0x8005d780,0x8005d868,0x8005da00,0x80191b6c)
ASSERTIONS={
    0x8020572c:('beqz','$a2, 0x8020587c'),
    0x80205740:('and','$a0, $s5, $s2'),
    0x8020574c:('jal','0x800b3a9c'),
    0x80205888:('jal','0x800b52e4'),
    0x802058a0:('jal','0x8018f6e4'),
    0x802058ac:('jal','0x8018e344'),
    0x8005e00c:('jal','0x800b3a9c'),
    0x8005e030:('jal','0x800b52e4'),
    0x8005e180:('jal','0x8005dc78'),
    0x8005dd6c:('jal','0x800c1014'),
    0x8005dacc:('jal','0x800b52e4'),
    0x8005dae0:('jal','0x800b43bc'),
    0x800b550c:('srlv','$t8, $s2, $s0'),
    0x800b5510:('sllv','$v1, $t8, $s0'),
    0x800b5514:('b','0x800b5524'),
    0x800b5518:('addu','$a0, $s2, $s3'),
    0x800b551c:('cache','0x15, ($v1)'),
    0x800b5520:('addu','$v1, $v1, $s1'),
    0x800b5524:('sltu','$s2, $v1, $a0'),
    0x800b5528:('bnez','$s2, 0x800b551c'),
    0x800ce888:('andi','$v0, $t0, 0xff00'),
    0x800ce89c:('mtc0','$t0, $t4, 0'),
    0x8005df38:('lui','$s1, 0x2000'),
    0x8005df3c:('and','$v0, $a0, $s1'),
    0x8005e01c:('or','$s6, $s6, $s1'),
    0x8005e028:('or','$s0, $s0, $s1'),
    0x8005e0d4:('jal','0x8005d780'),
    0x8005e19c:('jal','0x8005d868'),
    0x8005dd5c:('lui','$a1, 0x4000'),
    0x8005dd68:('addiu','$v0, $zero, -1'),
    0x8005dd70:('sw','$v0, 0x10($sp)'),
    0x8005ddb0:('addiu','$v0, $zero, 1'),
    0x8005dc70:('j','0x800cd938'),
}


def kseg_aliases(address):
    """Restricted description for observed KSEG0/1 tokens, not validation of RAM."""
    if type(address)is not int or not 0x80000000<=address<=0xbfffffff:
        raise ValueError('Only KSEG0/1-shaped32-bit addresses are modeled')
    return {'cached':address&0xdfffffff,'uncached':address|0x20000000,
        'low29':address&0x1fffffff}


def line_loop(address,length,line_exponent,limit=4096):
    """Actual small-range loop arithmetic; reports wrap rather than repairing it.

    The branch at 800b5514 tests before CACHE. A zero length can nevertheless
    cover one line when the address is unaligned; entry guards can select an
    assert or whole-cache operation before this loop is reached.
    Does not model tag-scan selection, MMIO, CACHE effects or invalid-input policy.
    """
    if not all(type(x)is int and 0<=x<=0xffffffff for x in (address,length,line_exponent)):
        raise ValueError('Inputs must be unsigned32-bit values')
    if type(limit)is not int or not 1<=limit<=100000:raise ValueError('Invalid model bound')
    exponent=line_exponent&31;step=1<<exponent;normalized=address&0xdfffffff
    start=(normalized>>exponent)<<exponent;total=normalized+length;end=total&0xffffffff
    cursor=start;lines=[];seen=set()
    while cursor<end:
        if cursor in seen:return {'lines':lines,'end':end,'end_wrapped':total>0xffffffff,'state':'cycle'}
        if len(lines)>=limit:return {'lines':lines,'end':end,'end_wrapped':total>0xffffffff,'state':'bounded-limit'}
        seen.add(cursor);lines.append(cursor);cursor=(cursor+step)&0xffffffff
    return {'lines':lines,'end':end,'end_wrapped':total>0xffffffff,'state':'finished'}


def fastcopy_alias_plan(destination,source,length):
    if type(length)is not int or not 0<=length<=0xffffffff:raise ValueError('Invalid length')
    dst=kseg_aliases(destination);src=kseg_aliases(source)
    operations=[]
    if not destination&0x20000000:operations.append({'operation':'D-invalidate','address':destination,'length':length})
    if not source&0x20000000:operations.append({'operation':'D-writeback-invalidate','address':source,'length':length})
    return {'operations':operations,'destination_alias':dst['uncached'],'source_alias':src['uncached'],
        'scope':'pre-copy alias/cache plan only; no allocation/overlap/geometry/completion validation'}


def build_report(workspace,source,native):
    if digest(source.read_bytes())!=BASELINE:raise ValueError('Source differs')
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    checks=[]
    for address,expected in ASSERTIONS.items():
        row=list(decoder.disasm(mapping.read(address,4),address))
        if len(row)!=1 or(row[0].mnemonic,row[0].op_str)!=expected:
            raise ValueError(f'Instruction differs at{address:#x}')
        checks.append({'address':address,'bytes_sha256':digest(mapping.read(address,4))})
    corroboration=check_dossiers(native,mapping,digest(raw),FUNCTIONS)
    barriers=[]
    for address in FUNCTIONS:
        data=json.loads((native/'functions'/f'{address:08x}.json').read_text())
        for row in data['instructions']:
            mnemonic=row['text'].split(' ',1)[0].lstrip('_')
            if mnemonic in ('sync','ehb','synci'):
                barriers.append({'function':address,'site':row['address'],'mnemonic':mnemonic})
    return {'schema_version':1,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
      'method':'authenticated independent Capstone checks and direct Ghidra dossiers, not REA Evidence',
      'camera_commands_issued':False,'target_executed':False,'patch_constructed':False,
      'instruction_checks':checks,
      'native_corroboration':corroboration,'explicit_sync_ehb_synci_in_selected_dossiers':barriers,
      'contracts':[
       {'id':'cache.small_range_loop','status':'static-contract-verified',
        'entries':{'I-invalidate':0x800b43bc,'D-invalidate':0x800b3a9c,'D-writeback-invalidate':0x800b52e4,'D-writeback':0x800b4614},
        'arguments':{'a0':'address token','a1':'length bytes'},'return':'void; no cache-completion status',
        'small_range_rule':'normalized=address&dfffffff;start=(normalized>>(exponent&31))<<(exponent&31);end=low32(normalized+length);while cursor<end:CACHE;cursor=low32(cursor+(1<<(exponent&31)))',
        'first_test':'800b5514 branches to unsigned comparison before first CACHE; arithmetic model zero-length aligned=0 lines, unaligned=1 line; entry guards may prevent this loop being reached',
        'geometry':'runtime exponent from EBase-selected context state; line rounding can affect bytes outside requested range',
        'large_range':'800b256c selects tag-scan path at unsigned length>=low32(cache_capacity*10); different address filtering, not modeled by small-range helper',
        'invalid_inputs':'I/D invalidate null address or zero length assert; D-WBINV null/zero uses whole-cache800b5028; D-writeback policy differs',
        'small_range_examples':[
            {'address':address,'length':length,'exponent':exponent,
             'arithmetic_only':line_loop(address,length,exponent)}
            for address,length,exponent in ((0x80001000,0,5),(0x80001001,0,5),
                (0xa000101f,2,5),(0xdffffff0,0x20000020,5))],
        'constraints':['caller must own entire affected cache lines','32-bit end arithmetic has no overflow guard in reviewed loop','bit29 mask is not proof arbitrary address maps to DRAM','cross-core visibility and hardware ordering remain unverified']},
       {'id':'cache.context_interrupts','status':'partial','enter':0x800b22fc,'exit':0x800b2364,
        'role':'per-EBase optional timing instrumentation and counter publication; not a lock around entire operation',
        'interrupt_helper':0x800ce880,'interrupt_rule':'returns prior Status&ff00; writes(Status&ffff00ff)|argument; called around cache tag-read sequences',
        'limits':'no global scheduler exclusion or DMA ownership transfer is proven; selected functions contain no explicit sync/ehb/synci; this does not prove absence of synchronization elsewhere'},
       {'id':'capture.direct_scale_cache_handoff','status':'static-route-verified','address':0x8020561c,
        'caller':0x802058f8,'source':'param1 word2 address; span low32((word4>>1)*word1*2)',
        'destination':'param4 address; span low32(even-rounded outputwidth*even-rounded outputheight*2)',
        'sequence':['if sourcebit29 clear:D-WBINV800b52e4(source,span)','source descriptor address=source|20000000','D-invalidate800b3a9c(destination&dfffffff,outputspan)','output descriptor address=destination|20000000','create8018e1d0','run/wait wrapper8018f6e4(path,0)','destroy8018e344;return wrapperresult'],
        'ownership':'caller-provided input/output allocations remain borrowed; descriptor construction copies address tokens, not image bytes',
        'unknowns':['full allocation extents and cache-line sharing','runtime format/colour domain','completion success on every type-specific callback','interrupt ownership and cross-context exclusion','safe caller CPU access after completion']},
       {'id':'dma.fastcopy_handoff','status':'static-route-verified','address':0x8005df30,
        'arguments':{'a0':'destination','a1':'source','a2':'length','a3/stackarg5':'scratchpad range selectors'},
        'preparation':'invalidate cached destination;writeback-invalidate cached source;ORboth with20000000;CPUcopies alignment head/tail;DMA only if alignment offsets agree',
        'ownership':'scratchpad acquire8005d780 before descriptors;release8005d868 after synchronous submit helper8005dc78',
        'descriptor_rule':'pairs of source/destination word addresses, masks differ at final remainder; cannot infer universal DMA address format',
        'completion_helper':0x8005dc78,'completion':'installs callback8005db18;wait800c1014(event808a7588,mask40000000,timeoutffffffff);callback sets event after descriptor count reaches0;helper returns1 without checking wait return',
        'return':'uncached destination alias on aligned DMA route;fallback memcpy return otherwise',
        'limits':'hardware-specific scratchpad/DMA route; caller overlap,lengthoverflow,foreign owners and cancellation safety are not established'},
       {'id':'code.observed_cache_pair','status':'partial','address':0x8005da00,
        'sequence':'one branch D-WBINV800b52e4(bfc08000,1800) then I-invalidate800b43bc(same); scratchpad ownership acquired and released',
        'scope':'Os/Dma/FastCopy initialization path; other branch copies preserved scratchpad bytes and skips pair',
        'limits':'not a general code-loader publication contract; no placement/hook/execute handoff proven'},
       {'id':'image.copy_cached_publication','status':'static-route-verified','address':0x80191b6c,
        'branch':'when(param3&e)==0:memcpy(destination&dfffffff,source&dfffffff,width*height*2),thenD-WBINVdestination,return1',
        'other_branch':'uncached descriptors;may invoke whole-cache800b5028 then80191a38',
        'limits':'another path-specific example, not permission to borrow any capture buffer'}],
      'gates':{'general_code_publication_verified':False,'capture_buffer_ownership_verified':False,
        'dma_public_sdk_verified':False,'code_trial_allowed':False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete/application')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/cache-dma-contracts.json')
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('Choose a new output path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as handle:json.dump(report,handle,indent=2);handle.write('\n')
    print(json.dumps({'contracts':len(report['contracts']),'native_dossiers':len(FUNCTIONS),'code_trial_allowed':False}))


if __name__=='__main__':main()
