"""Authenticate capture-mode dispatch through still queues into JPEG processing.

Offline static analysis only. Queue helpers describe words, never construct or
send device requests. Physical key origin and active Auto-mode RAM are unknown.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, checked_table, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x80707590,0x80706ca8,0x8022edac,0x80204460,0x801f5730,
    0x80239614,0x80239858,0x80239494,0x8032fad4,0x80330d98,
    0x80239fd4,0x8030847c,0x8023f458,0x8023a030)
WINDOWS = (('StillCaptMain_entry',0x80333458,0x240),
           ('FileCreator_receive_loop',0x8030980c,0x90))
ASSERTIONS = {
    0x80708554:('jal','0x80706ca8'),0x80708558:('move','$a0, $zero'),
    0x80707128:('beqz','$t8, 0x80707214'),0x80707134:('addiu','$a0, $zero, 0x58'),
    0x80707208:('addiu','$a0, $zero, 0x53'),0x80707218:('addiu','$a0, $zero, 0x50'),
    0x8022edb4:('jal','0x80204460'),0x80204af0:('addiu','$a0, $s1, -0x53'),
    0x80204af4:('sltiu','$t6, $a0, 0x10'),0x80204b10:('jr','$a0'),
    0x80204d28:('move','$s0, $zero'),0x80204d9c:('addiu','$s0, $zero, 1'),
    0x80204dec:('addiu','$s0, $zero, 2'),0x80204da4:('addiu','$s0, $zero, 6'),
    0x80204dac:('addiu','$s0, $zero, 3'),0x80204db4:('addiu','$s0, $zero, 7'),
    0x80204dbc:('addiu','$s0, $zero, 5'),0x80204d44:('bnel','$s3, $zero, 0x80204660'),
    0x80204d50:('move','$a3, $s0'),0x80204d54:('move','$a0, $zero'),
    0x80204d58:('addiu','$a1, $zero, -8'),0x80204d60:('jalr','$v0'),
    0x80204d64:('addiu','$a2, $zero, 1'),0x8023fc2c:('jal','0x80239614'),
    0x80239814:('jal','0x80239494'),0x8023955c:('jal','0x8032fad4'),
    0x8032fb64:('jal','0x800c21cc'),0x80333594:('jal','0x80330d98'),
    0x80331290:('addiu','$a1, $zero, 0x1006'),0x80331294:('move','$a2, $s2'),
    0x80331298:('jal','0x801f5730'),0x8023fff4:('jal','0x80239fd4'),
    0x80239fe0:('addiu','$a0, $zero, 4'),0x80239fe8:('jal','0x801f5730'),
    0x80239fec:('addiu','$a1, $zero, 0x1014'),0x80309838:('addiu','$a0, $zero, 4'),
    0x80309848:('jal','0x801f5810'),0x80309854:('bne','$v0, $s1, 0x80309830'),
    0x8030985c:('jal','0x8030847c'),0x80309860:('lw','$a0, 0x20($sp)'),
    0x80308fd0:('sb','$t4, 0x2de($s1)'),0x80308fdc:('addiu','$a1, $zero, 0x1044'),
    0x80308fe0:('jal','0x801f5730'),0x8023ffc0:('jal','0x8023a030'),
    0x8023a03c:('addiu','$a0, $zero, 7'),0x8023a048:('addiu','$a1, $zero, 0x1042'),
    0x801f5788:('sw','$a3, 0x18($sp)'),0x801f579c:('sw','$t3, 0x14($sp)'),
    0x801f57a0:('sw','$t9, 0x1c($sp)'),0x801f57a4:('beq','$t2, $a3, 0x801f57b8'),
    0x801f57a8:('sw','$t2, 0x10($sp)'),0x801f57ac:('addiu','$a0, $t1, 8'),
    0x801f57b8:('jal','0x800cc868'),
}
MODE_TABLE = (0x80204d70,0x80204d00,0x80204da8,0x80204d00,
    0x80204d00,0x80204da0,0x80204d00,0x80204d00,0x80204d00,0x80204d00,
    0x80204d00,0x80204d00,0x80204d00,0x80204dc0,0x80204db8,0x80204db0)


def u32(value):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError('Expected unsigned32-bit observed value')
    return value


def capture_mode_contract(mode, app_state):
    """Only AppSetMode's 0x50/0x60-family capture arm, not general mode control."""
    u32(mode);u32(app_state)
    if mode & 0xf0 not in (0x50,0x60) or mode > 255:
        raise ValueError('Only reviewed capture-mode families50/60 are modeled')
    selector = {0x53:1,0x55:3,0x58:6,0x60:2,0x61:5,0x62:7}.get(mode,0)
    return {'mode':mode,'selector':selector,'post_when_app_state_zero':app_state==0,
        'pipe':0,'event':0xfffffff8,'action':1,'device_request_created':False}


def capture_thread_contract(selector):
    u32(selector)
    if selector in (0,1,3,6):
        return {'entry':0x80333458,'name':'StillCaptMain','argument':selector,'stack_bytes':12000}
    if selector==2:return {'entry':0x803329c0,'name':'Capture_Sequence','argument':0,'stack_bytes':10000}
    if selector==5:return {'entry':0x803329c0,'name':'Capture_Sequence','argument':1,'stack_bytes':None}
    if selector==7:return {'entry':0x803329c0,'name':'Capture_Sequence_HDR','argument':2,'stack_bytes':8000}
    if selector==4:return {'entry':0x8033c918,'name':'Capture_DRAM','argument':0,'stack_bytes':8000}
    raise ValueError('Selector outside reviewed thread switch')


def describe_pipe_record(record):
    """Decode the four stack words passed to queue send; no object bytes copied."""
    if len(record)!=16:raise ValueError('Expected exactly four observed LE32 words')
    event,arg0,arg1,tail=struct.unpack('<4I',record)
    return {'event':event,'argument0':arg0,'argument1':arg1,'tail':tail,
        'queue_offset':0x40 if event==0xfffffffe else 8,
        'pointee_ownership_established':False}


def build_report(workspace,source,native):
    if digest(source.read_bytes())!=BASELINE:raise ValueError('Source identity differs')
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    checks=[]
    for address,expected in ASSERTIONS.items():
        rows=list(decoder.disasm(mapping.read(address,4),address))
        if len(rows)!=1 or(rows[0].mnemonic,rows[0].op_str)!=expected:
            raise ValueError(f'Instruction differs at{address:#x}')
        checks.append({'address':address,'sha256':digest(mapping.read(address,4))})
    windows=[]
    for name,address,length in WINDOWS:
        body=mapping.read(address,length);decoded=list(decoder.disasm(body,address))
        if sum(row.size for row in decoded)!=length:raise ValueError('Incomplete bounded window decode')
        windows.append({'name':name,'address':address,'bytes':length,'sha256':digest(body),'instructions':len(decoded),
            'scope':'analyst-selected original-byte window; no authenticated function boundary claimed'})
    table=checked_table(mapping,0x80253e50,list(MODE_TABLE))
    native_records=check_dossiers(native,mapping,digest(raw),FUNCTIONS)
    return {'schema_version':1,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
        'method':'Authenticated Capstone instructions and direct Ghidra dossiers; not REA Evidence',
        'target_executed':False,'camera_commands_issued':False,
        'instruction_assertions':checks,'bounded_windows':windows,'mode_switch_table':table,
        'native_corroboration':native_records,'contracts':[
         {'id':'capture.ui_mode_arm','status':'static-route-verified','ui_handler':0x80707590,
          'capture_call_site':0x80708554,'capture_setup':0x80706ca8,'mode_wrapper':0x8022edac,'app_set_mode':0x80204460,
          'normal_arm':'Within selected bVar3==0 setup branch, runtime UI/capture-state object(PTR808918a0) flag+3e chooses53; otherwise80891810 chooses58 or50. Other setup branches choose60 or50. This object is distinct from38-byte viewbank(PTR808918ac).',
          'side_effects':'UI state, capture/preview setup, timers and flags change before mode dispatch;80891810 is cleared after58.',
          'limits':['Physical shutter/key source and all event/state predicates into80707590 are not established.','Do not equate mode50 with a measured active Auto-mode call solely from this source trace.']},
         {'id':'capture.mode_to_thread','status':'static-contract-verified','app_set_mode':0x80204460,
          'selector_map':{f'{mode:02x}':capture_mode_contract(mode,0)['selector'] for mode in (0x50,0x53,0x55,0x58,0x60,0x61,0x62)},
          'condition':'For50/60-family arm,8020b1c0 return must be0 before pipe0/eventfffffff8(action1,selector) is posted.',
          'consumer':0x8023f458,'mode_request':0x80239614,'action_dispatch':0x80239494,'thread_dispatch':0x8032fad4,
          'thread_rows':[capture_thread_contract(n) for n in range(8)],
          'ownership':'Thread argument is a selector, not an external frame pointer; mode transitions depend on shared808c1bd4/1bd8/1be4 state.',
          'limits':['Mode request can defer/reconfigure existing states; not every request immediately creates a capture thread.','No safe host or camera SDK mode-set adapter exposed.']},
         {'id':'capture.still_to_creator','status':'static-route-verified','thread_window':0x80333458,'capture_entry':0x80330d98,
          'route':[{'pipe':0,'event':0x1006,'producer_site':0x80331298,'object_argument':'capture pointer in a2'},
                   {'pipe':4,'event':0x1014,'forwarder':0x80239fd4,'object_argument':'retains prior argument0'}],
          'creator_receive_window':0x8030980c,'creator':0x8030847c,
          'limits':['Capture entry has cyclic/alternate branches using10000038 and other completion paths;1006 is a reviewed branch, not universal.','Actual sensor completion, active object addresses and lifecycle ownership are not observed on camera.']},
         {'id':'capture.creator_to_compressor','status':'static-route-verified','creator':0x8030847c,
          'posted_marker_offset':0x2de,'producer_site':0x80308fe0,'producer_message':{'pipe':0,'event':0x1044,'argument0':'capture pointer','argument1':0},
          'server':0x8023f458,'forwarder':0x8023a030,'forwarded_message':{'pipe':7,'event':0x1042},
          'downstream':'saved-jpeg-path report follows FileCompressor receive to8031d0b4/8031aa5c and asynchronous saving.',
          'limits':['Creator sets+2de before queueing and skips an already marked object; post failure/error cleanup ownership remains incomplete.','Queued pointer lifetime does not become caller-owned merely because queue words are copied.']},
         {'id':'capture.pipe_message_ownership','status':'static-contract-partial','entry':0x801f5730,
          'arguments':'a0=pipe index,a1=event,a2/a3=two payload words','stack_record':'event,arg0,arg1,ffffffff as four LE32 words',
          'send':0x800cc868,'wait_argument':0xffffffff,'queue_offset_rule':'eventfffffffe uses pipe+40; ordinary events pipe+8',
          'return':'true when queue-send status0; missing/disabled pipe reports diagnostic and returnsfalse',
          'ownership':'Record contains words/pointer tokens only; no deep copy or transfer of referenced capture buffers is established.',
          'limits':['Pipe state, capacity, receiver completion and all error/timeout handling remain path dependent.','Internal pipe messages are not PTP operations or a supported command-construction interface.']}
        ],'remaining_gates':['Physical key/event producer and active Auto-mode state observation',
            'Chosen saved-photo hook pixel packing/stride/capacity and live allocation/cache ownership',
            'Complete control lifecycle, hook ABI/placement and general executable publication',
            'Complete installed backup and independent unbootable software recovery'],
        'safe_capture_adapter_established':False,'ready_for_executable_trial':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete/application')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/shutter-route.json')
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('Choose a new evidence path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as handle:json.dump(report,handle,indent=2);handle.write('\n')
    print(json.dumps({'contracts':len(report['contracts']),'native_dossiers':len(FUNCTIONS),
        'assertions':len(ASSERTIONS),'ready_for_executable_trial':False}))


if __name__=='__main__':main()
