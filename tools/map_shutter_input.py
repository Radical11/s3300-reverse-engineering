"""Source-bound scanner, debounce and logical shutter event investigation.

Pure observed-value models only; this module never reads MMIO or sends events.
"""
import argparse
import json
from pathlib import Path

from map_development_contracts import (ROOT,WORKSPACE,BASELINE,AddressMap,load_analysis,digest,
    Cs,CS_ARCH_MIPS,CS_MODE_MIPS32,CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS=(0x806a02bc,0x806a0574,0x806a109c,0x806a0b00,0x806a09a4,
    0x806a065c,0x806a12b8,0x806a0d04,0x8069e4d4,0x80212b90,0x80212d28,
    0x80212edc,0x806aa198,0x806a8a2c,0x80740280,0x8073f858,0x80707590,
    0x805ac03c,0x806ff834,0x806a0634,0x806ff7fc)
ASSERTIONS={
  0x806a02c4:('lui','$s1, 0xb002'),0x806a030c:('ori','$s4, $s1, 0x448'),
  0x806a0320:('lw','$fp, ($s4)'),0x806a0324:('ori','$t1, $s1, 0x44c'),
  0x806a0328:('sltiu','$t4, $fp, 1'),0x806a032c:('sll','$t3, $t4, 1'),
  0x806a0338:('lw','$t0, ($t1)'),0x806a0340:('sltiu','$s7, $t0, 1'),
  0x806a10b8:('jal','0x806a02bc'),0x806a10cc:('beq','$a2, $a0, 0x806a1130'),
  0x806a10dc:('beqz','$v0, 0x806a110c'),0x806a10ec:('beq','$a3, $t0, 0x806a1160'),
  0x806a10f0:('sb','$zero, -0x7b90($a1)'),0x806a1124:('sh','$a0, -0x7b8e($a2)'),
  0x806a112c:('sb','$v1, -0x7b90($a1)'),0x806a1164:('nor','$a3, $zero, $a2'),
  0x806a116c:('and','$a1, $a3, $a0'),0x806a1190:('nor','$t7, $zero, $a0'),
  0x806a1194:('and','$a0, $t7, $a2'),0x806a1198:('and','$t5, $a3, $t6'),
  0x806a11c4:('and','$s0, $a1, $v0'),0x806a1298:('jal','0x806a0b00'),
  0x806a12a8:('jal','0x806a09a4'),0x806a0c54:('addiu','$a0, $zero, 1'),
  0x806a0c64:('addiu','$a0, $zero, 2'),0x806a09b4:('andi','$v0, $v1, 2'),
  0x806a09c0:('andi','$a1, $v1, 1'),0x806a09c8:('addiu','$a0, $zero, 0x11'),
  0x806a0a80:('addiu','$a0, $zero, 0x12'),0x806a06a8:('andi','$t7, $t9, 0x1f'),
  0x806a06e0:('j','0x80212b90'),0x806a06e4:('addiu','$a0, $zero, 0x100'),
  0x806a12c0:('jal','0x806a109c'),0x806a12c8:('jal','0x806a0d04'),
  0x80212be8:('sw','$s1, 0x10($sp)'),0x80212bec:('jal','0x800cc868'),
  0x80212bf0:('sw','$s2, 0x14($sp)'),0x80212d90:('addiu','$a2, $zero, 2'),
  0x80212d94:('jal','0x800c1354'),0x80212f20:('jal','0x800c4334'),
  0x806aa1bc:('jal','0x80212edc'),0x806aa250:('jal','0x806a8a2c'),
  0x806a8ae0:('jal','0x80740280'),0x80740348:('j','0x8073f858'),
  0x8074034c:('or','$a0, $a3, $a2'),0x807401b0:('jal','0x80707590'),
  0x807075e0:('addiu','$t0, $zero, 0x112'),0x807075e4:('beq','$s0, $t0, 0x80707704'),
  0x807075f4:('addiu','$t2, $zero, 0x101'),0x807075f8:('beq','$s0, $t2, 0x807078d8'),
  0x80707718:('jal','0x806ff7fc'),0x8070771c:('sb','$zero, 0x36($t3)'),
}


def bounded(value,bits):
    if type(value)is not int or not 0<=value<(1<<bits):raise ValueError(f'Expected observed unsigned{bits}-bit value')
    return value


def snap_sample(register_448,register_44c):
    """Two source expressions on supplied register snapshots, not MMIO reads."""
    bounded(register_448,32);bounded(register_44c,32)
    return (int(register_448==0)<<1)|int(register_44c==0)


def debounce_step(previous,candidate,pending,current,press_mask,release_mask):
    """One scan of806a109c's acceptance/edge core; excludes side-effect calls."""
    for value in (previous,candidate,current,press_mask,release_mask):bounded(value,16)
    if type(pending)is not bool:raise ValueError('Pending candidate must be boolean')
    result={'previous':previous,'candidate':candidate,'pending':False,'accepted':False,'rising':0,'falling':0}
    if current==previous:return result
    if not pending:
        result.update(candidate=current,pending=True);return result
    if current!=candidate:return result
    result.update(previous=current,accepted=True,rising=(~previous&current&press_mask)&0xffff,
                  falling=(~current&previous&release_mask)&0xffff)
    return result


def snap_events(rising,falling):
    """Logical event IDs for only the two source-traced SNAP bits."""
    bounded(rising,16);bounded(falling,16)
    if (rising|falling)&~3:raise ValueError('Only SNAP bits1/2 are modeled')
    events=[]
    if rising&2:events.append(0x102)
    if rising&1:events.append(0x101)
    if falling&2:events.append(0x112)
    if falling&1:events.append(0x111)
    return events


def selected_view_handler(state):
    """Bounded known view-state arms, not the entire application dispatcher."""
    bounded(state,16)
    return {0x2050:0x80707590,0x2051:0x80704598,0x2060:0x806ff834,0x2068:0x80707234}.get(state)


def build_report(workspace,source,native):
    if digest(source.read_bytes())!=BASELINE:raise ValueError('Source identity differs')
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    checks=[]
    for address,expected in ASSERTIONS.items():
        rows=list(decoder.disasm(mapping.read(address,4),address))
        if len(rows)!=1 or(rows[0].mnemonic,rows[0].op_str)!=expected:raise ValueError(f'Instruction differs at{address:#x}')
        checks.append({'address':address,'sha256':digest(mapping.read(address,4))})
    corroboration=check_dossiers(native,mapping,digest(raw),FUNCTIONS)
    return {'schema_version':1,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
      'method':'Authenticated Capstone instruction checks and direct Ghidra dossiers; not REA Evidence',
      'target_executed':False,'camera_commands_issued':False,'instruction_assertions':checks,
      'native_corroboration':corroboration,'contracts':[
       {'id':'input.snap_scan','status':'static-contract-verified','scanner':0x806a02bc,
        'sampled_registers':[{'address':0xb0020448,'expression':'(u32read==0)<<1','normalized_bit':2},
                             {'address':0xb002044c,'expression':'u32read==0','normalized_bit':1}],
        'side_effects':'Scanner also configures and toggles GPIO matrix lines through800a1468/800a1580 and MMIO writes for other key bits; it is not a passive getter.',
        'limits':['Static register-zero interpretation is source-established; installed pad wiring, switch polarity and observed physical press correlation have not been measured.','No scanner or GPIO function is exposed as an SDK or invoked on the camera.']},
       {'id':'input.debounce_edges','status':'static-contract-verified','entry':0x806a109c,'periodic_caller':0x806a12b8,
        'periodic_parent':0x8069e4d4,'state':{'current':0x808d7454,'previous':0x808d7456,'press_enable':0x808d7458,'release_enable':0x808d745a,'candidate':0x80818472,'pending':0x80818470},
        'acceptance':'Changed state first becomes candidate. Matching state on the next pending scan accepts it; a different candidate clears pending without updating previous. Equal-to-previous clears pending.',
        'edge_rules':{'rising':'~previous & current & press_enable','falling':'~current & previous & release_enable'},
        'initialization':{'entry':0x806a0574,'press_enable':0,'release_enable':0x7000},
        'limits':['Enable masks are changed by mode lifecycle; initial masks do not enable both SNAP edge directions.','Logical scan-count behavior is established; physical sampling interval and debounce duration are not measured here.','Release/capture cancellation has additional state-specific behavior.']},
       {'id':'input.snap_event_encoding','status':'static-route-verified','rising_mapper':0x806a0b00,'falling_mapper':0x806a09a4,
        'event_poster':0x806a065c,'category':0x100,
        'events':[{'bit':2,'edge':'rising','low_id':2,'combined':0x102,'label':'SNAP1'},
                  {'bit':1,'edge':'rising','low_id':1,'combined':0x101,'label':'SNAP2'},
                  {'bit':2,'edge':'falling','low_id':0x12,'combined':0x112,'label':'SNAP1 release'},
                  {'bit':1,'edge':'falling','low_id':0x11,'combined':0x111,'label':'SNAP2 release'}],
        'label_corroboration':'805ac03c recognizes102 with MSG_KEY_SNAP1 diagnostic;806ff834 recognizes101 with GetSNAP2 diagnostic, alongside the checked bit/event mapping.',
        'serialization':'806a065c can defer low key IDs in32-word ring80816e08(index80816e94 wraps&1f), depending on pending-key count80816e98 and prior key8081846a; full press ID1 has a special pending-count rule.',
        'limits':['Map covers two SNAP bits, not arbitrary key combinations or FIFO overflow safety.','Internal event IDs are not USB/PTP commands or a supported event-injection API.']},
       {'id':'input.host_to_view_dispatch','status':'static-route-verified','host_send':0x80212b90,'host_queue':0x8010aba4,
        'queue_create':0x80212d28,'queue_message_words':2,'receiver':0x80212edc,
        'ui_receiver':0x806aa198,'ui_event_processor':0x806a8a2c,'mode_dispatcher':0x80740280,
        'message':'category100 plus low event ID; mode dispatcher combines argument words with OR',
        'view_family':'UI mode high nibble2000 reaches8073f858; exact2050 reaches80707590,2051 reaches80704598,2060 reaches806ff834,2068 reaches80707234.',
        'ownership':'Two scalar words are queued; no frame pointer or capture-buffer ownership is transferred by these key messages.',
        'constraints':['Host-send readiness/filter checks can drop a message; queue overflow asserts.','Receiver has optional callback filtering; a generated event is not a proof of delivery to a selected handler.','Current808921dc and callback/mask values are runtime-only.']},
       {'id':'input.capture_and_release_consumer','status':'static-route-partial','handler':0x80707590,'required_view_state':0x2050,
        'full_press':'101 reaches shared preparation arm807078d8. It can set2051/focus state or take later capture branches according to view-bank and runtime flags; full press is not unconditional directJPEG capture.',
        'half_release':'112 clears runtime UI/capture-state object(PTR808918a0)+36 and calls806ff7fc; that helper restores a temporary selection from80891812 when80891843 is set, then clears the flag.',
        'full_release':'111 does not enter the reviewed101/112 arms in this exact2050 handler; other view states have separate dispatch.',
        'downstream':'shutter-route report traces80706ca8 through AppSetMode and still queues into FileCompressor/JPEG.',
        'limits':['No general cancel-capture command or safe live state transition is established.','Physical key-to-live Auto branch remains unobserved; other focus/capture/sequence states are not all recovered here.']}
      ],'remaining_gates':['Installed key wiring/polarity and live scanner/mask/state correlation',
         'Complete mode-dependent focus/capture/release/cancellation ownership',
         'Chosen hook frame domain/stride/capacity/live cache ownership','Complete backup and independent software recovery'],
      'physical_shutter_runtime_verified':False,'safe_input_adapter_established':False,'ready_for_executable_trial':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete/application')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/shutter-input.json')
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('Choose a new evidence path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as handle:json.dump(report,handle,indent=2);handle.write('\n')
    print(json.dumps({'contracts':len(report['contracts']),'dossiers':len(FUNCTIONS),'assertions':len(ASSERTIONS),'ready_for_executable_trial':False}))


if __name__=='__main__':main()
