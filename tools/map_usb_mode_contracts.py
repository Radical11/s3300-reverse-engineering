"""Offline, source-bound USB mode/handle/descriptor contract map."""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT,WORKSPACE,BASELINE,AddressMap,
    load_analysis,digest,Cs,CS_ARCH_MIPS,CS_MODE_MIPS32,CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers
from build_resource_candidate import validate_chain

USB_RESOURCES={
    'UsbDevDesc.bin':('2a2c0a0de685e5753bec7d70afb13f4f1efbf8389337be1f2f12c30be245c1af',b'UsbDev~4bin'),
    'UsbModeDesc.bin':('3fc2b1df755428776bed09fcae5cc4b259847d980632067b3adfae12c7b6a3ed',b'UsbMod~7bin')}

FUNCTIONS=(0x8078bdac,0x8078bde0,0x8078be14,0x8077ec3c,0x807721f8,
    0x80772bfc,0x80772d34,0x80773144,0x80778304,0x8038a828,
    0x8038a644,0x807785c4,0x807787a0,0x80779318,0x8078fdbc,
    0x8078fa3c,0x8078dc8c,0x80777448,0x8078bd48,0x80771c68,
    0x8079c590,0x8077340c,0x806398d8,0x8069fcf8)
ASSERTIONS={0x8078bdc0:('addiu','$a0, $zero, 0x1a'),
    0x8078bdc4:('sll','$v1, $s0, 2'),0x8078bdcc:('lw','$v0, ($s0)'),
    0x8078be3c:('sw','$s1, ($s0)'),
    0x8038a8c0:('andi','$v1, $s2, 1'),
    0x8038a8cc:('sll','$ra, $v1, 7'),
    0x8038a8d0:('srl','$a1, $s2, 1'),
    0x8038a8dc:('or','$s1, $ra, $a1'),
    0x8038a8e8:('sb','$s1, 2($t0)')}


def endpoint_address(logical):
    """Pure encoding used by descriptor builder8038a828, not device access."""
    if not isinstance(logical,int)or not 0<=logical<=255:
        raise ValueError('Logical endpoint must be one byte')
    return ((logical&1)<<7)|(logical>>1)


def mode_contract(mode):
    """Only source-traced registrations; no request construction or switch."""
    if mode in (4,7):
        return {'mode':mode,'handle_slots':[4,7],'interface_classes':[6],
            'startup':'PTP','logical_endpoints':[2,3,5],
            'endpoint_addresses':[endpoint_address(x)for x in (2,3,5)]}
    if mode==6:
        return {'mode':6,'handle_slots':[6,5,0],'interface_classes':[0,8],
            'startup':'USB debug plus mass storage','logical_endpoints':[2,3,4,5],
            'endpoint_addresses':[endpoint_address(x)for x in (2,3,4,5)]}
    raise ValueError('Mode is outside this verified comparison')


def parse_usb_resource_rows(device, modes):
    """Parse only fields consumed by80772d34, without generating descriptors."""
    if len(device)!=6 or len(modes)!=48:
        raise ValueError('Expected baseline6-byte device and48-byte mode resources')
    vid,attributes,power,string_selector=struct.unpack('<HBBH',device)
    return {'device':{'vendor_id_default':vid,'config_attributes_default':attributes,
        'power_byte_default':power,'manufacturer_string_selector':string_selector},
        'mode_rows':[{'mode':i,'product_id_default':pid,
            'product_string_selector':product,'serial_string_selector':serial}
            for i,(pid,product,serial)in enumerate(struct.iter_unpack('<HHH',modes))]}


def resource_contract(source,evidence_path):
    metadata=json.loads(evidence_path.read_text())
    if metadata['input_sha256']!=BASELINE:
        raise ValueError('Resource extraction metadata belongs to another source')
    records=[];bodies={}
    for name,(expected_hash,short_name)in USB_RESOURCES.items():
        matches=[x for x in metadata['entries']if x['path']==name and x['kind']=='file']
        if len(matches)!=1:raise ValueError('Missing or duplicate USB resource')
        entry=matches[0];offset=entry['directory_entry_offset']
        if source[offset:offset+11]!=short_name:
            raise ValueError('Source directory short name differs')
        body=validate_chain(source,metadata,entry,expected_hash)
        bodies[name]=body
        records.append({'path':name,'sha256':digest(body),'size':len(body),
            'directory_entry_offset':offset,'start_cluster':entry['start_cluster'],
            'chunks':entry['chunks']})
    parsed=parse_usb_resource_rows(bodies['UsbDevDesc.bin'],bodies['UsbModeDesc.bin'])
    return {'id':'usb.descriptor_resource_defaults','status':'source-and-FAT-chain-verified',
        'metadata_sha256':digest(evidence_path.read_bytes()),'files':records,
        'parsed_consumed_fields':parsed,
        'consumer':0x80772d34,'row_rule':'mode*6, read6bytes',
        'overrides':'caps10 nonzero overrides VID; caps11 nonzero overrides PID; caps12 supplies bcdDevice; caps35<251 overrides a power-related local byte; string fields can use capability text',
        'limits':'defaults are not guaranteed live VID/PID or complete USB descriptors; supplied rows cover modes0..7 only'}


def build_report(workspace,source,native):
    source_bytes=source.read_bytes()
    if digest(source_bytes)!=BASELINE:raise ValueError('Source differs')
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
    checks=[]
    for address,expected in ASSERTIONS.items():
        instruction=list(decoder.disasm(mapping.read(address,4),address))
        if len(instruction)!=1 or(instruction[0].mnemonic,instruction[0].op_str)!=expected:
            raise ValueError(f'Instruction differs at{address:#x}')
        checks.append({'address':address,'bytes_sha256':digest(mapping.read(address,4))})
    native_check=check_dossiers(native,mapping,digest(raw),FUNCTIONS)
    resource=resource_contract(source_bytes,ROOT/'evidence/resource-filesystem.json')
    return {'schema_version':2,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
      'method':'authenticated Capstone plus direct Ghidra static analysis, not REA Evidence',
      'camera_commands_issued':False,'target_executed':False,'instruction_checks':checks,
      'native_corroboration':native_check,'modes':[mode_contract(x)for x in (4,7,6)],
      'contracts':[resource,
       {'id':'usb.handle_registry','status':'static-contract-verified',
        'getter':0x8078bdac,'caps_getter':0x8077ec3c,'caps_type':0x1a,
        'caps_base_pointer':0x80898d6c,'array_offset':0x35c,
        'rule':'read32(*(u32*)80898d6c+35c+4*slot)',
        'setter':0x8078be14,'setter_role':'write supplied handle into same slot array',
        'controller_getter':0x8078bde0,'controller_getter_role':'slot handle then80389b94 dereferences its first word',
        'limits':'slots are registration identifiers, not USB endpoints; aliases are assigned per mode'},
       {'id':'usb.ptp_mode_registration','status':'static-contract-verified',
        'registration':0x807721f8,'modes':[4,7],'aliased_slots':[4,7],
        'descriptor_switch':0x80772bfc,'interface_builder':0x80778304,
        'interface':[6,1,1],'endpoints':[{'logical':x,'address':endpoint_address(x)}for x in (2,3,5)],
        'packet_sizes':'bulk512 if speed argument1, otherwise64; interrupt8 interval16',
        'receive_entry':0x807785c4,'send_entry':0x807787a0,'data_send':0x80779318,
        'transport_handle_slot':4,'response_logical_selector':3,
        'runtime_comparison':'observed class6/sub1/proto1 and01/81/82 match this branch; cannot distinguish mode4 versus7'},
       {'id':'usb.debug_mode_registration','status':'static-contract-verified',
        'registration':0x807721f8,'mode':6,'aliased_slots':[6,5,0],
        'startup':0x8078fdbc,'thread':0x8078fa3c,'startup_handle_slot':6,
        'debug_transport_handle_slot':0,'mass_storage_handle_slot':5,
        'descriptor_switch':0x80772bfc,'descriptor_builders':[0x8078dc8c,0x80777448],
        'interfaces':'class0 interface0 with logical2/3 plus class8 mass-storage interface1 logical4/5',
        'comparison':'different mode registration and descriptor composition from PTP; common low-level USB transfer functions do not prove debug handler active under PTP'},
       {'id':'usb.endpoint_descriptor_encoding','status':'static-contract-verified',
        'address':0x8038a828,'rule':'((logical&1)<<7)|(logical>>1)',
        'scope':'descriptor byte encoding verified; this does not establish handler reachability on the live camera'},
       {'id':'usb.mode_selection','status':'partial','request_wrapper':0x80771c68,
        'message_sender':0x8078bd48,'message':'queue2 code100000 with mode byte',
        'message_consumer':0x8077340c,'mode_switch':0x80773144,
        'ptp_ui_caller':0x806398d8,'ptp_ui_mode':7,
        'ptp_ui_evidence':'PtpMode_CardReIn diagnostic and calls80771c68(7)',
        'diagnostic_caller':0x8079c590,'diagnostic_role':'passes subcommand to same mode wrapper; debug activation prerequisite not resolved',
        'initial_default':{'routine':0x8069fcf8,'value':0},
        'unknowns':['active RAM mode4 versus7','verified physical/UI entry to mode6','complete mode-switch ownership and disconnect lifecycle','whether vendor setup handling coexists with PTP elsewhere']}],
      'runtime_reference':'evidence/camera-usb-verification-2026-10-25.json',
      'runtime_evidence_policy':'parent-maintained read-only observations; no local device query performed by this mapper',
      'gates':{'debug_reachable_in_observed_ptp_configuration':False,
        'software_unbootable_recovery_verified':False,'code_trial_allowed':False},
      'limitations':['Descriptors establish advertised configuration, not absence of all vendor requests on endpoint0.',
        'No generic packet switch, mode request, alternate configuration or driver change is attempted.',
        'No exact installed image identity is inferred from V1.1 or matching descriptors alone.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete/application')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/usb-mode-contracts.json')
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('Choose a new output path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8')as handle:json.dump(report,handle,indent=2);handle.write('\n')
    print(json.dumps({'contracts':len(report['contracts']),'native_dossiers':len(FUNCTIONS),'code_trial_allowed':False}))


if __name__=='__main__':main()
