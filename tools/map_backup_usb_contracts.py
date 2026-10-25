"""Authenticate USB setup routing and the boundary of a software backup route.

Offline only: no USB transport, request builder, camera adapter or state change.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x80389888, 0x8038b6f4, 0x803908b4, 0x8038d38c,
    0x8038d420, 0x8038d90c, 0x8038e3ac, 0x8038e3d0,
    0x80796310, 0x80796424, 0x8079651c, 0x807769b4,
    0x80796108, 0x8077f204, 0x80782120, 0x8077f08c, 0x8077f0c8,
    0x8077b474, 0x8077b9d4, 0x8077b320)
WINDOWS = (
    ('controller0_setup_callback_registration', 0x803907c4, 0x14),
    ('controller0_attach_setup_buffer', 0x803908b4, 0x40),
    ('driver_setup_buffer_alias', 0x8038b93c, 0x14),
    ('setup_interrupt_copy_and_callback', 0x8038c8ac, 0xac),
    ('setup_classification_callback', 0x8038d4ac, 0x12c),
    ('standard_device_info_handler', 0x8077fe68, 0x19c),
    ('ptp_ascii_to_string_serializer', 0x8077b320, 0xd8),
)
ASSERTIONS = {
    0x803907c8: ('addiu', '$a2, $t4, -0x2b54'),
    0x803907d0: ('jal', '0x8038e3d0'),
    0x803907d4: ('move', '$a1, $zero'),
    0x803908d8: ('jal', '0x8038b6f4'),
    0x803908dc: ('lw', '$a0, 0x18($s0)'),
    0x8038b948: ('sw', '$fp, 0x40($s2)'),
    0x8038c8b8: ('lw', '$a2, 0x24($s0)'),
    0x8038c8d4: ('lw', '$v0, 0x28($a3)'),
    0x8038c8d8: ('sw', '$v0, ($a2)'),
    0x8038c8dc: ('lw', '$ra, 0x2c($a3)'),
    0x8038c8e0: ('sw', '$ra, 4($a2)'),
    0x8038c934: ('lw', '$v1, 0x140($s7)'),
    0x8038c94c: ('jalr', '$v1'),
    0x8038d4d8: ('ext', '$s1, $v0, 5, 2'),
    0x8038d4e0: ('jal', '0x8038a044'),
    0x8038d4e8: ('bnez', '$s0, 0x8038d538'),
    0x8038d4f4: ('beq', '$v0, $a0, 0x8038d554'),
    0x8038d50c: ('addiu', '$a1, $zero, 0x200'),
    0x8038d52c: ('addiu', '$a1, $zero, 0x400'),
    0x8038d568: ('addiu', '$s4, $zero, 0x200'),
    0x8038d5a0: ('addiu', '$s4, $zero, 0x400'),
    0x8038d5bc: ('jal', '0x8038f080'),
    0x8038d5cc: ('addiu', '$s4, $zero, 0x100'),
    0x8077fecc: ('jal', '0x80020980'),
    0x8077fed8: ('jal', '0x8077f0c8'),
    0x8077fef0: ('jalr', '$a1'),
    0x8077fefc: ('jal', '0x8077b474'),
    0x8077ffd0: ('addiu', '$v0, $zero, 0x2001'),
    0x8077f284: ('addiu', '$ra, $v0, -0x198'),
    0x8077f294: ('addiu', '$v1, $zero, 0x1001'),
    0x8077f298: ('sw', '$ra, 8($a3)'),
    0x8077f2d0: ('addiu', '$t9, $ra, 0x2120'),
    0x8077f2e0: ('addiu', '$v0, $zero, 0x1005'),
    0x8077f314: ('sh', '$v0, 0x30($a3)'),
    0x8077f318: ('sw', '$t9, 0x38($a3)'),
    0x80796354: ('addiu', '$a3, $zero, 6'),
    0x8079637c: ('andi', '$v1, $a1, 1'),
    0x80796380: ('bnez', '$v1, 0x8079640c'),
    0x807963a0: ('lbu', '$t3, 3($s1)'),
    0x807963a8: ('lbu', '$t2, 2($s1)'),
    0x8077b354: ('andi', '$v0, $v0, 0xff'),
    0x8077b364: ('addiu', '$s0, $v0, 1'),
    0x8077b368: ('sb', '$s0, ($s1)'),
    0x8077b36c: ('addiu', '$a2, $a2, 2'),
    0x8077b390: ('lbu', '$a0, ($a2)'),
    0x8077b398: ('slti', '$t1, $a3, 0xff'),
    0x8077b3a0: ('sb', '$a0, 1($a1)'),
}


def _byte(value):
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError('Expected an observed unsigned byte')
    return value


def setup_event_mask(request_type, logical_endpoint, endpoint_status, *, standard_handled=False):
    """Attempted8038d4ac events before handle+2c filtering, not acceptance."""
    request_type = _byte(request_type)
    if type(logical_endpoint) is not int or logical_endpoint < 0:
        raise ValueError('Expected a nonnegative logical selector')
    if type(endpoint_status) is not int or not 0 <= endpoint_status <= 255:
        raise ValueError('Expected an endpoint status byte')
    if logical_endpoint != 0:
        return 0
    if endpoint_status != 1:
        return 0x600
    kind = request_type >> 5 & 3
    if kind == 1:
        return 0x400
    if kind == 2:
        return 0x200
    if kind == 0 and not standard_handled:
        return 0x100
    return 0


def setup_wait_mask(flags):
    flags = _byte(flags)
    return ((flags & 1) << 8) | (0x200 if flags & 4 else 0) | (0x400 if flags & 2 else 0)


def inspect_observed_setup(setup, *, disconnect_pending=False):
    """Decode observed bytes only; this helper never constructs a USB request."""
    if not isinstance(setup, (bytes, bytearray)) or len(setup) != 8:
        raise ValueError('Expected exactly eight observed setup bytes')
    request_type, request, value, index, length = struct.unpack('<BBHHH', setup)
    route = ('stop' if disconnect_pending else
             'mass-storage-class-handler' if request_type & 1 else 'debug-dispatch-candidate')
    return {'request_type':request_type, 'request':request, 'value':value,
        'index':index, 'length':length, 'route':route,
        'internal_index':None if route != 'debug-dispatch-candidate' else setup[3],
        'subcommand':None if route != 'debug-dispatch-candidate' else setup[2],
        'zero_length_status_before_dispatch': route == 'debug-dispatch-candidate' and length == 0,
        'host_to_device_control_length_exceeds_dispatch_buffer': not bool(request_type & 0x80) and length > 0x2000,
        'safe_host_request':False}


def ptp_string_extent(ascii_length):
    """Arithmetic of8077b320, not a public serializer or request generator."""
    if type(ascii_length) is not int or not 0 <= ascii_length <= 0xffffffff:
        raise ValueError('Expected an unsigned32-bit observed ASCII strlen')
    low = ascii_length & 255
    if low == 0:
        return {'wire_count':0, 'copied_low_bytes':0, 'zero_fill_bytes':0,
                'full_input_and_terminator_represented':ascii_length == 0}
    count = low + 1
    return {'wire_count':count & 255, 'copied_low_bytes':min(count,255),
            'zero_fill_bytes':2 * count,
            'full_input_and_terminator_represented':ascii_length <= 254}


def build_report(workspace, source_path, native):
    source = Path(source_path).read_bytes()
    if digest(source) != BASELINE:
        raise ValueError('Unsupported source identity')
    manifest, raw = load_analysis(Path(workspace))
    mapping = AddressMap(raw, manifest['regions'])
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    assertions = []
    for address, expected in ASSERTIONS.items():
        decoded = list(decoder.disasm(mapping.read(address,4),address))
        if len(decoded) != 1 or (decoded[0].mnemonic,decoded[0].op_str) != expected:
            raise ValueError(f'Authenticated instruction differs at{address:#x}')
        assertions.append({'address':address,'bytes':mapping.read(address,4).hex(),
                           'instruction':expected[0]+' '+expected[1]})
    windows = []
    for label,address,size in WINDOWS:
        body = mapping.read(address,size)
        decoded = list(decoder.disasm(body,address))
        if sum(row.size for row in decoded) != size:
            raise ValueError('Incomplete independent bounded decode')
        windows.append({'label':label,'address':address,'bytes':size,'sha256':digest(body),
                        'instructions':len(decoded),'boundary':'Bounded analyst window, not an authenticated function boundary'})
    proof = check_dossiers(Path(native),mapping,digest(raw),FUNCTIONS)
    warnings = []
    for address in FUNCTIONS:
        path=Path(native)/'functions'/f'{address:08x}.json'
        dossier=json.loads(path.read_text(encoding='utf-8'))
        text=dossier.get('pseudocode') or ''
        if 'WARNING' in text:
            warnings.append({'address':address,'dossier_sha256':digest(path.read_bytes()),
                'warning_present':True,'scope':'Retained decompiler warning; byte-level assertions take precedence over inferred C'})
    return {'schema_version':1,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
        'image_namespace':'application','method':'Authenticated Capstone/raw windows and direct Ghidra; not REA Evidence',
        'camera_commands_issued':False,'target_executed':False,'rea_evidence':False,
        'instruction_assertions':len(assertions),'instruction_checks':assertions,
        'reviewed_windows':windows,'native_corroboration':proof,'retained_warnings':warnings,
        'contracts':[
            {'id':'backup.usb_original_setup_provenance','status':'static-route-verified',
             'arguments':'Controller0 attach803908b4 loads state+18 setup-buffer pointer into driver8038b6f4',
             'ownership':'State allocated by80389888; driver stores the same pointer at state+40; hardware ISR writes the buffer',
             'route':'8038b948 state+40 alias;8038c8d4..e0 copies two original controller words from queue+28/+2c;8038c94c calls state+140 callback',
             'registration':'803907c8..d4 installs callback8038d4ac through8038e3d0(controller0,kind0);8038d90c copies eight bytes from state+18',
             'side_effects':'Interrupt acknowledgement and setup-state transitions; not host-passive execution',
             'constraints':'Original eight-byte layout is preserved, not a normalized request header. Installed driver/mode not observed; concurrent setup ownership unresolved.',
             'failed_analysis':'Ghidra8038b6f4 marks post-MMIO-loop blocks unreachable; raw original instructions retain the conditional exits and state+40 store separately'},
            {'id':'backup.usb_setup_classification','status':'static-contract-verified',
             'entry':0x8038d4ac,'arguments':'a0 handle,a1 logical endpoint,a2 original setup pointer; logical0 is reviewed',
             'classification':'bmRequestType bits5..6: standard0,class1,vendor2,reserved3',
             'events':{'standard_unhandled':0x100,'vendor':0x200,'class':0x400,'nonready_endpoint0_wakeup':0x600},
             'return_behavior':'Other logical endpoints return; standard handlers may consume a request; event signaling also depends on enabled handle mask at+2c',
             'constraints':'This callback has no bRequest/wIndex allowlist for class/vendor. That bounded absence is not proof that every request reaches installed application debug mode.'},
            {'id':'backup.usb_debug_request_gate','status':'partial',
             'entry':0x80796310,'wait_flags':6,'wait_mask':0x600,
             'route':'After wait and disconnect check, bmRequestType bit0==0 forwards byte3/index and byte2/subcommand; bit0==1 calls mass-storage807769b4 and loops',
             'constraints':'Recipient parity is the actual checked expression; do not replace it by a complete USB recipient allowlist. bRequest and wIndex are not inspected by this reader.',
             'side_effects':'Zero-length forwarded requests issue control status before dispatch; receive/send helpers use setup direction/length and may complete status phases',
             'bounds':'Dispatcher80796108 allocates2000bytes. Host-to-device control receive8079651c takes the unsigned16-bit setup length without a demonstrated2000-byte cap; legal command/address/length sequence remains unverified.',
             'ownership':'One shared808c8568 setup record; queueing and setup lifetime require an end-to-end sequencing contract',
             'callers':'Application mode0/6 debug control loop; current PTP descriptor match does not establish this registration'},
            {'id':'backup.standard_ptp_metadata_handlers','status':'static-contract-partial',
             'registry':0x8077f204,'route':0,'data_phase':1,
             'device_info':{'opcode':0x1001,'handler':0x8077fe68,'behavior':'Allocates temporary supported-opcode list;callback80748f68 fills metadata;serializer8077b474;frees temporaries;response2001'},
             'storage_info':{'opcode':0x1005,'handler':0x80782120,'behavior':'Validates10001/20001 storage selection;queries device/media metadata and capacity;serializer8077b9d4;invalid storage2008/no media2013'},
             'side_effects':'Allocation, runtime metadata queries and response construction. No explicit NAND-program/erase call in these reviewed direct handler windows.',
             'constraints':'Not raw memory/flash backup. Full transitive media-driver side effects and installed correspondence are not proved; StorageInfo has retained unreachable-code decompiler warnings.'}],
        'ptp_string_contract':{'entry':0x8077b320,'storage_info_serializer':0x8077b9d4,
            'behavior':'ASCII strlen low8; nonempty length+1 stored as count byte; zero2*(low8 length+1)bytes; copy successive ASCII low bytes into UTF16LE low-byte positions, includingNUL for ordinary length<=254',
            'storage_info_layout':'Fixed26numeric bytes;description begins at1a;volume label follows at1b+2*description_count',
            'example':'Ordinary ASCII S3300 has length5, stored count6 and a terminating UTF16NUL under this baseline helper',
            'bounds':'At strlen low8==255 count256 truncates to0 and copy loop is capped255; low8==0 serializes an empty string. Not a general Unicode or arbitrary-length API.',
            'reconciliation':'An observed count5 followed by unterminated S3300 is not explained by this baseline helper. Preserve strict-decoder failure and numeric prefix separately; installed bytes, input provenance and transport transformation remain unresolved.'},
        'search_boundary':f'{len(FUNCTIONS)} native dossiers plus{len(WINDOWS)} bounded original windows and{len(ASSERTIONS)} selected instruction assertions; application namespace only; no full-program proof of reachability or passivity',
        'gates':{'safe_installed_memory_read_bridge':False,'complete_backup':False,
                 'reset_independent_software_recovery':False,'executable_trial_allowed':False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete/application')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/backup-usb-contracts.json')
    args=parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose an unused output path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'instruction_assertions':len(ASSERTIONS),'dossiers':len(FUNCTIONS),
                      'complete_backup':False,'camera_accessed':False}))


if __name__=='__main__': main()
