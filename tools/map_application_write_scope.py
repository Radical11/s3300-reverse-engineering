"""Check the application NAND writer independently of the updater namespace.

Focused direct Ghidra output is caller-seeded and retains its inference warning.
No camera operation, request, patch or hardware emulation is performed.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers
from map_updater_handoff import u32

FOCUS=ROOT/'derived/application-writer-focus-2026-10-25'
FUNCTIONS=(0x803d6520,0x803d6558,0x803d65d0,0x803d6878,0x803d6990,0x803d6b30,
    0x803d6c88,0x803d7100,0x803e17bc,0x803e1c28,0x80064744,0x80063aec,0x80062688,0x803e26b0)
ASSERTIONS={
    0x803d740c:('lw','$t3, 0x1250($a0)'),
    0x803d7424:('lbu','$a3, 0x1272($s5)'),
    0x803d7428:('lbu','$s4, 0x1264($s5)'),
    0x803d7430:('lbu','$t0, 0x1273($s5)'),
    0x803d7440:('lw','$s6, 0x1240($s5)'),
    0x803d766c:('jal','0x803d6c88'),
    0x803d777c:('addiu','$t9, $zero, 1'),
    0x803d7784:('lw','$t8, 8($v0)'),
    0x803d77ac:('beqz','$t8, 0x803d8cbc'),
    0x803d7d7c:('jal','0x803e1c28'),
    0x803d7f30:('beq','$s4, $t6, 0x803d9338'),
    0x803d8438:('jal','0x803d65d0'),
    0x803d8444:('bne','$v0, $v1, 0x803d877c'),
    0x803d8454:('lbu','$t6, 0x20($s2)'),
    0x803d8458:('beq','$t6, $v1, 0x803d8528'),
    0x803d8680:('jal','0x80064744'),
    0x803d8708:('jal','0x803d6b30'),
    0x803d8748:('jal','0x80064744'),
    0x803d94bc:('addiu','$a1, $zero, 5'),
    0x803d94d0:('jal','0x80064744'),
    0x803d9364:('addiu','$a1, $zero, 8'),
    0x803d9374:('jal','0x80064744'),
    0x803d9394:('jal','0x803d6878'),
    0x803d95d4:('jal','0x803d7100'),
    0x803d6560:('lw','$a3, 0x314($a0)'),
    0x803d656c:('lbu','$v0, 0x234($a0)'),
    0x803d6574:('lw','$a2, 0x310($a0)'),
    0x803d658c:('addu','$a3, $a3, $a2'),
    0x803d6590:('addiu','$a3, $a3, -1'),
    0x803d6610:('jal','0x803d6558'),
    0x803d6624:('lbu','$a0, 0xf9($s5)'),
    0x803d6734:('lbu','$t5, 0x21($a2)'),
    0x803d6ae4:('beq','$t4, $t3, 0x803d6b18'),
    0x803d6b20:('jal','0x803d6878'),
    0x803d6540:('jal','0x80064744'),
    0x803e188c:('lbu','$t0, 0x1270($t1)'),
}


def observed_byte(value):
    if type(value) is not int or not 0<=value<=255: raise ValueError('Expected an observed byte')
    return value


def section_protected(section,reserved,burn,upgrade,keep_section3):
    """803e17bc's flags, not physical write protection."""
    if type(section) is not int or not 0<=section<=6: raise ValueError('Reviewed sections are0..6')
    reserved,burn=u32(reserved),u32(burn)
    upgrade,keep_section3=observed_byte(upgrade),observed_byte(keep_section3)
    if section==3: return upgrade==1 and keep_section3==1
    if section==6: return upgrade==1 and burn==0
    return reserved!=0 and burn==0


def old_user_extent_contains(first,count,upgrade,unit):
    """803d6558's inclusive old-header unit predicate, with32-bit arithmetic."""
    first,count,unit=u32(first),u32(count),u32(unit)
    upgrade=observed_byte(upgrade)
    return count!=0 and upgrade!=0 and first<=unit<=((first+count-1)&0xffffffff)


def update_policy(header,upgrade):
    """Describe observed header flags without approving writes or preservation."""
    if not isinstance(header,bytes) or len(header)!=64: raise ValueError('Exactly64 observed header bytes required')
    upgrade=observed_byte(upgrade)
    flags={name:struct.unpack_from('<I',header,offset)[0]&255 for name,offset in
        (('full_erase',0x1c),('keep_section3',0x24),('relocate_user',0x2c),('user_placement',0x30))}
    return {**flags,'upgrade':upgrade,'pre_burn_relocation_selected':flags['relocate_user']==1 and flags['user_placement']==0,
        'full_erase_selected':flags['full_erase']==1,'complete_calibration_preservation_proven':False}


def build_report(workspace,source,native,focus=FOCUS):
    body=source.read_bytes()
    if digest(body)!=BASELINE: raise ValueError('Source identity differs')
    manifest,raw=load_analysis(workspace);mapping=AddressMap(raw,manifest['regions'])
    profile_path=focus/'provenance.json';profile=json.loads(profile_path.read_text())
    if (profile.get('source_sha256')!=BASELINE or profile.get('analysis_sha256')!=digest(raw)
            or profile.get('returncode')!=0 or profile.get('target_executed') is not False
            or profile.get('retained_application_project_modified') is not False
            or profile.get('tools',{}).get('versions')!={'ghidra':'12.1.4','jdk':'21.0.9+10'}):
        raise ValueError('Focused application analysis identity/scope differs')
    for name,expected in profile['scripts'].items():
        if name not in ('S3300Seed.java','S3300Export.java') or digest((ROOT/'tools/ghidra'/name).read_bytes())!=expected:
            raise ValueError('Focused exporter script differs')
    focused=check_dossiers(focus/'application',mapping,digest(raw),(0x803d73dc,))
    retained=check_dossiers(native/'application',mapping,digest(raw),FUNCTIONS)
    writer=json.loads((focus/'application/functions/803d73dc.json').read_text())
    decoder=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN);checks=[]
    for address,expected in ASSERTIONS.items():
        code=mapping.read(address,4);items=list(decoder.disasm(code,address))
        if len(items)!=1 or (items[0].mnemonic,items[0].op_str)!=expected:
            raise ValueError(f'Application write instruction differs at{address:#x}')
        checks.append({'address':address,'instruction_sha256':digest(code)})
    policy=update_policy(body[0x100000:0x100040],body[0x1000c0+0x234])
    return {'schema_version':1,'source_sha256':BASELINE,'analysis_sha256':digest(raw),
        'address_namespace':'application; no updater-address substitution',
        'method':'Authenticated carrier, retained/focused direct Ghidra dossiers and independent Capstone assertions; not REA Evidence',
        'target_executed':False,'camera_commands_issued':False,'instruction_checks':checks,
        'native_corroboration':{'retained':retained,'focused_writer':focused},
        'focused_analysis':{'provenance_sha256':digest(profile_path.read_bytes()),
            'directory':str(focus.relative_to(ROOT)).replace('\\','/') if focus.is_relative_to(ROOT) else str(focus),
            'native_tool_versions':profile['tools']['versions'],'exporter_hashes':profile['scripts'],
            'entry':0x803d73dc,'ranges_observed':writer['ranges'],
            'boundary_scope':'Caller-seeded from authenticated callback; neighboring function entry limits body, not an authenticated unwind range',
            'inference_warning':'Type propagation algorithm not settling; inferred C pointer/integer types are incomplete',
            'existing_application_project_modified':False},
        'supplied_package_policy':policy,
        'contracts':[
          {'id':'application_update.actual_writer','status':'static-route-partial','address':0x803d73dc,
           'arguments':'a0burn handle,a1input callback table; handle1240 erase sectors,1244 total sectors,1250 chunk bytes,1254/1258 buffers',
           'behavior':'Uses application map builder803e1c28 and application operation wrapper80064744; body spans caller-seeded803d73dc..803d9fb7 in focused Ghidra',
           'limit':'A matching family of algorithms exists in the separate updater, but addresses/callbacks and metadata paths are different. No installed geometry or complete write bound is inferred.'},
          {'id':'application_update.protection_and_relocation','status':'predicate-and-route-partial',
           'section_predicate':0x803e17bc,'block_predicate':0x803d65d0,'old_user_extent_predicate':0x803d6558,
           'section_flags':'Seven 0x24-byte (36-byte) records; protected byte+0x21. Section3 requires upgrade1+handle1270==1; section6 upgrade1+zero burn; other sections reserved nonzero+zero burn.',
           'old_extent':'Header310 first unit,314 count,234 nonzero: inclusive first..low32(first+count-1). Only used as protected user extent when section6 protected flag is1.',
           'logical_extent':'Spare-derived logical unit is compared with protected section0..5 starts/reservations under runtime zone geometry; parity and geometry decoding precede the test.',
           'writer_control':'Zero burn sectors skips section main-body consumption; metadata/finalization still execute. A protected unit normally advances to another unit, but current section flag20==1 can select relocation before programming.',
           'limit':'Protected flags do not prove that every physical block or all calibration remains untouched; relocation, full erase, bad-block marks and header/table rewriting must be accounted separately.'},
          {'id':'application_update.mutation_routes','status':'static-route-verified',
           'full_erase':'Handle1264==1 selects operation8 loop below total blocks minus tail backup reservation; failures may mark blocks bad',
           'user_relocation':'Handle1272==1 and1273==0 selects803d6c88 before burning and803d7100 restore afterward; both erase/program flash',
           'ordinary_burn':'Operation5 programming through803d6b30 followed by operation4 read/compare; failures may call803d6878',
           'finalization':'Writer may erase/program boot headers, recovery metadata and extended bad-block tables after section bodies',
           'known_package':'Upgrade byte1; keep-section3 flag1; full-erase flag0 and pre-burn-relocation flag0. These are package policy fields, not installed-state observations.'},
          {'id':'application_update.read_helpers_are_not_backup_api','status':'state-changing-route-verified',
           'bad_block_checker':0x803d6990,'mark_bad':0x803d6878,'spare_read':0x803d6520,
           'behavior':'803d6990 checks two geometry-selected spare locations and can call803d6878 when decoded status requests marking. Marking programs spare/status metadata with operation7.',
           'read_wrapper':'80064744 selects alternate backend80062688 for operation4 when global80069905==1; otherwise uses80063aec. Operation4 can return ECC-corrected bytes; spare words undergo geometry/bus-width transforms.',
           'limit':'No passive host backup route, raw NAND/ECC representation or complete address/length bounds established. Do not invoke a getter/checker by name as a read-only camera operation.'}],
        'gates':{'application_writer_static_path':True,'physical_write_ranges_complete':False,
            'calibration_preservation_complete':False,'passive_host_backup_verified':False,
            'software_unbootable_recovery_verified':False,'executable_trial_allowed':False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--focus',type=Path,default=FOCUS)
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/application-write-scope.json')
    args=parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose an unused evidence path')
    report=build_report(args.workspace,args.source,args.native,args.focus)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream: json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'instruction_assertions':len(ASSERTIONS),'retained_dossiers':len(FUNCTIONS),
        'new_focused_writer':True,'executable_trial_allowed':False}))


if __name__=='__main__': main()
