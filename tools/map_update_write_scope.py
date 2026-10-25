"""Authenticate updater section/write behavior without executing the updater.

All addresses belong to the separate ELF at carrier offset0x200. Pure models
describe reviewed arithmetic and flags, never safe device-operation recipes.
"""
import argparse
import json
from pathlib import Path

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, digest, Cs,
    CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import ElfBytes, check_dossiers

FUNCTIONS = (0x8001a07c, 0x8001a3d0, 0x8001a4e8, 0x80012e84,
    0x80012730, 0x80012ba8, 0x80012370, 0x80012258, 0x80012510,
    0x8007e2c0, 0x8007d668, 0x8001af70, 0x8001b300)
ASSERTIONS = {
    0x8001a0c8: ('beq', '$s0, $v0, 0x8001a134'),
    0x8001a0d4: ('beql', '$s0, $a2, 0x8001a160'),
    0x8001a148: ('lw', '$t1, -0x2858($t2)'),
    0x8001a14c: ('lbu', '$t0, 0x1270($t1)'),
    0x8001a134: ('lbu', '$a2, 0x234($s3)'),
    0x8001a16c: ('lw', '$t5, 8($s1)'),
    0x8001a45c: ('divu', '$zero, $t2, $t1'),
    0x8001a470: ('addiu', '$a3, $t0, -1'),
    0x8001a474: ('divu', '$zero, $a3, $a1'),
    0x8001a484: ('mul', '$s2, $a2, $a1'),
    0x8001a7e4: ('subu', '$s5, $s3, $ra'),
    0x8001a7e8: ('addu', '$s2, $t9, $s5'),
    0x8001275c: ('lw', '$s4, 0x1240($a1)'),
    0x80012760: ('lw', '$a3, 0x1244($a1)'),
    0x80012938: ('addiu', '$a1, $zero, 8'),
    0x80012948: ('jal', '0x8007e2c0'),
    0x80012a04: ('addiu', '$a1, $zero, 5'),
    0x80012a18: ('jal', '0x8007e2c0'),
    0x80012a2c: ('addiu', '$a1, $zero, 4'),
    0x80012a3c: ('jal', '0x8007e2c0'),
    0x80012308: ('addiu', '$a1, $zero, 7'),
    0x8001231c: ('jal', '0x8007e2c0'),
    0x80012500: ('jal', '0x80012258'),
    0x80012558: ('addiu', '$a1, $zero, 5'),
    0x80012570: ('jal', '0x8007e2c0'),
    0x800125c8: ('addiu', '$a1, $zero, 4'),
    0x800125d4: ('jal', '0x8007e2c0'),
    0x80013114: ('jal', '0x80012730'),
    0x80013824: ('jal', '0x8001a4e8'),
    0x8001322c: ('lw', '$t8, 8($v0)'),
    0x80013254: ('beqz', '$t8, 0x80014764'),
    0x8001507c: ('jal', '0x80012ba8'),
}
U32 = 0xffffffff


def u32(value):
    if type(value) is not int or not 0 <= value <= U32:
        raise ValueError('Expected an unsigned32-bit observation')
    return value


def section_protected(section, total_sectors, burn_sectors, upgrade, keep_user_area):
    """Exact IsSectionProtected predicate, not a write protection guarantee."""
    if type(section) is not int or not 0 <= section <= 6: raise ValueError('Reviewed sections are0..6')
    total_sectors, burn_sectors = u32(total_sectors), u32(burn_sectors)
    for flag in (upgrade, keep_user_area):
        if type(flag) is not int or not 0 <= flag <= 255: raise ValueError('Flags must be observed bytes')
    if section == 3: return upgrade == 1 and keep_user_area == 1
    if section == 6: return upgrade == 1 and burn_sectors == 0
    return total_sectors != 0 and burn_sectors == 0


def recover_extent(main, size, alternate_size, sector_bytes, erase_sectors):
    """InitRecoverSection's wrapping sum, floor division and ceil alignment."""
    values = [u32(x) for x in (main, size, alternate_size, sector_bytes, erase_sectors)]
    main, size, alternate_size, sector_bytes, erase_sectors = values
    if not sector_bytes or not erase_sectors: raise ValueError('Target divides by zero')
    mathematical_sum = main + size + alternate_size
    sectors = (mathematical_sum & U32) // sector_bytes
    numerator = (erase_sectors + sectors - 1) & U32
    total = ((numerator // erase_sectors) * erase_sectors) & U32
    return {'burn_sectors': sectors, 'reserved_sectors': total,
            'header_sum_wrapped': mathematical_sum > U32,
            'rounding_add_wrapped': erase_sectors + sectors - 1 > U32,
            'scope': 'package arithmetic only; no installed geometry or safe write range inferred'}


def boundary_padding(start, boundary):
    """Observed boundary-start%boundary: aligned starts still gain one unit."""
    start, boundary = u32(start), u32(boundary)
    if not boundary: raise ValueError('Target divides by zero')
    padding = boundary - start % boundary
    return {'padding_sectors': padding, 'aligned_start': (start + padding) & U32,
            'wrapped': start + padding > U32}


def backup_geometry(requested_user_sectors, total_sectors, erase_sectors):
    """NandUserAreaBackup allocation arithmetic; no operation sequence emitted."""
    requested_user_sectors, total_sectors, erase_sectors = [u32(x) for x in
        (requested_user_sectors, total_sectors, erase_sectors)]
    if not erase_sectors: raise ValueError('Target divides by zero')
    blocks = requested_user_sectors // erase_sectors
    mathematical_bytes = blocks * erase_sectors * 512
    return {'selected_good_blocks': blocks, 'nominal_total_blocks': total_sectors // erase_sectors,
        'requested_sector_remainder': requested_user_sectors % erase_sectors,
        'ram_allocation_bytes': mathematical_bytes & U32,
        'allocation_wrapped': mathematical_bytes > U32,
        'host_backup': False, 'scope': 'arithmetic for a stateful on-device relocation routine; not full-flash backup'}


def build_report(workspace, source, native):
    body = source.read_bytes()
    if digest(body) != BASELINE: raise ValueError('Source identity differs')
    elf = (workspace / 'elf-original/image-00000200.elf').read_bytes()
    if body[0x200:0x200 + len(elf)] != elf: raise ValueError('Updater ELF differs from carrier')
    mapping = ElfBytes(elf)
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    checks = []
    for address, expected in ASSERTIONS.items():
        items = list(decoder.disasm(mapping.read(address, 4), address))
        if len(items) != 1 or (items[0].mnemonic, items[0].op_str) != expected:
            raise ValueError(f'Instruction differs at{address:#x}')
        checks.append({'address': address, 'instruction_sha256': digest(mapping.read(address, 4))})
    corroboration = check_dossiers(native / 'image-00000200', mapping, digest(elf), FUNCTIONS)
    return {'schema_version': 1, 'source_sha256': BASELINE,
        'updater_elf_sha256': digest(elf), 'carrier_elf_offset': 0x200,
        'address_namespace': 'separate updater ELF; overlapping application addresses are different code',
        'method': 'Authenticated updater carrier, independent Capstone and direct Ghidra dossiers; not REA Evidence',
        'camera_commands_issued': False, 'target_executed': False,
        'instruction_checks': checks, 'native_corroboration': corroboration,
        'contracts': [
          {'id': 'update.section_records', 'status': 'static-contract-partial',
           'map_builder': 0x8001a4e8, 'record_bytes': 0x24, 'record_count': 7,
           'layout': {'start_sector': 0, 'reserved_sectors': 4, 'burn_sectors': 8,
               'section_type': 12, 'boot_patch_flag': 0x18, 'boot_patch_countdown': 0x1c, 'other_flag_byte': 0x20, 'protected_byte': 0x21},
           'geometry': {'erase_unit_sectors': 'handle+1240', 'total_sectors': 'handle+1244'},
           'mode': 'bootheader+234==1 selects upgrade; previous map is copied, size fields218/21c/220 must match; full-burn branch derives a new layout',
           'boundary_special_case': 'media kind5 adds boundary-start%boundary using handle11e0; an already aligned start advances a full boundary unit',
           'limits': 'Sector records are not an installed physical NAND map; geometry, zones and bad blocks are runtime inputs. Layout construction also updates an in-memory MBR/boot header.'},
          {'id': 'update.section_protection', 'status': 'predicate-verified',
           'address': 0x8001a07c, 'arguments': 'a0section0..6,a1record,a2newheader; returns boolean',
           'rule': 'section3:upgrade==1&&handle1270==1; section6:upgrade==1&&burn==0; others:reserved!=0&&burn==0',
           'limits': 'A map flag is not hardware write protection or proof that boot/calibration survives every update. Full erase, bad-block marking, headers and user-area relocation are separate mutation routes.'},
          {'id': 'update.recover_section_extent', 'status': 'arithmetic-verified',
           'address': 0x8001a3d0, 'rule': 'low32(header[0]+header[2]+header[3])/handle138 gives burn sectors; align with low32(erase+sectors-1)/erase*erase',
           'missing': 'Absent recovery header yields zero sizes; actual reset-independent activation remains unverified',
           'package_flag': 'Supplied main package bit31 at header word5 is clear, as recorded separately in recovery-transport.json'},
          {'id': 'update.nand_writer', 'status': 'static-route-partial',
           'address': 0x80012e84, 'section_loop': 'sections0..6, stride24; record+8 burn count0 skips that section body',
           'writes': 'Uses runtime physical/virtual zone configuration and bad-block advancement; erases/programs main data, headers, recover metadata and extended bad-block tables on selected branches',
           'full_erase': 'handle1264==1 erases blocks below total-blocks minus on-device-backup reservation before section burning',
           'transport': 'Input callback supplies update chunks; this is a programming consumer, not a host readback API',
           'limitations': ['Complete physical write extents require installed geometry, old header, flags, zone mapping and failure outcomes.',
              'Ghidra reports type-propagation warning for this large function; selected branches/words are independently checked.']},
          {'id': 'update.user_area_backup', 'status': 'state-changing-route-verified',
           'address': 0x80012730, 'restore': 0x80012ba8,
           'behavior': 'Reads selected good user blocks into allocated RAM, erases/programs tail blocks and writes/verifies an eight-byte marker with count. Restore reads that tail and erases/programs destinations, optionally erases the tail afterward.',
           'marker': '01 23 45 67 89 ab cd ef; count follows at+8',
           'ownership': 'Large dynamic RAM allocation; bad-block skips/retries affect selected destinations. No host output stream or full-flash/calibration/ECC backup is produced.',
           'limits': 'Must not be used as a read-only inventory or backup command; allocation overflow, tail exhaustion and power-failure restoration are not established safe.'},
          {'id': 'update.bad_block_and_verify', 'status': 'state-changing-route-verified',
           'check': 0x80012370, 'mark_bad': 0x80012258, 'program_compare': 0x80012510,
           'check_side_effect': 'BlockIsBad may call BlockMarkBad when returned status flag is1; the name does not guarantee passive access',
           'mark_bad_behavior': 'Updates spare/status metadata through operation7 for two pages, step1or4 depending on geometry byte11c8',
           'program_compare': 'Operation5 programs a block, operation4 reads it back, compares erase-unit*512 bytes and returns success/failure; this is not a generic safe verification function',
           'operations': {'4': 'data read, potentially ECC-normalized', '5': 'data program', '7': 'spare/status program', '8': 'block erase'},
           'limits': 'ECC handling and spare/status transformations vary with FcuNandOperationEx runtime geometry; returned read data is not a raw physical/ECC image.'}],
        'gates': {'complete_host_backup_verified': False, 'installed_physical_write_ranges_verified': False,
            'software_unbootable_recovery_verified': False, 'executable_trial_allowed': False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native', type=Path, default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/update-write-scope.json')
    args = parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose an unused evidence path')
    report = build_report(args.workspace, args.source, args.native)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle: json.dump(report, handle, indent=2); handle.write('\n')
    print(json.dumps({'contracts': len(report['contracts']), 'dossiers': len(FUNCTIONS),
        'instruction_assertions': len(ASSERTIONS), 'executable_trial_allowed': False}))


if __name__ == '__main__': main()
