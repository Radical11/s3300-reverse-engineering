"""Authenticate application card burning and its absent-ROM reboot boundary.

Offline only: models describe observed integers/header bytes and never issue
camera operations, produce a patch or authorize a recovery procedure.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import ElfBytes, check_dossiers
from map_reset_recovery import file_backed_at

FUNCTIONS = (0x8061fc68, 0x807366d4, 0x801f7100, 0x801eb708, 0x803d64f0,
             0x803dbc00, 0x803e26b0, 0x803e2a40, 0x803d5e20, 0x800a2cec,
             0x800b5890, 0x8005eaa0, 0x8008cd5c)
ASSERTIONS = {
    0x8061fd90: ('jal', '0x807366d4'),
    0x8061fda0: ('jal', '0x807366d4'),
    0x8061fdf0: ('jal', '0x801f7100'),
    0x8061fdf4: ('addiu', '$a0, $zero, 1'),
    0x8061fe24: ('sltiu', '$t0, $s1, 3'),
    0x801f7108: ('jal', '0x801eb708'),
    0x801f710c: ('addiu', '$a1, $zero, 1'),
    0x801eb710: ('jal', '0x803d64f0'),
    0x803d64fc: ('ext', '$a1, $a0, 0xf, 8'),
    0x803d6504: ('jal', '0x803dbc00'),
    0x803d6508: ('andi', '$a0, $a0, 0xff'),
    0x803dbfac: ('lui', '$a2, 0x10'),
    0x803dbfb4: ('jal', '0x8008cd5c'),
    0x803dbfb8: ('move', '$a3, $zero'),
    0x803dbfe0: ('addiu', '$a2, $zero, 0x40'),
    0x803dbfe4: ('jal', '0x8008158c'),
    0x803dc224: ('jal', '0x803e26b0'),
    0x803dc238: ('jal', '0x803e2a40'),
    0x803e26c4: ('lw', '$v1, 8($a0)'),
    0x803e28d8: ('addiu', '$s1, $t3, 0x73dc'),
    0x803e28ec: ('sw', '$s1, 0x125c($a1)'),
    0x803e2c00: ('lw', '$s0, 0x125c($s1)'),
    0x803e2c08: ('jalr', '$s0'),
    0x803e2c0c: ('move', '$a0, $s1'),
    0x800a2db4: ('ori', '$s2, $s0, 0x3000'),
    0x800a2ddc: ('and', '$ra, $s1, $s2'),
    0x800a2de4: ('and', '$v0, $v0, $v1'),
    0x800a2df4: ('or', '$s2, $v0, $ra'),
    0x800a2ec0: ('jal', '0x800b5890'),
    0x800a2ec4: ('move', '$a0, $s2'),
    0x800b58a8: ('sw', '$zero, ($t0)'),
    0x800b58b4: ('lui', '$t1, 0xbfc0'),
    0x800b58b8: ('addiu', '$t1, $t1, 0x664'),
    0x800b58cc: ('jr', '$t1'),
    0x8005eae8: ('ori', '$a2, $a3, 0x95fc'),
    0x8005eaec: ('lw', '$a1, ($a2)'),
}
BURN_HEADER = {0x0: 0x1120000, 0x4: 0x20000, 0x8: 3, 0xc: 0,
    0x10: 6, 0x14: 2, 0x18: 1, 0x1c: 0, 0x20: 0, 0x24: 1,
    0x28: 0, 0x2c: 0, 0x30: 0, 0x34: 1, 0x38: 0x50, 0x3c: 0x55aa0000}
U32 = 0xffffffff


def u32(value):
    if type(value) is not int or not 0 <= value <= U32:
        raise ValueError('Expected an observed unsigned32-bit integer')
    return value


def split_card_source(source, finish_mode):
    """803d64f0 argument splitting only, not a safe updater invocation."""
    source, finish_mode = u32(source), u32(finish_mode)
    return {'source': source & 255, 'sfcu': (source >> 15) & 255,
            'finish_mode': finish_mode & 255, 'device_invocation': False}


def application_result(burn_result):
    """801f7100 translates exactly1 to0, every other result tofe."""
    return 0 if u32(burn_result) == 1 else 0xfe


def boot_argument(old_flags, requested, mask):
    """800a2cec's value passed in a0 to absent ROM, not a reset API.

    Request bit0x800 reloads the previous flag word before the merge. Bits3000
    participate in the merge regardless of the caller mask. No device state is
    touched and the ROM's interpretation of this value is not established.
    """
    old_flags, requested, mask = [u32(x) for x in (old_flags, requested, mask)]
    if requested & 0x800:
        requested = old_flags
    effective = mask | 0x3000
    return ((old_flags & ~effective) | (requested & effective)) & U32


def describe_burn_header(header):
    """Describe one already observed 64-byte application burn header."""
    if not isinstance(header, bytes) or len(header) != 0x40:
        raise ValueError('Exactly64 observed burn-header bytes required')
    values = struct.unpack('<16I', header)
    return {'advertised_data_bytes': values[0], 'chunk_bytes': values[1],
        'media_kind': values[2], 'finish_action': values[3],
        'keep_user_area_flag': values[9] & 255,
        'hash_enabled': bool(values[15] & 0xffff),
        'extended_header_marker': values[15] >> 16,
        'camera_geometry_established': False,
        'scope': 'Package metadata, not installed flash geometry or a safe operation'}


def check_assertions(mapping):
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    rows = []
    for address, expected in ASSERTIONS.items():
        body = mapping.read(address, 4)
        instruction = list(decoder.disasm(body, address))
        if len(instruction) != 1 or (instruction[0].mnemonic, instruction[0].op_str) != expected:
            raise ValueError(f'Application instruction differs at{address:#x}')
        rows.append({'address': address, 'instruction_sha256': digest(body)})
    return rows


def build_report(workspace, source, native):
    body = source.read_bytes()
    if digest(body) != BASELINE: raise ValueError('Source identity differs')
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw, manifest['regions'])
    checks = check_assertions(mapping)
    corroboration = check_dossiers(native/'application', mapping, digest(raw), FUNCTIONS)
    for offset, expected in BURN_HEADER.items():
        if struct.unpack_from('<I', body, 0x100000 + offset)[0] != expected:
            raise ValueError('Package burn-header word differs')
    coverage = []
    for path in sorted((workspace/'elf-original').glob('*.elf')):
        carrier = path.read_bytes(); offset = int(path.stem.removeprefix('image-'),16)
        if body[offset:offset+len(carrier)] != carrier:
            raise ValueError('Separate ELF differs from carrier')
        elf = ElfBytes(carrier)
        coverage.append({'image': path.stem, 'sha256': digest(carrier),
            'rom_handoff_bfc00664': file_backed_at(elf.parts, 0xbfc00664, 4),
            'boot_flags_bfc095fc': file_backed_at(elf.parts, 0xbfc095fc, 4),
            'boot_header_bfc09600': file_backed_at(elf.parts, 0xbfc09600, 0x24)})
    if any(row['rom_handoff_bfc00664'] for row in coverage):
        raise ValueError('ROM handoff coverage changed; re-review missing entry')
    return {'schema_version': 1, 'source_sha256': BASELINE, 'analysis_sha256': digest(raw),
        'address_namespace': 'application; original executable carriers checked separately for absent ROM coverage',
        'method': 'Authenticated original carrier, independent Capstone checks and direct Ghidra dossiers; not REA Evidence',
        'camera_commands_issued': False, 'target_executed': False,
        'instruction_checks': checks, 'native_corroboration': corroboration,
        'burn_header': {'carrier_offset': 0x100000, 'sha256': digest(body[0x100000:0x100040]),
            **describe_burn_header(body[0x100000:0x100040])},
        'original_elf_coverage': coverage,
        'contracts': [
          {'id': 'handoff.normal_update_is_application_burn', 'status': 'static-route-verified',
           'chain': ['8061fc68 handles106/108 UI events and checks807366d4',
             '8061fdf0 calls801f7100 witha0=1; wrapper calls801eb708→803d64f0→803dbc00',
             '803dbc00 seeks to carrier offset100000 and reads40-byte burn header, optionally80 extension',
             '803e26b0 installs media-dependent writer at handle125c',
             '803e2a40 loads callback125c and calls it with handle and input callbacks'],
           'known_package': 'Header media_kind3 selects application NAND-NSR writer address803d73dc; keep-user-area flag1; finish action0 does not select the reboot branches in803d5e20',
           'returns': '801f7100 maps downloader result1 to0 success and all others tofe; UI retries at most3 times',
           'side_effects': 'Flash programming path, allocations, media initialization, UI state and error/retry state; not passive inspection',
           'limit': 'Reviewed pre-burn code seeks past the separate updater ELF and directly calls an application writer. No launch of that separate ELF is established in this traced route. Static flow is not a recorded installed-camera trace; complete writer body/geometry remain separately bounded research.'},
          {'id': 'handoff.reboot_rom_boundary', 'status': 'static-route-partial',
           'caller': 0x800a2cec, 'entry': 0x800b5890, 'rom_target': 0xbfc00664,
           'argument': 'a0=old&~(mask|3000)|requested&(mask|3000); requested bit800 replaces requested with old',
           'behavior': 'Application quiesces drivers, clocks/GPIO/interrupt state and cache;800b5890 calls800b3a90, writes zero to b0802010 and jumps through t1 to bfc00664',
           'limit': 'ROM instructions at bfc00664 and reset-vector-to-ROM routing are absent. This is an application-dependent handoff, not a verified independent recovery entry or host invocation.'},
          {'id': 'handoff.boot_flags_producer', 'status': 'unresolved',
           'reader': 0x8005eaa0, 'runtime_address': 0xbfc095fc, 'cache': 0x8005ee54,
           'behavior': 'Reads/caches runtime word while controlling interrupt state; cached value reused when notffffffff',
           'gap': 'Reviewed code passes merged flags in a0 to absent ROM; it does not establish where ROM writes bfc095fc or populates bfc09600',
           'limit': 'No instruction or request is emitted to set flags, jump to ROM, change boot source or invoke updater.'},
          {'id': 'handoff.recovery_independence', 'status': 'blocked',
           'known': 'Normal card update uses application code. A separate original updater and tiny loader exist, but their reset-independent activation remains unverified.',
           'required': ['Installed ROM/reset routing and safe software-only activation',
             'Bounded transport and full installed boot/firmware/calibration/settings/ECC backup',
             'Verified restore procedure available when application startup fails'],
           'limit': 'Neither existing user-reported normal update success nor recovered ROM handoff argument supplies these missing contracts'}],
        'gates': {'normal_update_route_static': True, 'boot_flags_producer_verified': False,
            'reset_to_recovery_independent': False, 'complete_backup_verified': False,
            'software_unbootable_recovery_verified': False, 'executable_trial_allowed': False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,default=WORKSPACE)
    parser.add_argument('--source',type=Path,default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native',type=Path,default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/updater-handoff.json')
    args=parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose an unused output path')
    report=build_report(args.workspace,args.source,args.native)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'instructions':len(ASSERTIONS),'dossiers':len(FUNCTIONS),
        'normal_update_is_application_burn':True,'executable_trial_allowed':False}))


if __name__ == '__main__': main()
