"""Map installed backup content and passive/mutating storage boundaries.

Offline source-bound analysis only. Helpers inspect supplied bytes and observed
geometry; they do not acquire memory, build requests or produce write images.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x80008f80, 0x800093bc, 0x80009510, 0x8000994c, 0x80009cb4,
    0x80009f70, 0x800e2e0c, 0x800e3fd8, 0x80065c50, 0x807378a4)
ASSERTIONS = {
    0x80009580: ('addiu', '$a2, $zero, 2'),
    0x80009594: ('jal', '0x800e408c'),
    0x800095b8: ('addiu', '$a2, $zero, 3'),
    0x800095d8: ('jal', '0x800e408c'),
    0x8000a004: ('jal', '0x80009cb4'),
    0x8000a00c: ('bnez', '$v0, 0x8000a0cc'),
    0x8000a0e0: ('jal', '0x80009510'),
    0x80009d9c: ('move', '$a2, $zero'),
    0x80009da8: ('jal', '0x800e408c'),
    0x80009df8: ('move', '$a2, $zero'),
    0x80009e0c: ('jal', '0x800e408c'),
    0x80009ddc: ('lbu', '$t9, 0x19d($ra)'),
    0x80009de0: ('lbu', '$t8, 0x19c($ra)'),
    0x80009dec: ('mul', '$s0, $s4, $s5'),
    0x80009efc: ('jal', '0x80008f80'),
    0x80009f00: ('addiu', '$a3, $zero, 0x249'),
    0x80009f04: ('lbu', '$s6, 0x248($s2)'),
    0x80009a34: ('addiu', '$a3, $zero, 0x249'),
    0x80009a3c: ('jal', '0x80008f80'),
    0x80009a44: ('sb', '$v0, 0x248($s0)'),
    0x800e2e40: ('lhu', '$a2, 0x11c4($s1)'),
    0x800e2e44: ('lw', '$a3, 0x314($a1)'),
    0x800e2e48: ('lw', '$a0, 0x1238($v0)'),
    0x800e2e4c: ('lw', '$a1, 0x310($a1)'),
    0x800e2e54: ('sllv', '$v0, $v1, $a2'),
    0x800e2e58: ('sw', '$a3, 4($s0)'),
    0x800e2e5c: ('sw', '$a0, 0xc($s0)'),
    0x800e2e60: ('sw', '$a1, ($s0)'),
    0x800e2e64: ('sw', '$v0, 8($s0)'),
    0x800093c4: ('addiu', '$v0, $v0, 0x3474'),
    0x807378bc: ('addiu', '$t3, $v0, 4'),
    0x807378c4: ('addiu', '$t4, $s1, 0x40'),
    0x80737938: ('addiu', '$t3, $v0, 0x4c'),
    0x8073793c: ('addiu', '$t2, $s1, 0x48'),
    0x80737940: ('addiu', '$s0, $s1, 0x88'),
    0x80737998: ('addiu', '$t3, $v0, 0x8c'),
    0x807379a0: ('addiu', '$t4, $s1, 0x108'),
    0x807379f8: ('addiu', '$t3, $v0, 0x10c'),
    0x807379fc: ('addiu', '$t2, $s1, 0x240'),
    0x80737a00: ('addiu', '$t4, $s1, 0x2f0'),
    0x80737a64: ('addiu', '$t3, $v0, 0x1c0'),
    0x80737a68: ('addiu', '$t4, $s1, 0x374'),
    0x80737a6c: ('addiu', '$t2, $s1, 0x2f4'),
}
CALIBRATION_SLICES = ((0x000, 0x004, 0x48), (0x048, 0x04c, 0x40),
    (0x088, 0x08c, 0x80), (0x240, 0x10c, 0xb4), (0x2f4, 0x1c0, 0x80))


def inspect_store(data, kind):
    """Inspect one observed serialized store; no repair or full-backup approval."""
    if not isinstance(data, bytes): raise ValueError('Supply observed immutable bytes')
    if kind == 'ui':
        length, magic, covered, checksum = 0x1a0, b'\x9c\xb6', 0x19e, 0x19f
    elif kind == 'calibration':
        length, magic, covered, checksum = 0x24a, b'Tx', 0x248, 0x248
    else: raise ValueError('Reviewed store kinds are ui and calibration')
    if len(data) != length: raise ValueError(f'Expected exactly{length} observed bytes')
    result = {'kind': kind, 'bytes': length, 'sha256': digest(data),
        'header_matches': data[:2] == magic,
        'checksum_matches': data[checksum] == sum(data[:covered]) & 255,
        'checksum_offset': checksum, 'covered_offsets_inclusive': [0, covered-1],
        'full_backup': False, 'restorable': False}
    if kind == 'ui': result['calibration_block_index'] = struct.unpack_from('<H', data, 0x19c)[0]
    result['valid_serialized_store'] = result['header_matches'] and result['checksum_matches']
    return result


def partition_geometry(first_block, block_count, observed_shift):
    """Model geometry getter plus caller arithmetic, never a physical read plan."""
    for value in (first_block, block_count):
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('Block observations must be unsigned32 words')
    if type(observed_shift) is not int or not 0 <= observed_shift <= 0xffff:
        raise ValueError('Shift observation must be unsigned16')
    erase_sectors = 1 << (observed_shift & 31)
    mathematical_start = first_block * erase_sectors
    mathematical_end = (first_block + block_count) * erase_sectors
    target_end = (((first_block + block_count) & 0xffffffff) * erase_sectors) & 0xffffffff
    return {'first_block': first_block, 'block_count': block_count,
        'erase_unit_sectors': erase_sectors,
        'start_sector_token': mathematical_start & 0xffffffff,
        'end_sector_token': target_end,
        'arithmetic_wrapped': mathematical_start > 0xffffffff or mathematical_end > 0xffffffff,
        'physical_extent_verified': False,
        'scope': 'Runtime user-partition tokens only; not total flash capacity or ECC/bad-block mapping'}


def calibration_location(ui_data, observed_erase_sectors):
    """Decode metadata from an acquired UI store without authorizing access."""
    result = inspect_store(ui_data, 'ui')
    if not result['valid_serialized_store']: raise ValueError('UI header/checksum differs')
    if type(observed_erase_sectors) is not int or not 1 <= observed_erase_sectors <= 0xffffffff:
        raise ValueError('Erase-unit observation must be a nonzero unsigned32 word')
    product = result['calibration_block_index'] * observed_erase_sectors
    return {'block_index': result['calibration_block_index'],
        'sector_token': product & 0xffffffff, 'arithmetic_wrapped': product > 0xffffffff,
        'physical_extent_verified': False, 'read_request_authorized': False}


def build_report(workspace, source, native):
    original = source.read_bytes()
    if digest(original) != BASELINE: raise ValueError('Source identity differs')
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw, manifest['regions'])
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    checks = []
    for address, expected in ASSERTIONS.items():
        body = mapping.read(address, 4)
        items = list(decoder.disasm(body, address))
        if len(items) != 1 or (items[0].mnemonic, items[0].op_str) != expected:
            raise ValueError(f'Instruction differs at{address:#x}')
        checks.append({'address': address, 'instruction_sha256': digest(body)})
    for address, expected in ((0x80101a30, 0x800032d4), (0x80101a34, 0x80003474)):
        if struct.unpack('<I', mapping.read(address, 4))[0] != expected:
            raise ValueError('Persistent store pointer differs')
    corroboration = check_dossiers(native/'application', mapping, digest(raw), FUNCTIONS)
    if digest(source.read_bytes()) != BASELINE: raise ValueError('Source changed during analysis')
    return {'schema_version': 1, 'source_sha256': BASELINE, 'analysis_sha256': digest(raw),
        'image_namespace': 'application',
        'method': 'Authenticated application instructions, independent Capstone, direct Ghidra dossiers; not REA Evidence',
        'camera_commands_issued': False, 'target_executed': False,
        'instruction_assertions': len(checks), 'instruction_checks': checks,
        'native_corroboration': corroboration,
        'contracts': [
          {'id': 'backup.ui_and_calibration_stores', 'status': 'static-read-layout-verified',
           'reader': 0x80009cb4, 'ui_store': {'ram': 0x800032d4, 'bytes': 0x1a0, 'magic_hex': '9cb6',
               'checksum_offset': 0x19f, 'checksum_covered': [0, 0x19d], 'calibration_block_index_le16': 0x19c},
           'calibration_store': {'ram': 0x80003474, 'bytes': 0x24a, 'magic_hex': '5478',
               'checksum_offset': 0x248, 'checksum_covered': [0, 0x247], 'excluded_tail_offset': 0x249},
           'read_route': 'The reader uses media selector0, count2 at each candidate user block and then calibration_index*erase_sectors. Lower mapping selector0->backend4 is retained in development-contracts.json.',
           'ownership_and_side_effects': 'Copies into global RAM stores; invalid loads zero them, print diagnostics and return6. This is not an external host transport.',
           'limits': 'Checksum/header validity is not proof of provenance, full calibration coverage, physical bounds or safe restoration.'},
          {'id': 'backup.calibration_serialized_subset', 'status': 'static-copy-layout-verified',
           'copier': 0x807378a4, 'destination': 0x80003474,
           'slices': [{'source_offset': src, 'destination_offset': dst, 'bytes': size} for src,dst,size in CALIBRATION_SLICES],
           'limits': 'Only selected bytes of the caller-provided calibration object are serialized. The 0x24a store cannot substitute for every installed ColdData/defocus/calibration resource or their original physical representations.'},
          {'id': 'backup.user_partition_geometry', 'status': 'static-RAM-query-verified',
           'query_router': 0x800e3fd8, 'query': 0x800e2e0c, 'registry_lookup': 0x80065c50,
           'fields': 'registry+123c->object+310/+314 provide caller start/count; handle u16+11c4 yields1<<(shift&31); registry+1238 copied to output+0xc',
           'effects': 'Registry lookup takes/releases a runtime synchronization object. Query copies geometry into caller RAM; no flash program/erase call exists in this reviewed getter.',
           'limits': 'No host-callable entry, live values, total flash capacity or raw bad-block/ECC interpretation is established.'},
          {'id': 'backup.user_partition_initialization_mutates', 'status': 'erase-route-verified',
           'entry': 0x80009f70, 'fallback_block_scan': 0x80009510,
           'trigger': 'Nonzero return from read/validate helper80009cb4 branches to fallback scan.',
           'mutation': 'Each candidate block first receives media selector2,count1, which existing router maps to backend8/erase; only afterward does selector3/backend6 check spare/status and collect up to4 block indices.',
           'limits': 'GoodBlock_Num diagnostics and geometry-looking names do not establish passive inventory. Calling this initializer to recover settings can erase data.'},
          {'id': 'backup.calibration_writer', 'status': 'erase-program-readback-verified',
           'entry': 0x8000994c,
           'behavior': 'Allocates0x400 bytes; uses calibration sector token8000324c; selector2 erase then checksum/copy0x24a, selector1 program count2, selector0 read count2; failures may invoke erase again.',
           'limits': 'Readback comparison does not make this a passive validator or complete restore procedure. No standalone adapter is exposed.'}],
        'required_backup_components': [
          {'id': 'boot-rom-reset-chain', 'status': 'missing-installed-acquisition', 'evidence': 'reset-recovery.json', 'scope': 'Reset vector/ROM fingerprint and activation path are absent from supplied carrier mappings.'},
          {'id': 'installed-boot-header-and-sections', 'status': 'missing-installed-acquisition', 'evidence': 'update-write-scope.json', 'scope': 'Current boot records, section map and recovery flags; supplied update header is not an installed snapshot.'},
          {'id': 'installed-code-and-resource-volumes', 'status': 'baseline-only', 'evidence': 'firmware-atlas.json', 'scope': 'Original update preserved; exact installed modified code/resource bytes have not been read back.'},
          {'id': 'persistent-ui-store', 'status': 'layout-known-not-acquired', 'evidence': 'backup.ui_and_calibration_stores', 'scope': '0x1a0 serialized UI store and source/location metadata.'},
          {'id': 'persistent-calibration-and-calibration-resources', 'status': 'partial-layout-not-acquired', 'evidence': 'backup.calibration_serialized_subset', 'scope': 'Separate0x24a serialized subset plus other installed calibration resources and provenance; completeness unresolved.'},
          {'id': 'physical-geometry-bad-block-spare-ecc', 'status': 'missing-installed-acquisition', 'evidence': 'update-write-scope.json', 'scope': 'Installed geometry, mappings, bad blocks, spare/ECC representation and read failures; normalized data alone may omit restoration metadata.'},
          {'id': 'independent-recovery-content', 'status': 'missing-installed-acquisition', 'evidence': 'reset-recovery.json', 'scope': 'Installed recovery content and reset-independent entry/transport must be demonstrated.'},
          {'id': 'user-files', 'status': 'ordinary-object-copy-only', 'evidence': 'ptp-vendor-contracts.json', 'scope': 'Copied ordinary PTP/WPD files can preserve exposed media; they do not prove backup of hidden flash, settings, calibration or boot sectors.'}],
        'gates': {'complete_host_backup_verified': False, 'passive_host_storage_access_verified': False,
            'unbootable_software_recovery_verified': False, 'executable_trial_allowed': False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native', type=Path, default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/backup-scope.json')
    args = parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose an unused evidence path')
    report = build_report(args.workspace, args.source, args.native)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2); handle.write('\n')
    print(json.dumps({'contracts': len(report['contracts']), 'dossiers': len(FUNCTIONS),
        'instruction_assertions': len(ASSERTIONS), 'complete_backup': False}))


if __name__ == '__main__': main()
