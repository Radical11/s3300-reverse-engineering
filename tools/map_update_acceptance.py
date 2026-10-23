"""Source-bound static map of S3300 v1.1 update checks and debug leads.

Never modifies a vendor file, runs target code, or sends camera commands.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor'))
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

ROOT = Path(__file__).resolve().parents[1]
SOURCE_HASH = '2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b'
ANALYSIS_HASH = '15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect_additive_checksum(data):
    if len(data) < 0x30:
        raise ValueError('Firmware header truncated before checksum field')
    stored = struct.unpack_from('<I', data, 0x2c)[0]
    calculated = (sum(data[:0x2c]) + sum(data[0x30:])) & 0xffffffff
    return {'offset': 0x2c, 'size': 4, 'endianness': 'little',
            'stored': stored, 'stored_hex': hex(stored),
            'calculated': calculated, 'calculated_hex': hex(calculated),
            'matches': stored == calculated,
            'formula': 'LE32(file[0x2c:0x30]) == sum(all other file bytes) modulo 2^32'}


def self_test():
    sample = bytearray(range(64))
    value = (sum(sample[:0x2c]) + sum(sample[0x30:])) & 0xffffffff
    struct.pack_into('<I', sample, 0x2c, value)
    assert inspect_additive_checksum(sample)['matches']
    changed = bytearray(sample)
    changed[0x33] ^= 1
    assert not inspect_additive_checksum(changed)['matches']
    changed = bytearray(sample)
    changed[0x2c] ^= 1
    assert not inspect_additive_checksum(changed)['matches']
    for length in (0, 0x2b, 0x2f):
        try:
            inspect_additive_checksum(bytes(length))
        except ValueError:
            pass
        else:
            raise AssertionError('Truncated header accepted')
    return {'synthetic_checks_passed': 6}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test()))
        return
    manifest_path = ROOT / 'derived/v1.1-analysis/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    data_path = Path(manifest['elf_file'])
    data = data_path.read_bytes()
    source_path = ROOT / 'sources/extracted-v1.1/S3300Update/firmware/firmware.bin'
    source = source_path.read_bytes()
    if digest(source) != SOURCE_HASH or digest(data) != ANALYSIS_HASH or manifest['elf_sha256'] != ANALYSIS_HASH:
        raise ValueError('Unsupported source or synthetic analysis ELF')
    destination = ROOT / 'evidence/update-acceptance.json'
    directory = ROOT / 'derived/update-acceptance-analysis'
    if destination.exists() or directory.exists():
        raise FileExistsError('Refusing to overwrite previous evidence')
    directory.mkdir()

    def read(va, length):
        matches = [r for r in manifest['regions'] if r['virtual_start'] <= va
                   and va + length <= r['virtual_start'] + r['size']]
        if len(matches) != 1:
            raise ValueError('Window is not uniquely file-backed')
        region = matches[0]
        offset = region['analysis_elf_offset'] + va - region['virtual_start']
        return data[offset:offset+length], offset

    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    selections = [
        ('application_checksum', 0x807366d4, 0x26c),
        ('candidate_product_marker_check', 0x80736568, 0xd8),
        ('update_version_reader', 0x80736640, 0x94),
        ('full_file_marker_version_comparison', 0x8063afc4, 0x224),
        ('update_menu_checksum_calls', 0x8061fc68, 0x1a0),
        ('update_menu_marker_gate', 0x80620fe0, 0x44),
        ('ptp_vendor_registration', 0x8057ad04, 0x3c),
        ('ptp_9002_9003_handler', 0x8057db04, 0x134),
        ('ptp_9005_9006_registration', 0x8077f27c, 0x210),
        ('ptp_send_object_handler', 0x807815a0, 0x300),
        ('usb_setmem_monitor_tail', 0x8079d74c, 0x264),
        ('usb_getmem_candidate', 0x8079de34, 0x1d8),
        ('sd_test_file_predicates', 0x807486bc, 0xac),
    ]
    windows = []
    for name, address, length in selections:
        raw, offset = read(address, length)
        decoded = list(decoder.disasm(raw, address))
        if sum(i.size for i in decoded) != length:
            raise ValueError(f'Incomplete linear decode of {name}')
        path = directory / (name + '.asm')
        path.write_text('; Bounded analyst window, not a proven complete function or runtime trace.\n'
                        '; Static MIPS32 little endian; branch delay slots require interpretation.\n'
                        + '\n'.join(f'{i.address:08x} {i.bytes.hex():8} {i.mnemonic:10} {i.op_str}' for i in decoded)
                        + '\n')
        windows.append({'analyst_label': name, 'virtual_start': address, 'size': length,
                        'analysis_elf_offset': offset, 'sha256': digest(raw),
                        'listing': str(path), 'linear_decode_bytes': sum(i.size for i in decoded)})
    checksum = inspect_additive_checksum(source)
    if not checksum['matches']:
        raise ValueError('Baseline checksum mismatch')
    report = {
        'method': 'Source-bound static MIPS32 windows in independently decoded v1.1 application; no target execution',
        'source_sha256': SOURCE_HASH, 'analysis_elf_sha256': ANALYSIS_HASH,
        'additive_checksum': {**checksum, 'routine': 0x807366d4,
            'seek_site': 0x8073673c, 'read_site': 0x80736750,
            'accumulate_site': 0x807367cc, 'comparison_sites': [0x807367fc, 0x8073681c, 0x80736828],
            'caller_sites': [0x8061fd90, 0x8061fda0],
            'status': 'Static arithmetic independently matches actual baseline file'},
        'version_field': {'offset': 0x28, 'size': 4, 'value': struct.unpack_from('<I', source, 0x28)[0],
            'value_hex': hex(struct.unpack_from('<I', source, 0x28)[0]), 'reader_routine': 0x80736640,
            'display_extraction_sites': [0x8062f48c, 0x8062f49c],
            'display_fields': 'high16 = 1; bits8..15 = 1 in this source; routine is used to display offered version',
            'ordinary_upgrade_or_downgrade_comparison': 'Not established by this bounded pass'},
        'candidate_product_marker': {'offset': 0x30, 'value': struct.unpack_from('<I', source, 0x30)[0],
            'value_hex': hex(struct.unpack_from('<I', source, 0x30)[0]), 'routine': 0x80736568,
            'compare_site': 0x807365d0, 'equals_constant': 0x4b230146,
            'runtime_flag_address': 0x808921f1,
            'behavior': 'When file handle and flag are nonzero, returns 2 for marker equality, 1 for mismatch; otherwise 0.',
            'caller_site': 0x80620fe8,
            'status': 'Static marker equality gate; exact model/product semantics and v1.0 equivalence unverified'},
        'file_paths': [
            {'address': 0x803867d8, 'text': 'I:\\FIRMWARE\\FIRMWARE.BIN', 'xref_sites': [0x80736570, 0x80736648, 0x807366dc]},
            {'address': 0x80675d30, 'text': '\\FIRMWARE\\FIRMWARE.BIN', 'xref_sites': [0x8061fd2c]},
            {'address': 0x806791d4, 'text': 'I:\\FIRMWARE\\FULL_EN.txt', 'xref_sites': [0x8063b008, 0x8063b074]},
        ],
        'full_file_marker': {'routine': 0x8063afc4,
            'behavior': 'If the marker file exists, reads 6 ASCII bytes and compares parsed major/hex fraction to firmware u32 at 0x28; stores equality and availability flags.',
            'flag_addresses': [0x8065e6b8, 0x8065e6b9],
            'limitation': 'Special full-file path only; not proof of ordinary update version policy. Marker was not created.'},
        'usb_vendor_operations': [
            {'opcode': '0x9002', 'registration_site': 0x8057ad28, 'handler': 0x8057db04,
             'finding': 'Branches on parameter 1 or 2 and may call state-changing routine 0x8063b3bc; not a validated read-only dump operation.'},
            {'opcode': '0x9003', 'registration_site': 0x8057ad38, 'handler': 0x8057db04,
             'finding': 'Delegated registration plus shared opcode handler; parameter path writes multiple global/state bytes.'},
            {'opcode': '0x9005', 'registration_site': 0x8077f404, 'handler': 0x80781028,
             'finding': 'Default handler table points to 0x80781028, also used by standard 0x100c (SendObjectInfo); object-receive metadata path.'},
            {'opcode': '0x9006', 'registration_site': 0x8077f408, 'handler': 0x807815a0,
             'finding': 'Handler 0x807815a0 is also used by standard 0x100d (SendObject); USB receive and file/object mutation path, not a validated memory-read facility.'},
        ],
        'debug_leads': [
            {'label': 'GetMem over USB implementation candidate', 'routine': 0x8079de34,
             'handler_pointer': 0x80899660, 'diagnostic_string': 0x80686dd8,
             'finding': 'Copies address and length from shared command at 0x800e113c, constructs memory alias and reaches transfer routine 0x80796070.',
             'missing': 'Actual active transport/interface and command framing, safe address bounds, installed-v1.0 correspondence, and read-only reachability.'},
            {'label': 'SetMem / monitor execution implementation', 'routine': 0x8079d74c,
             'handler_pointer': 0x80899658, 'monitor_call_site': 0x8079d93c,
             'finding': 'Side-effectful command handling exists adjacent to GetMem; do not treat the protocol generically as read-only.'},
            {'label': 'NAND dump monitor command', 'registration_address': 0x808983cc,
             'description_address': 0x803894e4, 'handler': 0x805810c0,
             'output_path_address': 0x8066790c, 'output_path': 'I:\\DumpNand.txt',
             'finding': 'Static monitor table associates NAND-to-card description with handler; bounded follow-up reaches file writes.',
             'missing': 'Verified console access, full routine behavior, exact storage geometry and complete calibration/backup coverage.'},
        ],
        'source_unchanged': digest(source_path.read_bytes()) == SOURCE_HASH,
        'windows': windows,
        'limitations': ['Analysis applies to supplied v1.1 update, not an observed dump of running v1.0.',
            'Additive checksum is an integrity mechanism, not evidence that all acceptance checks or authentication are known.',
            'No confirmed end-to-end read-only USB RAM/flash dump or restoration procedure is established.',
            'No installable image, update bypass, marker file, camera command or hardware write was produced.'],
    }
    with destination.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps({'additive_checksum_matches': checksum['matches'], 'windows': len(windows),
                      'source_unchanged': report['source_unchanged']}))


if __name__ == '__main__':
    main()
