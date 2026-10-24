"""Map the legacy packed gamma format and selected static consumers, offline.

This is a bounded instruction transcription and address scan, not target
execution, REA Evidence, a complete call graph, or an installable modification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from workspace_functions import load_analysis
from map_development_interfaces import AddressMap

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b'
GAMMA_VA = 0x80348344


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expand_legacy_gamma(raw):
    """Transcribe only 0x6200 / exactly 960-byte paths, before hardware repacking.

    Section labels indicate sample counts, not established colour domains.
    First section: 0x8021c444..0x8021c49c.
    Second section: 0x8021be98..0x8021bf14.
    """
    if len(raw) != 960:
        raise ValueError('Only the exactly 960-byte legacy resource is supported')
    words = struct.unpack('<240I', raw)
    first = []
    for x in range(1024):
        index, fraction = (64+x//4, x%4) if x < 64 else (x//16, x%16)
        value = words[index]
        base = (value >> 8) & 255
        slope = value & 255
        first.append((2*base + (slope*fraction >> 7) + 1) >> 1)
    second = []
    for x in range(4096):
        if x < 4:
            index, fraction = x, 0
        elif x < 128:
            index, fraction = 128+x//4, x%4
        else:
            index, fraction = x//32, x%32
        value = words[80+index]
        base = (value & 0xfff00) >> 7
        slope = value & 255
        second.append(((base + (slope*fraction >> 7) + 1) >> 1) << 2)
    return {'first_1024': first, 'second_4096': second}


def direct_transfers(regions, raw, targets):
    """Find aligned MIPS32 J/JAL encodings; data/indirect calls are unresolved."""
    result = {f'{t:#010x}': [] for t in sorted(targets)}
    for region in regions:
        start = region['virtual_start']
        offset = region['analysis_elf_offset']
        for relative in range((-start) % 4, region['size']-3, 4):
            word = struct.unpack_from('<I', raw, offset+relative)[0]
            opcode = word >> 26
            if opcode not in (2, 3):
                continue
            address = start+relative
            target = ((address+4) & 0xf0000000) | ((word & 0x3ffffff) << 2)
            if target in targets:
                result[f'{target:#010x}'].append({'site': address, 'instruction': 'jal' if opcode == 3 else 'j'})
    return result


def curve_summary(values):
    return {'samples': len(values), 'minimum': min(values), 'maximum': max(values),
            'decreases': sum(a > b for a, b in zip(values, values[1:])),
            'u32_le_sha256': digest(struct.pack(f'<{len(values)}I', *values)),
            'selected_samples': {str(x): values[x] for x in (0, 1, 3, 4, 15, 16, 63, 64, 127, 128, 255, 256, len(values)-1)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/gamma-pipeline.json')
    parser.add_argument('--listings', type=Path, default=ROOT/'derived/gamma-pipeline-map')
    args = parser.parse_args()
    if args.output.exists() or args.listings.exists():
        raise FileExistsError('Use fresh evidence and listing paths')
    source = (ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin').read_bytes()
    if digest(source) != BASELINE:
        raise ValueError('Baseline firmware identity differs')
    manifest, raw = load_analysis(ROOT/'derived/unpacked-v1.1-indexed')
    address_map = AddressMap(raw, manifest['regions'])
    resource_map = json.loads((ROOT/'evidence/resource-filesystem.json').read_text())
    if resource_map['input_sha256'] != BASELINE:
        raise ValueError('Resource evidence source differs')
    entry = next(f for f in resource_map['entries'] if f.get('path') == 'GammaLut0.bin' and f.get('kind') == 'file')
    filesystem = b''.join(source[c['carrier_offset']:c['carrier_offset']+c['file_bytes']] for c in entry['chunks'])
    if len(filesystem) != entry['size'] or digest(filesystem) != entry['sha256']:
        raise ValueError('Filesystem gamma reconstruction differs')
    embedded = address_map.read(GAMMA_VA, 960)
    tables = {name: {key: curve_summary(value) for key, value in expand_legacy_gamma(data).items()}
              for name, data in [('embedded', embedded), ('filesystem', filesystem)]}
    sys.path.insert(0, str(ROOT/'tools/vendor'))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    windows = [('resource_dispatch', 0x8000c300, 0x25c),
               ('format_and_converter', 0x8021bc90, 0x8d4),
               ('loader_and_extractor', 0x8021c7a8, 0x294),
               ('ipp_command_builder', 0x801fdd40, 0x1cc),
               ('gamma_table_selection', 0x801fe04c, 0x21c),
               ('hardware_upload', 0x80191c94, 0xd4),
               ('still_gamma_upload_call', 0x8024b090, 0x40),
               ('processing_gamma_upload_call', 0x802a5df4, 0x34),
               ('wrapper_caller', 0x80797638, 0xbc),
               ('table_length', 0x80234a20, 8)]
    args.listings.mkdir(parents=True)
    listing_reports = []
    for name, start, size in windows:
        data = address_map.read(start, size)
        instructions = list(decoder.disasm(data, start))
        if sum(i.size for i in instructions) != size:
            raise ValueError('Incomplete selected static window')
        path = args.listings/(name+'.asm')
        path.write_text('; Static analyst window; not a proven function boundary. Branch delay slots matter.\n'+
                        '\n'.join(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}' for i in instructions)+'\n')
        listing_reports.append({'name': name, 'start': start, 'bytes': size, 'sha256': digest(data),
                                'path': str(path.relative_to(ROOT))})
    targets = {0x8021bc90, 0x8021bd3c, 0x8021c7a8, 0x8021c960, 0x801fdd40, 0x801fde2c,
               0x801fe17c, 0x80191c94, 0x80234a20}
    report = {'source_sha256': BASELINE, 'analysis_sha256': digest(raw),
              'method': 'Authenticated bytes, bounded static MIPS32 listings, aligned J/JAL scan, instruction-transcribed curve expansion',
              'rea_evidence': False, 'target_executed': False,
              'embedded': {'address': GAMMA_VA, 'bytes': 960, 'sha256': digest(embedded)},
              'filesystem': {'path': 'GammaLut0.bin', 'bytes': len(filesystem), 'sha256': digest(filesystem)},
              'legacy_format': {'selector': 0x6200, 'size_selects_format_without_header': 960,
                                'first_section_bytes': 320, 'second_section_bytes': 640,
                                'first_section_expanded_samples': 1024, 'second_section_expanded_samples': 4096,
                                'channel_order': 'Unestablished; not three RGB channel tables'},
              'expanded_curve_summaries': tables, 'listings': listing_reports,
              'direct_transfer_encoding_candidates': direct_transfers(manifest['regions'], raw, targets),
              'confirmed_static_contracts': [
                  'Loader 0x8021c7a8 calls converter 0x8021bd3c on both raw-cache hit and miss.',
                  '0x8021c960 copies 0x100 u32 from converted+0x194 and frees the converted allocation.',
                  '0x801fdd40 constructs command id 10 and copies the 256-word extracted table into command+0x18.',
                  '0x80191c94 sends 256 u32 to 0xb60000b8 then 128 packed pairs to 0xb6000bbc.',
                  '0x801fe17c selects a cached gamma command through 0x801fe04c and calls 0x80191c94.',
                  '0x8024b0c8 and 0x802a5e20 call the cached-table upload path; their selected table contents are not established here.'],
              'unknowns': [
                  'No observed target execution or saved-image effect from either gamma resource.',
                  'Link from resource id 0 through cached-table producers to ordinary still capture remains unestablished.',
                  'Colour domain, channel semantics, calibration assumptions, allowed slopes and downstream transfer function are unresolved.',
                  'Pure Python expansion is an instruction transcription, not independently emulated target output.',
                  'Aligned J/JAL scan can include data false positives and misses indirect calls and other instruction modes.',
                  'GammaDDE has a separate DLCD path and does not provide a confirmed shortcut to saved-photo looks.'],
              'candidate_ready': False}
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps({'evidence': str(args.output), 'candidate_ready': False, 'curves': tables}))


if __name__ == '__main__':
    main()
