"""Recover bounded capture/IPP contracts from authenticated v1.1 bytes, offline.

This is independent Capstone analysis, not native REA Evidence or execution.
No firmware is modified. Structure offsets describe observed accesses only.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from workspace_functions import load_analysis, listing
from map_development_interfaces import AddressMap, SOURCE_SHA, digest
from map_application import address_pairs
from map_gamma_pipeline import direct_transfers

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT/'derived/unpacked-v1.1-indexed'


def command_context_index(value):
    """Transcribe 0x8023c778; numeric buckets have no proven shooting names."""
    return {0x40: 0, 0x50: 1, 0xa0: 2, 0xb0: 5}.get(value & 0xffffffff, 8)


def command_id_parts(value):
    """Transcribe 0x801fe7f4/0x801fe82c, retaining unsigned MIPS semantics."""
    value &= 0xffffffff
    if value < 50:
        return 0, value
    if value < 100:
        return 3, value-50
    if value < 200:
        return 1, value-100
    if value < 1000:
        return 4, value-200
    return 2, value-1000


def validate_instruction_facts(mapped, facts):
    """Fail closed when any reviewed source instruction differs."""
    for address, expected_hex in facts:
        if mapped.read(address, 4).hex() != expected_hex:
            raise ValueError(f'Reviewed instruction differs at {address:#x}')


# Selected exact byte assertions supplement the whole-artifact authentication.
FACTS = [
    (0x80205918, '21608000'),  # move t4,a0: earlier candidate omitted this.
    (0x8020591c, '0100a32c'),
    (0x80205920, '0100842c'),
    (0x806af4d4, '34000224'),  # command allocation length
    (0x806af4dc, '1000a2af'),
    (0x806af51c, 'fa8c080c'),
    (0x801fd33c, '0c00838c'),  # context at command+0xc
    (0x801fd364, 'eef10808'),  # tailcall the retained-command dispatcher
    (0x8023db18, '1000043c'),  # dirty bit 0x00100000
    (0x80234e1c, '95be030c'),  # copy command payload
]

STRINGS = {
    0x802540f0: 'DirectConvertRawToYuvEx:',
    0x801abf58: 'In C13 - 420 input to JPEG is not supported in HW.',
    0x801ac044: 'In yuv 420 - Top and Left',
    0x801ac204: "subimage's height when input is yuv 420",
    0x801ac2a0: 'Jpeg decoding to Yuv 420 output is not supported',
    0x8033faa4: 'psCapture->bUseSeperateYuvBuffer',
    0x80343838: 'For DNG format YUV buffer should be separate from RAW',
    0x80341584: 'In case of CW 90 or CW 270 rotation',
    0x8033fc44: 'Does not support!!! if to enable storing JPEG strips',
    0x803458c0: 'StillCaptureImageTunePreviewRunIpp',
    0x80345a4c: 'StillCaptureImageTunePreviewRunIpu',
    0x80342e2c: 'psSensorFrame',
    0x80342e6c: 'sJpegActualSize',
}

WINDOWS = [
    ('raw_to_yuv_wrapper', 0x80205918, 0x484),
    ('ipp_queue_wrapper', 0x802233e8, 0x20),
    ('ipp_route_and_copy', 0x801fd324, 0xb0),
    ('ipp_context_classifier', 0x8023c778, 0x40),
    ('ipp_dispatch_entry', 0x8023c7b8, 0x1d8),
    ('ipp_retained_cache', 0x8023c990, 0xbc),
    ('ipp_dispatch_15_selection', 0x8023cbcc, 0x38),
    ('ipp_dispatch_15_branch', 0x8023d2f0, 0x10),
    ('ipp_dirty_matrix', 0x8023db0c, 0x20),
    ('ipp_payload_copy', 0x80234d4c, 0xe0),
    ('ipp_allocate_cache', 0x80235004, 0x10),
    ('gamma_select_and_upload', 0x801fe17c, 0xec),
    ('still_gamma_call_context', 0x8024b090, 0x40),
    ('processing_gamma_call_context', 0x802a5df4, 0x34),
    ('jpeg_input_setup', 0x801a4490, 0x50),
    ('jpeg_420_conversion_guard', 0x801a4820, 0x24),
    ('jpeg_crop_guard', 0x801a492c, 0x28),
    ('jpeg_subimage_alignment_guard', 0x801a663c, 0x24),
    ('jpeg_decode_420_rejection', 0x801a6c80, 0x18),
    ('capture_separate_buffer_field', 0x803093ec, 0x28),
    ('capture_dng_buffer_diagnostic', 0x803336b0, 0x18),
    ('capture_rotation_diagnostic', 0x8031d098, 0x1c),
    ('preview_ipp_entry', 0x8033bfd0, 0x38),
    ('preview_ipu_entry', 0x8033c650, 0x28),
]


def build_report(mapped, manifest, raw):
    validate_instruction_facts(mapped, FACTS)
    strings = []
    for address, prefix in STRINGS.items():
        text = mapped.text(address)
        if not text.startswith(prefix):
            raise ValueError(f'Diagnostic binding differs at {address:#x}')
        strings.append({'address': address, 'text': text})
    references = []
    for region in manifest['regions']:
        offset, size = region['analysis_elf_offset'], region['size']
        references.extend(address_pairs(region['virtual_start'], raw[offset:offset+size], set(STRINGS)))
    return {
        'source_sha256': SOURCE_SHA, 'analysis_sha256': digest(raw),
        'method': 'Authenticated carrier/ELF, selected exact instruction assertions, bounded MIPS32 linear listings, delay-slot-aware manual trace, address-materialization and J/JAL scans',
        'rea_evidence': False, 'target_executed': False,
        'reviewed_instruction_facts': [{'address': a, 'bytes_hex': h} for a, h in FACTS],
        'diagnostics': strings, 'diagnostic_reference_candidates': references,
        'contracts': [
            {'id': 'capture.raw_to_yuv', 'evidence_type': 'instruction-traced',
             'entry': 0x80205918, 'old_incomplete_candidate': 0x80205924,
             'source_window': 'raw_to_yuv_wrapper',
             'arguments': 'a0/a1 are required descriptor pointers; a2 is a required options pointer whose +0xc member is also required. No original C type recovered.',
             'descriptor_accesses': {'a0': {'word_offsets_copied': list(range(0, 0x1c, 4)), 'local_destination': 'sp+0x24'},
                                     'a1': {'word_offsets_copied': list(range(0, 0x1c, 4)), 'local_destination': 'sp+0x48'}},
             'options_accesses': [{'offset': 0, 'type': 'u32', 'role': 'five-way format dispatch; numeric values 0..4'},
                                  {'offset': 4, 'type': 'u32', 'role': 'policy selector values 1..4 map to 0,4,5,1'},
                                  {'offset': 8, 'type': 'u32', 'role': 'processing-disable choices 1,2,3'},
                                  {'offset': 12, 'type': 'pointer', 'role': 'required; four u16 copied into local command payload'},
                                  {'offset': 16, 'type': 'u8', 'role': 'controls processing mask bit0x10'},
                                  {'offset': 17, 'type': 'u8', 'role': 'controls processing mask bit0x20'},
                                  {'offset': 20, 'type': 'pointer', 'role': 'optional additional command if first word nonzero'},
                                  {'offset': 24, 'type': 'u32', 'role': 'numeric context0x40/0x50/0xb0 -> indices0/1/5'}],
             'path_calls': [0x8018e1d0, 0x801fbc8c, 0x801fc964, 0x80192c7c, 0x80192e04, 0x80190a4c, 0x8030b86c, 0x8018f6e4, 0x8030b8e4, 0x8018e344],
             'ownership': 'Descriptors are copied by value; this does not establish retention/lifetime/cache coherence for pointers inside them. No full-frame allocation/free contract established.',
             'unknowns': ['descriptor field meanings, dimensions/stride/planes, Bayer order, bit depth, clipping, cache ownership, asynchronous completion and active ordinary-capture reachability']},
            {'id': 'capture.command15_retention', 'evidence_type': 'instruction-traced',
             'builder': 0x806af434, 'wrapper': 0x802233e8, 'router': 0x801fd324,
             'external_command_bytes': 0x34,
             'external_fields': {'size': 0, 'command_id': 4, 'secondary_id': 8, 'context': 12, 'bank': 16, 'payload': 24},
             'payload': 'Nine 16-bit matrix coefficients at+0x18..+0x28, two offset halfwords at+0x2a/+0x2c biased by128, one byte at+0x2e, signed source halfword extended to word at+0x30.',
             'contexts_from_color_effect': {'sites': [0x806ac624, 0x806ac62c], 'values': [0x40, 0xb0], 'numeric_cache_indices': [0, 5], 'semantic_names': 'Unestablished; cannot label still/live from these values alone'},
             'ordinary_route': {'condition': 'command+0xc != 0x90', 'callee': 0x8023c7b8,
                                'dirty_word': 0x808c1d78, 'dirty_mask': 0x100000,
                                'cache_pointer_base': 0x808c1d88,
                                'slot_formula': 'base + 4*(74*context_index + 37*bank + command_subindex); id15 yields command_subindex15',
                                'retained_copy': 0x80234d4c,
                                'payload_copy': 'source+0x18 -> retained+0x14; command_length-0x18 bytes, 0x1c for the reviewed command15',
                                'allocation_path': 0x80192c7c,
                                'ownership': 'This synchronous branch retains copied payload before returning; stack command does not itself become the retained buffer. Embedded pointers, replacement allocator failure and eventual hardware application need separate proof.'},
             'special_route': {'condition': 'command+0xc == 0x90', 'allocator': 0x80020980, 'copy': 0x800efa54,
                               'copy_bytes': 'command first word', 'queue': 0x801f5614, 'message': 0x1046,
                               'ownership': 'Allocated full command copy is passed as message argument; receiver/free completion not traced.'},
             'hardware_apply': 'Dirty state and cache retention traced; final matrix MMIO dispatch and active saved-photo context not established.'},
            {'id': 'capture.gamma_normal_still_selector', 'evidence_type': 'instruction-traced',
             'classifier': 0x801fe3c0, 'static_input': 0, 'classification_result': 0,
             'call_sites': [0x8024b0c8, 0x802a5e20],
             'first_call_arguments': 'a0=global[0x808c1c04], a1=0, a2=word at active s4+0x3c',
             'second_call_arguments': 'a0=0, a1=0, a2=stack+0x9c',
             'cached_table_selector': 0x801fe04c, 'cached_command_pointers': 0x808c1cf8,
             'cached_table_offset_rule': 'selected object+8==12 -> object+0x150; otherwise object+0x1b0',
             'uploader': 0x80191c94,
             'unknowns': ['table producers and normal-mode active command contents', 'resource id0 selection', 'sensor/RGB/YUV domain and calibration requirements']},
            {'id': 'capture.jpeg_constraints', 'evidence_type': 'diagnostics-with-local-guards',
             'compiled_sdk_family_diagnostic': 'C13',
             'constraints': [
                 {'string': 0x801abf58, 'reference': 0x801a4834, 'guard': 'input halfword+2 ==1 enters branch checking flags at+0x68 &0x40', 'meaning': '420 input requires the existing ICA conversion path and flag0x40; hardware JPEG does not directly accept420 per diagnostic'},
                 {'string': 0x801ac044, 'reference': 0x801a4944, 'guard': 'branch checks odd bit via andi1', 'meaning': '420 crop top and left must be even per diagnostic; full operand provenance remains partial'},
                 {'string': 0x801ac204, 'reference': 0x801a6650, 'guard': 'andi0xf, branch to diagnostic when nonzero', 'meaning': 'subimage height multiple16 for420 input or420 output per diagnostic; full mode conditions need trace'},
                 {'string': 0x801ac2a0, 'reference': 0x801a6c88, 'guard': 'rejection diagnostic, incoming branch provenance unresolved', 'meaning': 'JPEG decode to420 unsupported in this SDK path per diagnostic'}],
             'limit': 'Compiled code constraints are not proof of active camera format, silicon identity, sensor model or device measurements.'},
            {'id': 'capture.buffer_separation', 'evidence_type': 'diagnostic-tied-to-field',
             'field_read_site': 0x80309408, 'field_offset': 0x1b3, 'field_type': 'u8',
             'field_diagnostic': 0x8033faa4, 'base': 's1 in selected capture-processing function; not a stable public pointer ABI',
             'dng_separation_diagnostic': {'string': 0x80343838, 'reference': 0x803336b8},
             'unknowns': ['where separation is set', 'RAW/YUV alias lifetime', 'active image sizes', 'whether DNG path is exposed on S3300']},
            {'id': 'capture.preview_separate_entries', 'evidence_type': 'directly-bound-entry-diagnostic',
             'ipp': {'entry': 0x8033bfd0, 'diagnostic': 0x803458c0},
             'ipu': {'entry': 0x8033c650, 'diagnostic': 0x80345a4c},
             'limit': 'These named tuning-preview paths must not be substituted for proof that an effect changes an ordinary saved JPEG.'},
        ],
        'direct_transfer_encoding_candidates': direct_transfers(manifest['regions'], raw, {0x80205918, 0x801fd324, 0x8023c7b8, 0x80234d4c, 0x8033bfd0, 0x8033c650}),
        'limitations': [
            'All new findings are independent offline Capstone observations/inferences, not retained native REA Evidence or target execution.',
            'Bounded analyst windows outside compiler-unwind coverage do not prove complete function boundaries or reachable control flow.',
            'J/JAL and LUI address scans can include data false positives and miss indirect calls, GP-relative references and other instruction modes.',
            'No end-to-end saved-JPEG integration hook, safe frame-buffer ABI, physical sensor model, RAM budget or recovery mechanism is established.',
            'No firmware bytes, device state or candidate were changed.'
        ], 'ready_for_saved_photo_patch': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/capture-contracts.json')
    parser.add_argument('--listings', type=Path, default=ROOT/'derived/capture-contracts')
    args = parser.parse_args()
    args.workspace = args.workspace.resolve()
    args.output = args.output.resolve()
    args.listings = args.listings.resolve()
    if not args.listings.is_relative_to(ROOT.resolve()):
        raise ValueError('Keep local firmware-derived listings inside the project')
    if args.output.exists() or args.listings.exists():
        raise FileExistsError('Use fresh evidence and listing paths')
    if digest((ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin').read_bytes()) != SOURCE_SHA:
        raise ValueError('Unsupported baseline carrier')
    manifest, raw = load_analysis(args.workspace)
    mapped = AddressMap(raw, manifest['regions'])
    report = build_report(mapped, manifest, raw)
    sys.path.insert(0, str(ROOT/'tools/vendor'))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    args.listings.mkdir(parents=True)
    report['listings'] = []
    for name, address, size in WINDOWS:
        body = mapped.read(address, size)
        decoded = list(decoder.disasm(body, address))
        if sum(i.size for i in decoded) != size:
            raise ValueError(f'Incomplete linear decoding for {name}')
        path = args.listings/(name+'.asm')
        path.write_text('; Bounded analyst window; not a proven function boundary. Branch delay slots matter.\n'+
                        '\n'.join(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic:10} {i.op_str}' for i in decoded)+'\n')
        report['listings'].append({'name': name, 'start': address, 'bytes': size, 'sha256': digest(body), 'path': path.relative_to(ROOT).as_posix(), 'boundary_type': 'analyst-window'})
    for address in (0x806ac078, 0x806ac4dc, 0x806af434):
        text, metadata = listing(args.workspace, address)
        path = args.listings/f'{address:08x}.asm'
        path.write_text(text)
        report['listings'].append({**metadata, 'path': path.relative_to(ROOT).as_posix(), 'boundary_type': 'compiler-unwind'})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps({'evidence': str(args.output), 'contracts': len(report['contracts']), 'listings': len(report['listings']), 'ready_for_saved_photo_patch': False}))


if __name__ == '__main__':
    main()
