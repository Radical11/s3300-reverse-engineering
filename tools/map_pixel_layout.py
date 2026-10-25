"""Distinguish JPEG input kind from ApsJpeg addressing and DMA geometry.

Source-bound static metadata and pure arithmetic only; no live image access,
colour transform, firmware patch, camera request or callable adapter.
"""
import argparse
import json
from pathlib import Path

from map_capture_buffers import SOURCE_SHA, sha, require_u32, validate_facts
from map_development_contracts import ROOT, WORKSPACE, AddressMap, load_analysis
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x8031aa5c, 0x8032b20c, 0x801a4490, 0x801a5c40)
FACTS = {
    0x8031abcc: 'd4029390', 0x8031abd4: '1404b3af',
    0x8031b6dc: 'd4023f92', 0x8031b6f0: '4c04bfaf',
    0x8031b7e8: '4c04ab8f', 0x8031b830: 'd801abaf',
    0x8031b840: 'd401a0af', 0x8031b848: '83ac0c0c',
    0x8031b954: '1404ae8f', 0x8031b970: 'd801aeaf',
    0x8031b974: 'd401a0af', 0x8031b9f8: '83ac0c0c',
    0x8032b2cc: '08005f8e', 0x8032b2d0: '0400428e',
    0x8032b2f4: '4200a2a7', 0x8032b2f8: '4400bfa7',
    0x8032b31c: '02200971', 0x8032b324: '40380800',
    0x801a44b4: '0200a394', 0x801a44bc: 'da0023a6',
    0x801a44c4: '0400a594', 0x801a44cc: 'dc0025a6',
    0x801a4820: '40008730', 0x801a483c: 'fe2d030c',
    0x801a5c58: 'c0014c7c', 0x801a5c74: 'dc00a795',
    0x801a5c80: '0b488500', 0x801a5c84: '10000724',
    0x801a5c8c: 'da00a595', 0x801a5c98: '1b00e901',
    0x801a5cb4: '5100aa10', 0x801a5cbc: '0400df8c',
    0x801a5cc4: '40101f00', 0x801a5cc8: '03004224',
    0x801a5ccc: '82500200', 0x801a5cd0: '0c000bad',
    0x801a5cd8: '14000aad', 0x801a5dfc: '0400c28c',
    0x801a5e04: '82580900',
}
MASK = 0xffffffff


def require_u16(value):
    if type(value) is not int or not 0 <= value <= 0xffff:
        raise ValueError('Expected an observed unsigned16 selector')
    return value


def constructor_input_guards(input_kind, flags, chroma_left=0, chroma_top=0):
    """Only the kind1 flag/alignment checks, not all constructor validation."""
    kind = require_u16(input_kind); flags = require_u32(flags)
    left, top = require_u32(chroma_left), require_u32(chroma_top)
    failures = []
    if kind == 1:
        if not flags & 0x40: failures.append('kind1-requires-conversion-flag40')
        if left & 1 or top & 1: failures.append('kind1-chroma-left-and-top-must-be-even')
    return {'reviewed_guards_pass': not failures, 'failures': failures,
            'safe_buffer_access_established': False,
            'scope': 'Only reviewed input-kind guards; no pointer/capacity/ownership validation'}


def dma_input_geometry(parent_width, roi_width, input_kind, flags=0,
                       secondary_option=0, transfer_height=8):
    """Initial always-executed geometry in801a5c40, preserving MIPS wrapping.

    This deliberately omits the later orientation/operation-dependent DMA
    descriptor fields, address validation, component order and hardware work.
    """
    parent_width, roi_width, flags, transfer_height = map(require_u32,
        (parent_width, roi_width, flags, transfer_height))
    kind, secondary = require_u16(input_kind), require_u16(secondary_option)
    orientation_bit = bool(flags & 0x80)
    block = 8 if orientation_bit and secondary != 1 else 16
    selected_height = 16 if orientation_bit else transfer_height
    numerator = (roi_width + block - 1) & MASK
    aligned = ((numerator // block) * block) & MASK
    pitch = parent_width if kind == 1 else (parent_width << 1) & MASK
    words = ((pitch + 3) & MASK) >> 2
    return {'input_kind': kind, 'orientation_flag80': orientation_bit,
        'horizontal_block': block, 'rounded_roi_width': aligned,
        'parent_pitch_bytes_arithmetic': pitch, 'parent_pitch_words': words,
        'burst_words': block >> (2 if kind == 1 else 1),
        'selected_transfer_height': selected_height,
        'roi_rounding_wrapped': roi_width + block - 1 > MASK,
        'pitch_shift_wrapped': kind != 1 and parent_width * 2 > MASK,
        'pitch_word_rounding_wrapped': pitch + 3 > MASK,
        'safe_buffer_access_established': False}


def build_report(workspace, source, native):
    if sha(source.read_bytes()) != SOURCE_SHA: raise ValueError('Source identity differs')
    manifest, raw = load_analysis(workspace); mapping = AddressMap(raw, manifest['regions'])
    validate_facts(mapping, FACTS)
    corroboration = check_dossiers(native / 'application', mapping, sha(raw), FUNCTIONS)
    diagnostic = bytearray()
    for offset in range(256):
        value = mapping.read(0x801abf58 + offset, 1)
        if value == b'\0': break
        diagnostic.extend(value)
    else: raise ValueError('Unterminated JPEG diagnostic')
    if b'420 input to JPEG' not in diagnostic or b'ICA' not in diagnostic:
        raise ValueError('Expected kind1 conversion diagnostic differs')
    return {'schema_version': 1, 'source_sha256': SOURCE_SHA,
        'analysis_sha256': sha(raw),
        'method': 'Authenticated original instruction words and direct Ghidra dossiers, not REA Evidence',
        'target_executed': False, 'camera_commands_issued': False,
        'instruction_assertions': len(FACTS), 'native_corroboration': corroboration,
        'diagnostic': {'address': 0x801abf58, 'sha256': sha(bytes(diagnostic)),
            'meaning': 'Kind1 is named420 input; this target requires ICA420-to422 conversion flag40'},
        'contracts': [
            {'id': 'jpeg.selectors_are_distinct', 'status': 'static-contract-verified',
             'aps_entry': 0x8032b20c, 'arguments': {'input_kind_u32': 4, 'address_layout_u32': 8},
             'options': {'input_kind_u16': 2, 'secondary_option_u16': 4},
             'context': {'input_kind_u16': 0xda, 'secondary_option_u16': 0xdc},
             'flow': 'ApsJpeg copies argument+4 low16 to options+2, and argument+8 low16 to options+4. Constructor801a4490 stores them separately.',
             'constraint': 'Address-layout selector1 is not evidence that JPEG input-kind equals1.'},
            {'id': 'jpeg.still_image_selector_origin', 'status': 'static-contract-verified',
             'caller': 0x8031aa5c, 'calls': [0x8031b848, 0x8031b9f8],
             'input_kind': 0, 'address_layout_source': 'Capture byte+2d4 through retained stack slots44c/414 into ApsJpeg argument+8',
             'constraints': ['These two branches explicitly pass input-kind0; do not label them420 merely from argument+8.',
                 'Live Auto-mode state and full path branch selection remain unobserved.']},
            {'id': 'jpeg.kind1_conversion', 'status': 'static-guard-verified',
             'constructor': 0x801a4490, 'input_kind': 1,
             'required_flag': 0x40, 'chroma_alignment': 'Left and top must both be even',
             'side_effects': 'Conversion path allocates and initializes ICA path through indirect factory; options/context may be adjusted.',
             'constraints': ['Known420 naming does not define component byte order, numeric range or full plane capacity.',
                 'Constructor is stateful and asserting; these are not sufficient public call guards.']},
            {'id': 'jpeg.dma_input_geometry', 'status': 'static-arithmetic-verified',
             'address': 0x801a5c40, 'arguments': 'a0 context,a1 DMA fields,a2 seven-u32 frame descriptor,a3 transfer-height quantity',
             'selector': 'context+da ==1 uses parent width as byte-pitch arithmetic; other kinds double it before rounding to32-bit words',
             'horizontal_block': 'Normally16; when context flags+420 bit80 set and secondary option+dc !=1,8',
             'orientation': 'Flag80 forces transfer-height quantity16; later descriptor branches differ',
             'writes': 'Rounds descriptor ROI width+14 in place; writes burst words at DMA+0c and parent-pitch words at DMA+14',
             'constraints': ['Original arithmetic wraps at32 bits without complete capacity validation.',
                 'Geometry in this internal helper is not proof of CPU-readable RAM, live ownership, range or colour domain.',
                 'Later DMA address/row descriptors and all synchronization remain outside the pure helper model.']}],
        'remaining_gates': ['Resolve component order and numeric range at a selected active capture hook.',
            'Verify live descriptor values, pitch/capacity and allocation lifetime for that hook.',
            'Verify scheduler, cache-line and DMA ownership while preview/JPEG are active.',
            'Establish safe executable placement, hook ABI and independent software recovery.'],
        'rgb8_adapter_verified': False, 'safe_capture_adapter_established': False,
        'ready_for_executable_trial': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native', type=Path, default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/pixel-layout.json')
    args = parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose a new report path')
    report = build_report(args.workspace, args.source, args.native)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle: json.dump(report, handle, indent=2); handle.write('\n')
    print(json.dumps({'contracts': len(report['contracts']), 'instruction_assertions': len(FACTS),
        'native_dossiers': len(FUNCTIONS), 'safe_capture_adapter_established': False}))


if __name__ == '__main__': main()
