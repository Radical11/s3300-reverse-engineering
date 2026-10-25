"""Authenticate the asynchronous StillImage -> ApsJpeg -> ApsSave path.

Offline static investigation only. No firmware patch or device request is made.
The arithmetic helpers model reviewed target operations, not a usable SDK API.
"""
import argparse
import json
from pathlib import Path

from map_capture_buffers import (SOURCE_SHA, sha, require_u32, FRAME_FIELDS,
    validate_facts, reference_scan)
from map_development_contracts import (ROOT, WORKSPACE, AddressMap, load_analysis,
    Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x8023a030, 0x8023a05c, 0x8023f458, 0x8031e060,
    0x8031d0b4, 0x8031aa5c, 0x8030c010, 0x80325f1c,
    0x8032b20c, 0x8032b0fc, 0x8032b1a8, 0x80310c30,
    0x803133ec, 0x80319380, 0x8030e240, 0x8030e27c,
    0x8030e2d4, 0x8030e9e0, 0x8030e458, 0x8030ed78,
    0x8030eeb4, 0x8030ef84, 0x8030f2d8, 0x8032c004,
    0x8032be70, 0x80097418)
WINDOWS = (("file_compressor_pipe_loop", 0x8031dfd0, 0x90),
    ("store_pipe_loop", 0x8032c1b4, 0x424),
    ("segment_write_callback", 0x8030e7d4, 0x20c))
FACTS = {
    0x8031e00c: "04d6070c",  # Receive pipe7 message
    0x8031e020: "2d740c0c",  # FileCompressor -> StillImage
    0x8031d878: "976a0c0c", 0x8031de60: "976a0c0c",
    0x8031b848: "83ac0c0c", 0x8031b860: "6aac0c0c",
    0x8031ca38: "fb4c0c0c", 0x8031cbfc: "0c430c0c",
    0x8030c10c: "6082000c", 0x80325fac: "a583000c",
    0x80325fb8: "540000ae",  # Clear released capture image pointer
    0x8032b2c8: "0c00438e",  # args+0xc -> descriptor
    0x8032b31c: "02200971", 0x8032b324: "40380800",
    0x8032b5e0: "02180971", 0x8032b5f4: "42781900",
    0x8032b5f8: "42981800", 0x8032b610: "0000668c",
    0x8032b388: "7438060c", 0x8032b578: "725d060c",
    0x8032b580: "3c5e060c", 0x8032b120: "b25e060c",
    0x8032b1c0: "3fac0c0c", 0x8032b1cc: "d138060c",
    0x8032c218: "04d6070c", 0x8032c264: "e13b0c0c",
    0x8032c328: "e13b0c0c", 0x8032c354: "e13b0c0c",
    0x8032c378: "b63c0c0c", 0x8032c3a8: "01b00c0c",
    0x8032c480: "ad3b0c0c", 0x8030e83c: "065d020c",
    0x8030e8c4: "a583000c", 0x8030e8dc: "a583000c",
}
U32 = 0xffffffff


def jpeg_input_plan(frame, layout_selector, chroma_data_address=None):
    """Transcribe ApsJpeg argument+8 layout arithmetic, not JPEG input kind.

    The target uses low32 arithmetic at each step. A pointer-shaped result is
    not proof of capacity, packing, colour space, coherence or accessibility.
    """
    f = {name: require_u32(frame[name]) for name in FRAME_FIELDS}
    if type(layout_selector) is not int or layout_selector not in (0, 1):
        raise ValueError("Only reviewed ApsJpeg address-layout selectors0 and1 are modeled")
    base, width, height = f['data_address'], f['frame_width'], f['frame_height']
    left, top = f['left'], f['top']
    if layout_selector == 0:
        offset = (((top * width) & U32) + left) & U32
        mathematical = base + (top * width + left) * 2
        result = {'image_address': (base + ((offset << 1) & U32)) & U32,
                  'chroma_address': None}
    else:
        row = (((top * width) & U32) * 3) & U32
        column = (left * 3) & U32
        address = (base + (row >> 1) + (column >> 1)) & U32
        mathematical = base + (top * width * 3 >> 1) + (left * 3 >> 1)
        if chroma_data_address is None:
            extent = ((width * height + 15) & U32) & 0xfffffff0
            chroma = (address + extent) & U32
        else:
            chroma = require_u32(chroma_data_address)
        result = {'image_address': address, 'chroma_address': chroma}
    result.update(address_layout_selector=layout_selector, aps_argument_offset=8,
        jpeg_input_kind_established=False,
        unbounded_image_address=mathematical,
        image_arithmetic_wrapped=result['image_address'] != mathematical,
        capacity_or_colour_domain_verified=False,
        scope='address arithmetic only; no memory read, allocation or SDK adapter')
    return result


def store_event_contract(event):
    """Known pipe3 dispatch arms, with local writer flags and ownership scope."""
    if type(event) is not int: raise ValueError('Event must be an integer')
    rows = {
        0x1002: ('8032c004', None, 'whole-file preparation/write/close route'),
        0x1059: ('8030eeb4', None, 'open shared file state; subsequent chunk events required'),
        0x105a: ('8030ef84', 12, 'write chunks, consume owned segments, seek-related flag8'),
        0x105b: ('8030ef84', 4, 'write chunks and consume owned segments'),
        0x105c: ('8030f2d8', None, 'seek shared file state'),
        0x105d: ('8030ef84', 4, 'write chunks and consume owned segments, then finish route'),
    }
    if event not in rows: raise ValueError('Event outside reviewed store dispatch arms')
    handler, flags, meaning = rows[event]
    return {'event': event, 'handler': handler, 'writer_flags': flags,
            'segment_data_consumed': flags is not None and bool(flags & 4),
            'meaning': meaning, 'safe_for_arbitrary_pointer': False}


def build_report(workspace, source_path, native):
    if sha(source_path.read_bytes()) != SOURCE_SHA: raise ValueError('Source identity differs')
    manifest, raw = load_analysis(workspace)
    mapping = AddressMap(raw, manifest['regions'])
    validate_facts(mapping, FACTS)
    corroboration = check_dossiers(native / 'application', mapping, sha(raw), FUNCTIONS)
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    windows = []
    for label, address, length in WINDOWS:
        body = mapping.read(address, length)
        decoded = list(decoder.disasm(body, address))
        if sum(row.size for row in decoded) != length: raise ValueError('Incomplete window decode')
        windows.append({'label': label, 'start': address, 'length': length,
            'sha256': sha(body), 'instructions': len(decoded),
            'boundary': 'analyst-bounded original-byte window; no native function boundary claimed'})
    report = {'schema_version': 1, 'source_sha256': SOURCE_SHA,
      'analysis_sha256': sha(raw),
      'method': 'Authenticated instruction bytes with independent Capstone and direct Ghidra dossiers; not REA Evidence',
      'target_executed': False, 'camera_commands_issued': False,
      'instruction_assertions': len(FACTS), 'native_corroboration': corroboration,
      'bounded_windows': windows,
      'contracts': [
        {'id': 'saved-photo.compressor_queue', 'status': 'static-route-verified',
         'server_forwarder': 0x8023a030, 'pipe': 7, 'event': 0x1042,
         'thread_create': 0x8031e060, 'thread_name': 'FileCompressor',
         'thread_window': 0x8031dfd0, 'receive': 0x801f5810,
         'consumer': 0x8031d0b4, 'consumer_call_site': 0x8031e020,
         'image_processor': 0x8031aa5c,
         'limits': ['Shutter event producer and complete sensor-to-pipe reachability are not established.',
                    'The recovered queue arm proves static routing, not execution on the connected camera.']},
        {'id': 'saved-photo.capture_descriptor', 'object_descriptor_offset': 0x54,
         'descriptor_bytes': 28, 'fields': list(FRAME_FIELDS),
         'allocator': 0x8030c010, 'normal_branch': 'If pointer+54 is zero, align dimensions via80190204, allocate low32(width*height*2), store pointer+54; optional percentage/HDR branches change extent and origin.',
         'image_processor': 0x8031aa5c, 'jpeg_arguments_descriptor_offset': 0xc,
         'release': 0x80325f1c,
         'ownership': 'Capture object owns or borrows image according to mode. Release may free pointer+54 or use another pool route, then clears it. A caller cannot retain this descriptor beyond the capture lifecycle.',
         'constraints': ['No universal two-byte pixel format inferred from allocation size.',
                        'Mode-specific pool ownership, aliases, active descriptor values and byte pitch remain unresolved.']},
        {'id': 'saved-photo.jpeg_execution', 'create_go': 0x8032b20c,
         'finish': 0x8032b0fc, 'finish_destroy': 0x8032b1a8,
         'sequence': [0x8018e1d0, 0x801975c8, 0x801978f0, 0x80197ac8, 0x801a400c, 0x8018e344],
         'return': 'Create/go returns path or0. Finish returns encoded byte count, invokes801a40e4 if wait fails or output count exceeds supplied capacity, optionally returns second count. Finish/destroy requires nonzero path, returns count after deleting path.',
         'input_plan': 'Selector0 rebases data by low32((top*frame_width+left)*2). Selector1 adds separate floor(low32(top*width*3)/2) and floor(low32(left*3)/2), then uses supplied chroma data or aligned frame area after rebased image.',
         'constraints': ['Arithmetic is not bounds validation; overflow and selector-specific packing must be respected.',
                        'Queue/event synchronization is essential; create/go returns before finish waits.',
                        'This does not establish CPU colour domain or permit the RGB creative-look module.']},
        {'id': 'saved-photo.file_assembly', 'exif_builders': [0x80310c30, 0x803133ec],
         'segment_append': 0x8030e2d4, 'segment_allocate': 0x8030e240,
         'segment_size': 32, 'segment_fields': {'data': 8, 'length': 12},
         'file_property_size': 56, 'list_offset': 0x28,
         'store_strip': 0x80319380,
         'ownership': 'Segment nodes retain data addresses, not byte copies. The asynchronous writer can unlink and free both segment data and node under flag4; producers must transfer ownership or select a different reviewed lifecycle.',
         'limits': ['Full format-dependent list content and all error/race cases are not proved.']},
        {'id': 'saved-photo.store_queue', 'server_forwarder': 0x8023a05c,
         'pipe': 3, 'thread_window': 0x8032c1b4,
         'events': [store_event_contract(x) for x in (0x1002,0x1059,0x105a,0x105b,0x105c,0x105d)],
         'whole_file_route': [0x8032c004,0x8032be70,0x8030ed78,0x8030e5e0,0x8030e9e0,0x8030ec14],
         'chunk_route': [0x8030ef84,0x8030e9e0,0x8030e7d4,0x80097418],
         'write_callback_window': 0x8030e7d4,
         'write_arguments': {'a0': 'file object', 'a1': 'segment+8 data pointer', 'a2': 'segment+0xc length'},
         'write_error': 'Nonzero filesystem status records failure, closes/frees file object and marks shared write state failed. Later chunks can be dropped.',
         'limits': ['Software filesystem return does not establish power-loss durability or physical media bounds.',
                    'These stateful write routines are research entries, not exposed SDK adapters.']}
      ],
      'reachability_search': reference_scan(manifest, raw, 0x8031d0b4),
      'remaining_gates': ['Trace shutter/sensor producer through capture queue under the active Auto-mode configuration.',
          'Recover exact packing, pixel range, active stride, allocation capacity and ownership for a selected saved-photo hook.',
          'Prove cache/DMA ownership at that hook, including concurrency with preview and encoders.',
          'Establish complete backup, unbootable software recovery, safe placement and hook ABI.'],
      'safe_capture_adapter_established': False, 'ready_for_executable_trial': False}
    if sha(source_path.read_bytes()) != SOURCE_SHA: raise ValueError('Source changed during analysis')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native', type=Path, default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/saved-jpeg-path.json')
    args = parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose a new evidence path')
    report = build_report(args.workspace, args.source, args.native)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2); handle.write('\n')
    print(json.dumps({'contracts': len(report['contracts']), 'instruction_assertions': len(FACTS),
        'native_dossiers': len(FUNCTIONS), 'safe_capture_adapter_established': False}))


if __name__ == '__main__': main()
