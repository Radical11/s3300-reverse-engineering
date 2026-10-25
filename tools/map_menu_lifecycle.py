"""Recover existing Color Options creation, navigation and close ownership.

Offline source-bound static checks and pure bounded list models only. No menu
registration API, device call, setting write or firmware patch is exposed.
"""
import argparse
import json
from pathlib import Path
import struct

from map_capture_buffers import SOURCE_SHA, sha, require_u32, validate_facts
from map_development_contracts import ROOT, WORKSPACE, AddressMap, load_analysis
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x805b0200, 0x805ae9b8, 0x805af460, 0x805b1558,
    0x805aad94, 0x805ac85c, 0x805ab198, 0x805a8bf4, 0x805a7070,
    0x806fbc00, 0x806fc080, 0x806fbab0, 0x806fba5c,
    0x806fc2a4, 0x806fc3e4, 0x806fc4f0)
FACTS = {
    0x805af8b8: '05001124', 0x805af8bc: '1000ccad',
    0x805af8c0: '5005b1ad', 0x805af8c4: '1a006b90',
    0x805af8dc: '5cc84625', 0x805af8e0: '20088424',
    0x805af8e4: '04008bad', 0x805af8e8: '1c0089ad',
    0x805af8ec: '200086ad', 0x805af8f0: '180089ad',
    0x805af8f4: '14000cae', 0x805af8f8: '240084ad',
    0x805af900: '100095ad', 0x805af904: '0c0080ad',
    0x805af908: '280080a1', 0x805af914: '0f000624',
    0x806fbc1c: '887104ae', 0x806fbc20: '040085ac',
    0x806fbc3c: '0200e330', 0x806fbc7c: '0700c511',
    0x806fbcac: '1800f98f', 0x806fbcb0: '09f82003',
    0x806fc0a8: '0000458c', 0x806fc0c0: '887125ae',
    0x806fc0c8: '53008a50', 0x806fc120: '2e006410',
    0x806fbaec: '21809100', 0x806fbafc: 'ba91030c',
    0x806fbb14: 'fc1762ae', 0x806fbb5c: '240067ac',
    0x806fbb78: 'c391030c', 0x806fbb84: 'fc1760ae',
    0x806fba94: 'c391030c', 0x806fba9c: 'fc1700ae',
    0x805aadb4: '2000628c', 0x805aadb8: '09f84000',
    0x805aadc0: '1e004014', 0x805ac8cc: '1a003fa3',
}


def entry_flags(body):
    if not isinstance(body, (bytes, bytearray)) or not body or len(body) % 3:
        raise ValueError('Expected nonempty three-byte menu entries')
    if len(body) // 3 > 0xffff: raise ValueError('Model count is bounded to u16 loop capacity')
    return list(body[2::3])


def open_selection(body, start):
    """806fbc00 disabled-skip behavior within an analyst-bounded valid list.

    The original helper does not validate its initial index or allocation.
    These model input checks must not be described as target safety checks.
    """
    flags = entry_flags(body)
    if type(start) is not int or not 0 <= start < len(flags):
        raise ValueError('Initial index outside model list; target lacks this guard')
    selected = start; visited = 0
    while flags[selected] & 2:
        selected += 1; visited += 1
        if selected >= len(flags): selected = 0
        if selected == start: break
    return {'selected': selected, 'skipped_entries': visited,
        'selected_disabled': bool(flags[selected] & 2),
        'safe_camera_adapter': False}


def child_selection(body, requested=0xffff):
    """806fc080 static-child selection arm; dynamic list allocation excluded."""
    flags = entry_flags(body)
    if type(requested) is not int or not 0 <= requested <= 0xffff:
        raise ValueError('Expected u16 child selection argument')
    if requested != 0xffff: return open_selection(body, requested)
    selected = len(flags) - 1
    while selected and not flags[selected] & 1: selected -= 1
    return {'selected': selected, 'selected_marked': bool(flags[selected] & 1),
        'selected_disabled': bool(flags[selected] & 2), 'safe_camera_adapter': False}


def mark_selected(body, selected):
    flags = entry_flags(body)
    if type(selected) is not int or not 0 <= selected < len(flags):
        raise ValueError('Selected index outside model list; target lacks this guard')
    result = bytearray(body)
    for index in range(len(flags)): result[index * 3 + 2] &= 0xfe
    result[selected * 3 + 2] |= 1
    return bytes(result)


def replace_parent_low5(old_byte, selected):
    if type(old_byte) is not int or not 0 <= old_byte <= 255:
        raise ValueError('Expected parent status byte')
    selected = require_u32(selected)
    return (old_byte & 0xe0) | (selected & 0x1f)


def build_report(workspace, source, native):
    if sha(source.read_bytes()) != SOURCE_SHA: raise ValueError('Source identity differs')
    manifest, raw = load_analysis(workspace); mapping = AddressMap(raw, manifest['regions'])
    validate_facts(mapping, FACTS)
    corroboration = check_dossiers(native / 'application', mapping, sha(raw), FUNCTIONS)
    ids = struct.unpack('<5H', mapping.read(0x8065a6b6, 10))
    if ids != (560, 561, 562, 563, 564): raise ValueError('Color Options text IDs differ')
    return {'schema_version': 1, 'source_sha256': SOURCE_SHA,
        'analysis_sha256': sha(raw),
        'method': 'Authenticated original instruction words and direct Ghidra dossiers, not REA Evidence',
        'camera_commands_issued': False, 'target_executed': False,
        'instruction_assertions': len(FACTS), 'native_corroboration': corroboration,
        'contracts': [
            {'id': 'menu.view_creation', 'status': 'static-route-verified',
             'entry': 0x805b0200, 'builders': [0x805ae9b8, 0x805af460],
             'effects': 'Sets mode2100, resets root globals809f05b8..05e0, builds root/submenu objects, opens through806fbc00 or806fc624 depending state.',
             'auto_root_handler': 0x805b1558, 'auto_root_enter': 'Events106/108 call805af460(6), then806fc080(ffff), subject to mode guards.',
             'constraints': ['Creation mutates shared UI globals and display/capture lifecycle; not a standalone registrar.',
                 'Builder cases6/7 and runtime mode state expose different menu sets.']},
            {'id': 'menu.color_object_registration', 'status': 'static-contract-verified',
             'builder': 0x805af460, 'object': 0x809f0550, 'root_child_index': 4,
             'creation_condition': 'Builder argument6 and runtime mode80891ea8 neither2 nor3; other branches expose different submenus.',
             'count': 5, 'selection_source': 'Active view byte+1a',
             'parent': 0x809f05b8, 'related_self': 0x809f0550,
             'render_callbacks': [0x805c099c, 0x805c099c], 'event_handler': 0x805ac85c,
             'entry_array': 0x809f0820, 'entry_stride': 3, 'entry_array_bytes': 15,
             'dynamic_flag28': 0, 'text_ids': list(ids),
             'ownership': 'Static shared RAM object and entry array initialized by existing builder; no private heap ownership is granted.',
             'constraints': ['Valid existing selection indices0..4; generic helpers do not prove bounds before first entry access.',
                 'Parent low-five-bit status encoding and u16 loop counters constrain any generalized use.']},
            {'id': 'menu.open_and_child_selection', 'status': 'static-contract-verified',
             'open': 0x806fbc00, 'enter_child': 0x806fc080,
             'open_behavior': 'Sets global current pointer80107188, truncates initial selection to16bits, skips flag2 disabled entries with wrap, invokes render callback+18.',
             'child_behavior': 'Static parent chooses child through pointer-array+0c at4*current; dynamic parent uses first pointer.ffff searches backward from child count-1 for entry flag1, stopping at0.',
             'disabled_boundary': 'All-disabled open cycle returns to original disabled entry; no universal no-selection result is returned.',
             'constraints': ['Nonnull callbacks, valid parent/child arrays, count and selection are caller assumptions.',
                 'ffff restores a marked choice, not a universal cancel token.']},
            {'id': 'menu.dynamic_entry_ownership', 'status': 'static-contract-partial',
             'allocate': 0x806fbab0, 'free': 0x806fba5c, 'global_buffer': 0x808917fc,
             'sequence': 'Free previous global list if nonzero; clear it; allocate low32(count*3); zero list; update current object+24 only if dynamic flag+28 is nonzero.',
             'failure': 'Allocation failure logs and returns before replacing current object entry pointer; no rollback to freed previous list is established.',
             'transition_cleanup': 'Parent-return helpers free this shared list when current dynamic flag28 is nonzero before switching current object.',
             'constraints': ['Single shared allocation slot; cannot retain entry-array pointers across replacement/close.',
                 'This allocation helper does not allocate/own a complete menu object.']},
            {'id': 'menu.color_commit_and_cancel', 'status': 'static-route-verified',
             'handler': 0x805ac85c,
             'preview': 'Events103/104 change temporary current selection, apply it through807132d0, wait100ticks; active-view+1a is not committed there.',
             'commit': 'Events106/108 store selection to active-view+1a, update parent flags, apply colour, call805a7070 then806fc2a4.',
             'parent_return': 'Event105 calls806fc2a4 without the active-view+1a commit store, then reapplies saved active-view colour.',
             'close': 'Events102/107/10e/124 call805ab198 cleanup/exit, then reapply saved active-view colour.',
             'persistence_boundary': '806fc2a4 stages mode-selected state and calls80009644 whenever parent pointer+10 is nonzero, even on the105 parent-return route; no blanket no-write-on-cancel rule.',
             'constraints': ['80009644 return is ignored by the transition; successful UI return does not prove persistence success.',
                 'Physical key mappings and all mode/error/cancellation races remain unverified.']},
            {'id': 'menu.event_dispatch_contract', 'status': 'static-contract-verified',
             'dispatcher': 0x805aad94, 'handler_offset': 0x20,
             'behavior': 'Invokes current menu handler first; nonzero result consumes event. Zero result continues outer system/card/capture handling.',
             'constraints': ['Custom handler return conventions and event lifecycle cannot be omitted.',
                 'No supported dynamic menu-registration ABI or verified custom persistent control is exposed.']}],
        'remaining_gates': ['Complete physical event-to-current-menu routing for a chosen control.',
            'Verify safe object/list lifetime, callback registration and bounds across all modes.',
            'Verify custom Original bypass, persistence error handling and cancellation.',
            'Establish backup, reset-independent software recovery and executable hook ABI.'],
        'existing_menu_lifecycle_statically_traced': True,
        'custom_control_adapter_verified': False, 'ready_for_executable_trial': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, default=ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native', type=Path, default=ROOT/'derived/native-analysis-complete')
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/menu-lifecycle.json')
    args = parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose an unused report path')
    report = build_report(args.workspace, args.source, args.native)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle: json.dump(report, handle, indent=2); handle.write('\n')
    print(json.dumps({'contracts': len(report['contracts']), 'instruction_assertions': len(FACTS),
        'custom_control_adapter_verified': False}))


if __name__ == '__main__': main()
