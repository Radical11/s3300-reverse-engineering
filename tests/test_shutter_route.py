"""Capture selector/queue interpretation tests, never camera commands."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tools/vendor')]
from map_shutter_route import capture_mode_contract,capture_thread_contract,describe_pipe_record,build_report


class ShutterRouteTests(unittest.TestCase):
    def test_capture_family_named_selectors(self):
        expected={0x50:0,0x53:1,0x55:3,0x58:6,0x60:2,0x61:5,0x62:7}
        self.assertEqual({mode:capture_mode_contract(mode,0)['selector']for mode in expected},expected)

    def test_default_capture_arm_and_state_gate_are_explicit(self):
        self.assertEqual(capture_mode_contract(0x5f,0)['selector'],0)
        self.assertTrue(capture_mode_contract(0x50,0)['post_when_app_state_zero'])
        self.assertFalse(capture_mode_contract(0x50,1)['post_when_app_state_zero'])
        self.assertFalse(capture_mode_contract(0x50,0xffffffff)['post_when_app_state_zero'])

    def test_other_families_and_non_u32_values_rejected(self):
        for mode,state in ((0x40,0),(0xf4,0),(0x150,0),(-1,0),(0x50,-1),(True,0)):
            with self.subTest(mode=mode,state=state),self.assertRaises(ValueError):capture_mode_contract(mode,state)

    def test_thread_selector_is_not_a_buffer_pointer(self):
        for selector in (0,1,3,6):
            row=capture_thread_contract(selector)
            self.assertEqual(row['entry'],0x80333458);self.assertEqual(row['argument'],selector)
            self.assertEqual(row['stack_bytes'],12000)
        self.assertEqual(capture_thread_contract(2)['argument'],0)
        self.assertEqual(capture_thread_contract(5)['argument'],1)
        self.assertIsNone(capture_thread_contract(5)['stack_bytes'])
        self.assertEqual(capture_thread_contract(7)['name'],'Capture_Sequence_HDR')
        with self.assertRaises(ValueError):capture_thread_contract(8)

    def test_pointer_words_remain_tokens_and_no_ownership_is_inferred(self):
        row=describe_pipe_record(bytes.fromhex('441000007856348100000000ffffffff'))
        self.assertEqual(row,{'event':0x1044,'argument0':0x81345678,'argument1':0,'tail':0xffffffff,
            'queue_offset':8,'pointee_ownership_established':False})

    def test_urgent_queue_selects_only_exact_minus_two_event(self):
        self.assertEqual(describe_pipe_record(struct.pack('<4I',0xfffffffe,1,2,0xffffffff))['queue_offset'],0x40)
        self.assertEqual(describe_pipe_record(struct.pack('<4I',0xfffffff8,1,2,0xffffffff))['queue_offset'],8)
        self.assertEqual(describe_pipe_record(struct.pack('<4I',0xfffffffd,1,2,0))['tail'],0)

    def test_exact_record_extent_required(self):
        for length in (0,12,15,17,32):
            with self.assertRaises(ValueError):describe_pipe_record(bytes(length))

    def test_wrong_source_stops_before_native_reads(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);source=root/'wrong.bin';source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'Source identity'):build_report(root,source,root)


if __name__=='__main__':unittest.main()
