"""Observed-value scanner/debounce models; no MMIO, host event or camera calls."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tools/vendor')]
from map_shutter_input import snap_sample,debounce_step,snap_events,selected_view_handler,build_report


class ShutterInputTests(unittest.TestCase):
    def test_register_zero_conditions_are_whole_u32_comparisons(self):
        self.assertEqual(snap_sample(1,1),0)
        self.assertEqual(snap_sample(0,1),2)
        self.assertEqual(snap_sample(1,0),1)
        self.assertEqual(snap_sample(0,0),3)
        self.assertEqual(snap_sample(0x80000000,0x100),0)
        with self.assertRaises(ValueError):snap_sample(-1,0)

    def test_first_changed_scan_is_candidate_only_then_matching_scan_accepts(self):
        first=debounce_step(0,0,False,2,3,3)
        self.assertTrue(first['pending']);self.assertFalse(first['accepted']);self.assertEqual(first['previous'],0)
        second=debounce_step(first['previous'],first['candidate'],first['pending'],2,3,3)
        self.assertTrue(second['accepted']);self.assertEqual(second['rising'],2);self.assertEqual(second['falling'],0)
        self.assertEqual(second['previous'],2);self.assertFalse(second['pending'])

    def test_changed_candidate_requires_new_pair_not_immediate_replacement(self):
        first=debounce_step(0,0,False,2,3,3)
        bounce=debounce_step(first['previous'],first['candidate'],first['pending'],3,3,3)
        self.assertFalse(bounce['pending']);self.assertFalse(bounce['accepted']);self.assertEqual(bounce['candidate'],2)
        third=debounce_step(0,bounce['candidate'],bounce['pending'],3,3,3)
        self.assertTrue(third['pending']);self.assertFalse(third['accepted'])
        fourth=debounce_step(0,third['candidate'],third['pending'],3,3,3)
        self.assertTrue(fourth['accepted']);self.assertEqual(fourth['rising'],3)

    def test_return_to_previous_cancels_pending_transition(self):
        result=debounce_step(0,2,True,0,3,3)
        self.assertFalse(result['pending']);self.assertFalse(result['accepted'])
        self.assertEqual(result['rising'],0);self.assertEqual(result['falling'],0)

    def test_release_and_disabled_masks_do_not_fabricate_events(self):
        disabled=debounce_step(3,0,True,0,0,0x7000)
        self.assertTrue(disabled['accepted']);self.assertEqual(disabled['previous'],0)
        self.assertEqual(disabled['falling'],0)
        enabled=debounce_step(3,0,True,0,3,3)
        self.assertEqual(enabled['falling'],3);self.assertEqual(snap_events(0,enabled['falling']),[0x112,0x111])
        rise=debounce_step(0,3,True,3,0,3)
        self.assertTrue(rise['accepted']);self.assertEqual(rise['rising'],0)

    def test_two_snap_mapping_order_and_other_keys_excluded(self):
        self.assertEqual(snap_events(3,0),[0x102,0x101])
        self.assertEqual(snap_events(0,3),[0x112,0x111])
        self.assertEqual(snap_events(0,0),[])
        with self.assertRaises(ValueError):snap_events(4,0)

    def test_widths_and_pending_type_are_explicit(self):
        for args in ((0,0,False,0x10000,3,3),(0,0,1,0,3,3),(False,0,False,0,3,3),(0,0,False,0,-1,3)):
            with self.assertRaises(ValueError):debounce_step(*args)

    def test_exact_view_state_matters(self):
        self.assertEqual(selected_view_handler(0x2050),0x80707590)
        self.assertEqual(selected_view_handler(0x2051),0x80704598)
        self.assertEqual(selected_view_handler(0x2060),0x806ff834)
        self.assertIsNone(selected_view_handler(0x2000))
        with self.assertRaises(ValueError):selected_view_handler(0x12050)

    def test_wrong_source_rejected_before_native_reads(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);source=root/'bad.bin';source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'Source identity'):build_report(root,source,root)


if __name__=='__main__':unittest.main()
