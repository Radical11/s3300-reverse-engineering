"""Target arithmetic and asynchronous segment ownership boundaries."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from map_saved_jpeg_path import jpeg_input_plan, store_event_contract, validate_facts


class SavedJpegPathTests(unittest.TestCase):
    def frame(self, **edits):
        row = dict(data_address=0x81000000, frame_width=640, frame_height=480,
                   left=0, top=0, width=640, height=480)
        row.update(edits)
        return row

    def test_selector0_roi_rebase_uses_parent_width(self):
        result = jpeg_input_plan(self.frame(left=10, top=3, width=100), 0)
        self.assertEqual(result['image_address'], 0x81000000 + (3*640+10)*2)
        self.assertIsNone(result['chroma_address'])
        self.assertFalse(result['capacity_or_colour_domain_verified'])
        self.assertEqual(result['aps_argument_offset'],8)
        self.assertFalse(result['jpeg_input_kind_established'])

    def test_selector1_rounds_row_and_column_separately(self):
        result = jpeg_input_plan(self.frame(frame_width=3, frame_height=2, top=1, left=1), 1)
        self.assertEqual(result['image_address'], 0x81000000+4+1)
        self.assertEqual(result['chroma_address'], result['image_address']+16)
        # floor(9/2)+floor(3/2) differs from floor((9+3)/2).
        self.assertNotEqual(result['image_address'], 0x81000000+6)

    def test_selector1_explicit_chroma_pointer_is_not_rebased(self):
        result = jpeg_input_plan(self.frame(left=2, top=4), 1, 0xa1234567)
        self.assertEqual(result['chroma_address'], 0xa1234567)
        self.assertFalse(result['capacity_or_colour_domain_verified'])

    def test_wrap_in_roi_and_base_is_visible(self):
        result = jpeg_input_plan(self.frame(data_address=0xfffffff0, left=32), 0)
        self.assertEqual(result['image_address'], 48)
        self.assertTrue(result['image_arithmetic_wrapped'])
        result = jpeg_input_plan(self.frame(frame_width=0xffffffff, top=2), 1)
        target_row = (((2*0xffffffff)&0xffffffff)*3)&0xffffffff
        self.assertEqual(result['image_address'], (0x81000000+(target_row>>1))&0xffffffff)
        self.assertTrue(result['image_arithmetic_wrapped'])

    def test_unknown_layouts_and_non_u32_values_rejected(self):
        for selector in (-1,2,3,True,0.0):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                jpeg_input_plan(self.frame(), selector)
        for value in (-1,0x100000000,True,3.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                jpeg_input_plan(self.frame(left=value), 0)

    def test_store_chunk_events_transfer_segment_ownership(self):
        for event,flags in ((0x105a,12),(0x105b,4),(0x105d,4)):
            row=store_event_contract(event)
            self.assertEqual(row['writer_flags'],flags)
            self.assertTrue(row['segment_data_consumed'])
            self.assertFalse(row['safe_for_arbitrary_pointer'])
        for event in (0x1002,0x1059,0x105c):
            row=store_event_contract(event)
            self.assertFalse(row['segment_data_consumed'])
            self.assertFalse(row['safe_for_arbitrary_pointer'])

    def test_event_table_is_closed(self):
        for value in (0x1042,0x105e,0,-1,True,'0x105a'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                store_event_contract(value)

    def test_authenticated_instruction_assertion_rejects_stale_bytes(self):
        class Map:
            def read(self,address,size):
                if (address,size)!=(0x1000,4): raise ValueError('Out of synthetic map')
                return bytes.fromhex('2d740c0c')
        validate_facts(Map(), {0x1000:'2d740c0c'})
        with self.assertRaisesRegex(ValueError,'differs'):
            validate_facts(Map(), {0x1000:'00000000'})


if __name__=='__main__': unittest.main()
