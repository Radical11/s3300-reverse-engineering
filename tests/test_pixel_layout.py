"""Reviewed selector/word-pitch arithmetic; no target buffer is accessed."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tools/vendor')]
from map_pixel_layout import constructor_input_guards, dma_input_geometry, build_report


class PixelLayoutTests(unittest.TestCase):
    def test_kind1_requires_conversion_and_even_chroma_origin(self):
        self.assertIn('kind1-requires-conversion-flag40', constructor_input_guards(1, 0)['failures'])
        self.assertTrue(constructor_input_guards(1, 0x40, 2, 4)['reviewed_guards_pass'])
        self.assertIn('kind1-chroma-left-and-top-must-be-even', constructor_input_guards(1, 0x40, 1, 4)['failures'])
        self.assertFalse(constructor_input_guards(1, 0x40)['safe_buffer_access_established'])

    def test_kind0_does_not_inherit_kind1_checks(self):
        result = constructor_input_guards(0, 0, 1, 1)
        self.assertTrue(result['reviewed_guards_pass'])
        self.assertFalse(result['safe_buffer_access_established'])

    def test_parent_pitch_and_word_rounding_distinguish_kind(self):
        packed = dma_input_geometry(641, 640, 0)
        separated = dma_input_geometry(641, 640, 1)
        self.assertEqual((packed['parent_pitch_bytes_arithmetic'], packed['parent_pitch_words'], packed['burst_words']), (1282, 321, 8))
        self.assertEqual((separated['parent_pitch_bytes_arithmetic'], separated['parent_pitch_words'], separated['burst_words']), (641, 161, 4))

    def test_roi_width_rounding_does_not_replace_parent_pitch(self):
        result = dma_input_geometry(1024, 641, 0)
        self.assertEqual(result['rounded_roi_width'], 656)
        self.assertEqual(result['parent_pitch_words'], 512)
        self.assertEqual(result['selected_transfer_height'], 8)

    def test_orientation_flag_and_secondary_option_select_block(self):
        narrow = dma_input_geometry(640, 17, 0, 0x80, 0, 3)
        wide = dma_input_geometry(640, 17, 0, 0x80, 1, 3)
        self.assertEqual((narrow['horizontal_block'], narrow['rounded_roi_width'], narrow['selected_transfer_height']), (8, 24, 16))
        self.assertEqual((wide['horizontal_block'], wide['rounded_roi_width'], wide['selected_transfer_height']), (16, 32, 16))

    def test_roi_rounding_wrap_is_visible(self):
        result = dma_input_geometry(640, 0xffffffff, 0)
        self.assertTrue(result['roi_rounding_wrapped'])
        self.assertEqual(result['rounded_roi_width'], 0)

    def test_pitch_shift_and_word_rounding_wrap_are_distinct(self):
        shifted = dma_input_geometry(0x80000000, 1, 0)
        rounded = dma_input_geometry(0xffffffff, 1, 1)
        self.assertTrue(shifted['pitch_shift_wrapped'])
        self.assertEqual(shifted['parent_pitch_words'], 0)
        self.assertFalse(rounded['pitch_shift_wrapped'])
        self.assertTrue(rounded['pitch_word_rounding_wrapped'])
        self.assertEqual(rounded['parent_pitch_words'], 0)

    def test_other_u16_kinds_share_arithmetic_without_format_claim(self):
        result = dma_input_geometry(640, 320, 2)
        self.assertEqual(result['parent_pitch_words'], 320)
        self.assertFalse(result['safe_buffer_access_established'])

    def test_invalid_field_widths_and_types_rejected(self):
        for args in ((-1, 1, 0), (1, 1, 0x10000), (True, 1, 0), (1, 1, True)):
            with self.assertRaises(ValueError): dma_input_geometry(*args)
        with self.assertRaises(ValueError): constructor_input_guards(1, 0x100000000)

    def test_source_mismatch_rejected_before_native_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root/'wrong.bin'; source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'identity'):
                build_report(root, source, root)


if __name__ == '__main__': unittest.main()
