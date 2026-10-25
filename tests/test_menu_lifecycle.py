"""Bounded existing-menu list semantics, not a custom control API."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tools/vendor')]
from map_menu_lifecycle import (open_selection, child_selection, mark_selected,
    replace_parent_low5, build_report)


def entries(flags):
    return b''.join(bytes([0xa0 + index, 0x80, flag]) for index, flag in enumerate(flags))


class MenuLifecycleTests(unittest.TestCase):
    def test_open_skips_disabled_entries_and_wraps(self):
        result = open_selection(entries([0, 2, 2]), 2)
        self.assertEqual(result['selected'], 0)
        self.assertEqual(result['skipped_entries'], 1)
        self.assertFalse(result['selected_disabled'])

    def test_all_disabled_stops_at_original_disabled_entry(self):
        result = open_selection(entries([2, 2, 2]), 1)
        self.assertEqual(result['selected'], 1)
        self.assertEqual(result['skipped_entries'], 3)
        self.assertTrue(result['selected_disabled'])
        self.assertFalse(result['safe_camera_adapter'])

    def test_child_sentinel_restores_highest_marked_entry(self):
        result = child_selection(entries([1, 0, 1, 0]))
        self.assertEqual(result['selected'], 2)
        self.assertTrue(result['selected_marked'])

    def test_child_sentinel_can_restore_disabled_mark_and_falls_back_to_zero(self):
        marked = child_selection(entries([0, 3, 0]))
        self.assertEqual(marked['selected'], 1)
        self.assertTrue(marked['selected_disabled'])
        fallback = child_selection(entries([0, 0, 0]))
        self.assertEqual(fallback['selected'], 0)
        self.assertFalse(fallback['selected_marked'])

    def test_explicit_child_argument_uses_disabled_skip_behavior(self):
        self.assertEqual(child_selection(entries([2, 0, 0]), 0)['selected'], 1)

    def test_selection_marker_preserves_entry_bytes_and_other_flags(self):
        original = entries([0x83, 0x44, 0x21])
        changed = mark_selected(original, 1)
        self.assertEqual(changed[2::3], bytes([0x82, 0x45, 0x20]))
        self.assertEqual(changed[0::3], original[0::3])
        self.assertEqual(changed[1::3], original[1::3])

    def test_parent_selection_preserves_upper_flags_and_truncates_low_five(self):
        self.assertEqual(replace_parent_low5(0xa0, 0x123), 0xa3)
        self.assertEqual(replace_parent_low5(0xff, 0), 0xe0)

    def test_model_rejects_unbacked_indices_and_incomplete_entries(self):
        for body, index in ((b'', 0), (b'xx', 0), (entries([0, 0]), 2), (entries([0]), -1)):
            with self.assertRaises(ValueError): open_selection(body, index)
        with self.assertRaises(ValueError): child_selection(entries([0]), 0x10000)
        with self.assertRaises(ValueError): mark_selected(bytes(65536 * 3), 0)

    def test_source_mismatch_rejected_before_native_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root/'wrong.bin'; source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'identity'): build_report(root, source, root)


if __name__ == '__main__': unittest.main()
