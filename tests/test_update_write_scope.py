"""Pure updater predicates/arithmetic, not a NAND simulator or camera test."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tools/vendor')]
from map_update_write_scope import (section_protected, recover_extent,
    boundary_padding, backup_geometry, build_report)


class UpdateWriteScopeTests(unittest.TestCase):
    def test_normal_protection_requires_reserved_size_and_zero_burn(self):
        for section in (0, 1, 2, 4, 5):
            self.assertTrue(section_protected(section, 64, 0, 0, 0))
            self.assertFalse(section_protected(section, 0, 0, 0, 0))
            self.assertFalse(section_protected(section, 64, 1, 1, 1))

    def test_section3_uses_exact_upgrade_and_keep_flags(self):
        self.assertTrue(section_protected(3, 0, 19, 1, 1))
        for flags in ((0, 1), (1, 0), (255, 1), (1, 255)):
            self.assertFalse(section_protected(3, 64, 0, *flags))

    def test_section6_differs_from_normal_predicate(self):
        self.assertTrue(section_protected(6, 0, 0, 1, 0))
        self.assertFalse(section_protected(6, 64, 0, 0, 1))
        self.assertFalse(section_protected(6, 64, 1, 1, 1))

    def test_invalid_sections_words_and_nonbyte_flags_rejected(self):
        for args in ((7,1,0,1,1), (0,-1,0,1,1), (0,1,0,256,1), (True,1,0,1,1)):
            with self.assertRaises(ValueError): section_protected(*args)

    def test_recover_header_floor_then_erase_alignment(self):
        result = recover_extent(1024, 513, 0, 512, 64)
        self.assertEqual(result['burn_sectors'], 3)
        self.assertEqual(result['reserved_sectors'], 64)
        self.assertFalse(result['header_sum_wrapped'])
        self.assertEqual(recover_extent(0, 0, 0, 512, 64)['reserved_sectors'], 0)

    def test_recover_arithmetic_preserves_wrap_instead_of_validating_capacity(self):
        result = recover_extent(0xffffffff, 1, 0, 512, 64)
        self.assertTrue(result['header_sum_wrapped'])
        self.assertEqual(result['burn_sectors'], 0)
        result = recover_extent(0xfffffffe, 0, 0, 1, 64)
        self.assertTrue(result['rounding_add_wrapped'])
        self.assertEqual(result['reserved_sectors'], 0)

    def test_boundary_rule_advances_already_aligned_start_and_records_wrap(self):
        self.assertEqual(boundary_padding(128, 64), {'padding_sectors':64,'aligned_start':192,'wrapped':False})
        self.assertEqual(boundary_padding(129, 64)['padding_sectors'], 63)
        self.assertTrue(boundary_padding(0xffffffff, 64)['wrapped'])

    def test_backup_selects_floor_number_of_blocks_and_is_not_host_backup(self):
        result = backup_geometry(130, 1024, 64)
        self.assertEqual(result['selected_good_blocks'], 2)
        self.assertEqual(result['requested_sector_remainder'], 2)
        self.assertEqual(result['ram_allocation_bytes'], 65536)
        self.assertEqual(result['nominal_total_blocks'], 16)
        self.assertFalse(result['host_backup'])
        self.assertTrue(backup_geometry(0xffffffff, 0xffffffff, 1)['allocation_wrapped'])

    def test_division_by_zero_and_oversized_observations_rejected(self):
        for call in (lambda:recover_extent(0,0,0,0,64), lambda:recover_extent(0,0,0,512,0),
                     lambda:boundary_padding(1,0), lambda:backup_geometry(1,1,0),
                     lambda:backup_geometry(0x100000000,1,1)):
            with self.assertRaises(ValueError): call()

    def test_wrong_source_rejected_before_reading_private_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/'wrong.bin'; source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'Source identity'):
                build_report(root, source, root)


if __name__ == '__main__': unittest.main()
