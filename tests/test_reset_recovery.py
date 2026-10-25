"""Offline boot interpretation boundaries; these tests do not operate a camera."""
import sys
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tools/vendor')]
from map_reset_recovery import chip_selector,destination_class,file_backed_at,build_report


class ResetRecoveryTests(unittest.TestCase):
    def test_known_and_unrecognized_rom_sums(self):
        self.assertEqual(chip_selector(bytes([0xf7])+bytes(63)),0x13a0)
        self.assertEqual(chip_selector(bytes([0x29])+bytes(63)),0x13a1)
        self.assertEqual(chip_selector(bytes(64)),0)

    def test_sum_wrap_and_collision_do_not_imply_rom_identity(self):
        self.assertEqual(chip_selector(bytes([255,248])+bytes(62)),0x13a0)
        self.assertEqual(chip_selector(bytes([246,1])+bytes(62)),0x13a0)

    def test_exact_rom_window_required(self):
        for size in (0,63,65):
            with self.assertRaises(ValueError):chip_selector(bytes(size))

    def test_reserved_skip_window_has_inclusive_edges(self):
        for address in (0xbfc00000,0xbfc07fff):
            self.assertEqual(destination_class(address),{'action':'skip','destination':None})
        self.assertEqual(destination_class(0xbfbfffff)['action'],'stage-then-copy')
        self.assertEqual(destination_class(0xbfc08000),
            {'action':'stage-then-copy','destination':0x90008000})

    def test_destination_classes_are_not_a_ram_whitelist(self):
        self.assertEqual(destination_class(0x80000600),
            {'action':'direct-read','destination':0xa0000600})
        self.assertEqual(destination_class(0x90001234),
            {'action':'stage-then-copy','destination':0x90001234})
        self.assertEqual(destination_class(0),{'action':'direct-read','destination':0x20000000})
        for address in (-1,0x100000000):
            with self.assertRaises(ValueError):destination_class(address)

    def test_alias_coverage_preserves_file_backing_boundary(self):
        parts=[(0x9fc08000,b'abcdefgh')]
        self.assertTrue(file_backed_at(parts,0xbfc08000,8))
        self.assertFalse(file_backed_at(parts,0xbfc08004,8))
        self.assertFalse(file_backed_at(parts,0xbfc00000,4))
        self.assertFalse(file_backed_at(parts,0x9fc00900,64))

    def test_coverage_does_not_join_adjacent_or_different_images(self):
        self.assertFalse(file_backed_at([(0x1000,b'abcd'),(0x1004,b'efgh')],0x1002,4))
        self.assertFalse(file_backed_at([(0x1000,b'abcd')],0x2000,4))
        for address,size in ((0,0),(0,-1),(0xffffffff,2)):
            with self.assertRaises(ValueError):file_backed_at([],address,size)

    def test_unsupported_source_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);source=root/'source.bin';source.write_bytes(b'invalid')
            with self.assertRaisesRegex(ValueError,'identity'):
                build_report(root,source,root)


if __name__=='__main__':unittest.main()
