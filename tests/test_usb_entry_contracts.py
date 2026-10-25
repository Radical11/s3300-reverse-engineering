"""Bounded MIPS32 call/delay-slot and internal mode predicate interpretation."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tools/vendor')]
from map_usb_entry_contracts import jal_target,a0_delay_constant,test_mode_flag,build_report


class UsbEntryTests(unittest.TestCase):
    def test_jal_target_uses_pc_plus_four_region(self):
        self.assertEqual(jal_target(0x0c1dc71a,0x8059ba8c),0x80771c68)
        self.assertEqual(jal_target(0x0c000000,0x8ffffffc),0x90000000)
        self.assertIsNone(jal_target(0x081dc71a,0x8059ba8c)) # J is not JAL

    def test_invalid_instruction_location_rejected(self):
        for word,pc in ((0x0c000000,1),(-1,0),(0,0x100000000)):
            with self.assertRaises(ValueError):jal_target(word,pc)

    def test_constants_in_delay_slot_affect_call_argument(self):
        self.assertEqual(a0_delay_constant(0x24040005),5)
        self.assertEqual(a0_delay_constant(0x24040007),7)
        self.assertEqual(a0_delay_constant(0x00002021),0)
        self.assertEqual(a0_delay_constant(0x2404ffff),-1) # sign extension, not an allowed mode

    def test_unresolved_or_wrong_register_argument_is_not_invented(self):
        for word in (0,0x24050006,0x24840006,0x00802021):
            with self.assertRaises(ValueError):a0_delay_constant(word)

    def test_predicate_polarity_and_high_bits(self):
        for word in (0x0008,0x1238,0xfff8):self.assertFalse(test_mode_flag(word))
        for word in (0,4,6,7,9,0xffff):self.assertTrue(test_mode_flag(word))
        # Startup stores inverse of the predicate, then mode0 requires that byte0.
        self.assertEqual(int(not test_mode_flag(4)),0)
        self.assertEqual(int(not test_mode_flag(8)),1)

    def test_predicate_requires_observed_word(self):
        for word in (-1,0x10000):
            with self.assertRaises(ValueError):test_mode_flag(word)

    def test_wrong_source_rejected_before_native_reads(self):
        with tempfile.TemporaryDirectory()as folder:
            path=Path(folder);source=path/'firmware.bin';source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'identity'):build_report(path,source,path,path)


if __name__=='__main__':unittest.main()
