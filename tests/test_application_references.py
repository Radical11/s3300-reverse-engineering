"""Address-reference scanner arithmetic and false-positive guards."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from map_application import address_pairs, candidate_prologue


def encoded(*instructions):
    return struct.pack("<"+"I"*len(instructions), *instructions)


class ApplicationReferenceTests(unittest.TestCase):
    def test_positive_low_half(self):
        body = encoded(0x3c048025, 0x248475d4)
        refs = address_pairs(0x80001000, body, {0x802575d4})
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["lui_address"], 0x80001000)
        self.assertEqual(refs[0]["low_address"], 0x80001004)

    def test_signed_low_half_requires_high_half_carry(self):
        body = encoded(0x3c048026, 0x2484f5d4)
        self.assertEqual(len(address_pairs(0, body, {0x8025f5d4})), 1)
        self.assertEqual(address_pairs(0, body, {0x8026f5d4}), [])

    def test_ori_low_half_is_unsigned(self):
        body = encoded(0x3c048025, 0x3484f5d4)
        self.assertEqual(len(address_pairs(0, body, {0x8025f5d4})), 1)

    def test_addiu_clobber_rejects_stale_high_half(self):
        body = encoded(0x3c048025, 0x24040000, 0x248475d4)
        self.assertEqual(address_pairs(0, body, {0x802575d4}), [])

    def test_load_clobber_rejects_stale_high_half(self):
        body = encoded(0x3c048025, 0x8c840000, 0x248475d4)
        self.assertEqual(address_pairs(0, body, {0x802575d4}), [])

    def test_zero_register_is_not_a_high_half(self):
        body = encoded(0x3c008025, 0x240475d4)
        self.assertEqual(address_pairs(0, body, {0x802575d4}), [])

    def test_scheduled_pair_with_other_register(self):
        body = encoded(0x3c048025, 0x24050001, 0x248475d4)
        self.assertEqual(len(address_pairs(0, body, {0x802575d4})), 1)

    def test_prologue_requires_saved_return_address(self):
        body = encoded(0x27bdffe0, 0, 0, 0)
        self.assertIsNone(candidate_prologue(0x80001000, body, 0x8000100c))
        body = encoded(0x27bdffe0, 0xafbf0018, 0, 0)
        candidate = candidate_prologue(0x80001000, body, 0x8000100c)
        self.assertEqual(candidate["virtual_address"], 0x80001000)
        self.assertEqual(candidate["stack_allocation"], 32)
        self.assertIn("not a proven", candidate["confidence"])


if __name__ == "__main__":
    unittest.main()
