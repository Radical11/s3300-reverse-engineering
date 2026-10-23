import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from map_unwind import leb, parse_headers


class UnwindHeaderTests(unittest.TestCase):
    CIE = struct.pack("<II", 12, 0)+b"\x01\0\x01\x04\x1f\x0c\x1d\0"
    REGION = {"virtual_start": 0x80001000, "size": 0x1000,
              "permissions": 5, "sha256": "synthetic"}

    def fde(self, start=0x80001000, size=16, backref=20):
        return struct.pack("<4I", 12, backref, start, size)

    def test_absolute_function_range_and_cie_backreference(self):
        cies, functions = parse_headers(self.CIE+self.fde(), 0x80008000, [self.REGION])
        self.assertEqual(cies[0]["fde_pointer_encoding"], 0)
        self.assertEqual(functions[0]["cie_address"], 0x80008000)
        self.assertEqual(functions[0]["end_exclusive"], 0x80001010)

    def test_unknown_cie_backreference_rejected(self):
        with self.assertRaisesRegex(ValueError, "earlier parsed CIE"):
            parse_headers(self.CIE+self.fde(backref=4), 0x80008000, [self.REGION])

    def test_source_escape_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside validated"):
            parse_headers(self.CIE+self.fde(start=0x80001ffc), 0x80008000, [self.REGION])

    def test_nonexecutable_region_rejected(self):
        region = {**self.REGION, "permissions": 4}
        with self.assertRaisesRegex(ValueError, "non-executable"):
            parse_headers(self.CIE+self.fde(), 0x80008000, [region])

    def test_overlapping_ranges_rejected(self):
        data = self.CIE+self.fde()+self.fde(start=0x80001008, backref=36)
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            parse_headers(data, 0x80008000, [self.REGION])

    def test_unsorted_records_are_sorted_without_assuming_order(self):
        data = self.CIE+self.fde(start=0x80001020)+self.fde(backref=36)
        _, functions = parse_headers(data, 0x80008000, [self.REGION])
        self.assertEqual([f["start"] for f in functions], [0x80001000, 0x80001020])

    def test_truncated_record_rejected(self):
        with self.assertRaisesRegex(ValueError, "record length"):
            parse_headers(self.CIE+self.fde()[:-1], 0x80008000, [self.REGION])

    def test_signed_leb_and_bounds(self):
        self.assertEqual(leb(b"\x7c", 0, True), (-4, 1))
        with self.assertRaisesRegex(ValueError, "Truncated"):
            leb(b"\x80", 0)


if __name__ == "__main__":
    unittest.main()
