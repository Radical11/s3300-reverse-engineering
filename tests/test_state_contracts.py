"""Synthetic tests for bounds and fail-closed state-contract evidence checks."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from map_development_interfaces import AddressMap
from map_state_contracts import check_instructions, decode_window, paired_dispatch_records


class StateContractsTests(unittest.TestCase):
    def fixture(self):
        raw = bytearray(64)
        struct.pack_into("<4I", raw, 0, 0x1020, 0, 0x1028, 3)
        struct.pack_into("<2I", raw, 32, 0x03e00008, 0)
        return AddressMap(bytes(raw), [{"virtual_start": 0x1000,
                                       "analysis_elf_offset": 0, "size": len(raw)}])

    def test_record_flags_are_receive_bits_not_permissions(self):
        records = paired_dispatch_records(self.fixture(), 0x1000, 2)
        self.assertEqual([r["handler"] for r in records], [0x1020, 0x1028])
        self.assertEqual([r["receive_before_handler_bit0"] for r in records], [False, True])
        self.assertEqual(records[1]["raw_flags"], 3)

    def test_null_handler_preserved(self):
        result = paired_dispatch_records(self.fixture(), 0x1010, 1)
        self.assertEqual(result[0]["handler"], 0)

    def test_table_bounds_rejected(self):
        for base, count in ((0x1001, 1), (0x1000, 0), (0x1000, 1025)):
            with self.subTest(base=base, count=count), self.assertRaises(ValueError):
                paired_dispatch_records(self.fixture(), base, count)

    def test_unbacked_handler_rejected(self):
        fixture = self.fixture()
        raw = bytearray(fixture.data)
        struct.pack_into("<I", raw, 0, 0x2000)
        fixture.data = bytes(raw)
        with self.assertRaisesRegex(ValueError, "uniquely backed"):
            paired_dispatch_records(fixture, 0x1000, 1)

    def test_unaligned_handler_rejected(self):
        fixture = self.fixture()
        raw = bytearray(fixture.data)
        struct.pack_into("<I", raw, 0, 0x1021)
        fixture.data = bytes(raw)
        with self.assertRaisesRegex(ValueError, "Unaligned"):
            paired_dispatch_records(fixture, 0x1000, 1)

    def test_window_decode_includes_delay_slot(self):
        raw, instructions = decode_window(self.fixture(), 0x1020, 8)
        self.assertEqual(len(raw), 8)
        self.assertEqual([(i.mnemonic, i.op_str) for i in instructions], [("jr", "$ra"), ("nop", "")])

    def test_invalid_window_bounds_rejected(self):
        for address, size in ((0x1021, 4), (0x1020, 0), (0x1020, 3)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                decode_window(self.fixture(), address, size)

    def test_changed_and_missing_instructions_rejected(self):
        expected = {0x1020: ("jr", "$ra")}
        self.assertEqual(check_instructions(expected, expected), 1)
        for observed in ({}, {0x1020: ("j", "0x1040")}):
            with self.assertRaisesRegex(ValueError, "changed"):
                check_instructions(observed, expected)


if __name__ == "__main__":
    unittest.main()
