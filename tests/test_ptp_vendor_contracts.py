"""Offline registry decoding and source-identity rejection checks."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tools/vendor')]
from map_ptp_vendor_contracts import parse_registry, build_report


class PtpVendorContractsTests(unittest.TestCase):
    def test_complete_registry_required(self):
        for length in (0, 12, 0xbff, 0xc01):
            with self.assertRaises(ValueError): parse_registry(bytes(length))

    def test_unsigned_opcode_and_independent_flag_bytes(self):
        body = bytearray(0xc00)
        body[12:24] = bytes.fromhex('029001ff0200000004db5780')
        rows = parse_registry(body)
        self.assertEqual(len(rows), 256)
        self.assertEqual(rows[1], {'opcode': 0x9002, 'route': 1, 'disabled': 255,
            'data_phase': 2, 'handler': 0x8057db04, 'slot': 1})
        self.assertEqual(rows[0]['opcode'], 0)

    def test_last_record_is_included(self):
        body = bytearray(0xc00)
        struct.pack_into('<HBBII', body, 255 * 12, 0xffff, 0, 1, 0, 0x80781028)
        rows = parse_registry(body)
        self.assertEqual(rows[-1]['slot'], 255)
        self.assertEqual(rows[-1]['handler'], 0x80781028)
        self.assertEqual(rows[-1]['opcode'], 0xffff)

    def test_wrong_source_rejected_before_analysis_or_emulation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'wrong.bin'; source.write_bytes(b'not firmware')
            with self.assertRaisesRegex(ValueError, 'Source differs'):
                build_report(Path(directory), source, Path(directory))


if __name__ == '__main__': unittest.main()
