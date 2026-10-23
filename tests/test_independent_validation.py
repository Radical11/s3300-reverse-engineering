"""Exercise the separate prefix/zlib checker with hand-specified wire bytes."""
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from validate_decoded_firmware import expand_table, transcode


class IndependentCheckerTests(unittest.TestCase):
    def test_literal_via_native_zlib(self):
        # Source codes 0=A, 1=EOB; payload 01, then zero DMA padding.
        output, result = transcode(b"\x40"+bytes(127), (0x8804, 263, 1027), (3,), 1, b"")
        self.assertEqual(output, b"A")
        self.assertEqual(result["end_marker_bit_position"], 2)
        self.assertEqual(result["zero_padding_bits"], 1022)

    def test_overlap_and_cross_block_dictionary_via_zlib(self):
        output, result = transcode(b"\x40"+bytes(127), (0x8804, 0x80f, 1027), (3,), 3, b"Q")
        self.assertEqual(output, b"QQQ")
        self.assertEqual(result["match_tokens"], 1)

    def test_unavailable_dictionary_rejected_by_zlib(self):
        with self.assertRaises(zlib.error):
            transcode(b"\x40"+bytes(127), (0x8804, 0x80f, 1027), (3,), 3, b"")

    def test_nonzero_tail_rejected(self):
        with self.assertRaisesRegex(ValueError, "Nonzero"):
            transcode(b"\x41"+bytes(127), (0x8804, 263, 1027), (3,), 1, b"")

    def test_early_end_rejected(self):
        with self.assertRaisesRegex(ValueError, "incorrect output size"):
            transcode(b"\x80"+bytes(127), (0x8804, 263, 1027), (3,), 1, b"")

    def test_conflicting_direct_alias_rejected(self):
        # Peek two bits, consume one: 00 and 01 must name the same leaf.
        with self.assertRaisesRegex(ValueError, "aliases"):
            expand_table((0x9004, 263, 267, 1027, 1027))

    def test_cyclic_graph_rejected(self):
        with self.assertRaisesRegex(ValueError, "cyclic"):
            expand_table((0x8800, 3))


if __name__ == "__main__":
    unittest.main()
