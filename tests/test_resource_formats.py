"""Hand-built format fixtures, independent of vendor resource generation."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from resource_formats import decode_zst, encode_zst, decode_zbm, encode_zbm


def string_fixture(width, records):
    header = bytearray(22)
    header[:4] = b"ZST\0"
    struct.pack_into("<I", header, 4, len(records)+1)
    struct.pack_into("<H", header, 20, width)
    body = bytes(header)+bytes(2*width)
    for record in records:
        body += struct.pack("<H", len(record))+record+bytes(width)
    return body


def bitmap_fixture(width, height, bits, pixels):
    header = bytearray(32)
    struct.pack_into("<HHI", header, 4, width, height, bits)
    return bytes(header)+pixels


class StringResourceTests(unittest.TestCase):
    def test_ascii_and_empty_record_roundtrip(self):
        raw = string_fixture(1, [b"custom", b""])
        document = decode_zst(raw)
        self.assertEqual(document["entries"][0]["text_projection"], "custom")
        self.assertEqual(encode_zst(document), raw)

    def test_big_endian_code_units_not_assumed_little_endian(self):
        raw = string_fixture(2, [b"\x00A\x12\x34"])
        document = decode_zst(raw)
        self.assertEqual(document["entries"][0]["code_units"], [65, 0x1234])
        self.assertEqual(encode_zst(document), raw)

    def test_code_units_are_authoritative_and_editable(self):
        raw = string_fixture(2, [b"\x00A"])
        document = decode_zst(raw)
        document["entries"][0]["code_units"] = [66]
        self.assertEqual(decode_zst(encode_zst(document))["entries"][0]["text_projection"], "B")

    def test_declared_count_must_consume_file_exactly(self):
        with self.assertRaisesRegex(ValueError, "Unparsed"):
            decode_zst(string_fixture(1, [b"A"])+b"tail")

    def test_truncated_string_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            decode_zst(string_fixture(2, [b"\x00A"])[:-1])

    def test_nonzero_terminator_rejected(self):
        raw = bytearray(string_fixture(1, [b"A"]))
        raw[-1] = 1
        with self.assertRaisesRegex(ValueError, "terminator"):
            decode_zst(raw)

    def test_odd_width_two_length_rejected(self):
        with self.assertRaisesRegex(ValueError, "partial"):
            decode_zst(string_fixture(2, [b"A"]))

    def test_accidental_entry_reordering_rejected(self):
        document = decode_zst(string_fixture(1, [b"A", b"B"]))
        document["entries"].reverse()
        with self.assertRaisesRegex(ValueError, "ordinal"):
            encode_zst(document)

    def test_partial_default_region_rejected(self):
        raw = string_fixture(2, [])
        with self.assertRaisesRegex(ValueError, "default"):
            decode_zst(raw[:-1])


class BitmapResourceTests(unittest.TestCase):
    def test_nonzero_header_marker_rejected_by_encoder(self):
        document = decode_zbm(bitmap_fixture(2, 1, 4, b"\x12"))
        header = bytearray.fromhex(document["header_hex"])
        struct.pack_into("<I", header, 0, 0xdeadbeef)
        document["header_hex"] = header.hex()
        with self.assertRaisesRegex(ValueError, "marker"):
            encode_zbm(document)

    def test_four_bit_indices_preserve_nonzero_unused_nibble(self):
        raw = bitmap_fixture(3, 1, 4, b"\x12\x3f")
        document = decode_zbm(raw)
        self.assertEqual(document["rows"], [[1, 2, 3]])
        self.assertEqual(document["unused_low_row_bits"], [15])
        self.assertEqual(encode_zbm(document), raw)

    def test_one_bit_indices_preserve_row_padding(self):
        raw = bitmap_fixture(3, 2, 1, b"\xa7\x5e")
        document = decode_zbm(raw)
        self.assertEqual(document["rows"], [[1, 0, 1], [0, 1, 0]])
        self.assertEqual(encode_zbm(document), raw)

    def test_size_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "geometry"):
            decode_zbm(bitmap_fixture(4, 1, 4, b"\x12"))

    def test_index_outside_palette_range_rejected(self):
        document = decode_zbm(bitmap_fixture(2, 1, 4, b"\x12"))
        document["rows"][0][0] = 16
        with self.assertRaisesRegex(ValueError, "index"):
            encode_zbm(document)

    def test_changed_geometry_rejected(self):
        document = decode_zbm(bitmap_fixture(2, 1, 4, b"\x12"))
        document["width"] = 4
        with self.assertRaisesRegex(ValueError, "disagreement"):
            encode_zbm(document)


if __name__ == "__main__":
    unittest.main()
