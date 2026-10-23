import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from map_branding import english_records, jpeg_frame


class BrandingMetadataTests(unittest.TestCase):
    def test_jpeg_frame_dimensions(self):
        body = b"\xff\xd8\xff\xc0"+struct.pack(">H B H H B", 8, 8, 480, 640, 3)
        result = jpeg_frame(body)
        self.assertEqual((result["width"], result["height"]), (640, 480))
        self.assertEqual(result["components"], 3)

    def test_jpeg_segment_outside_carrier_rejected(self):
        with self.assertRaisesRegex(ValueError, "segment size"):
            jpeg_frame(b"\xff\xd8\xff\xe0\xff\xff")

    def test_truncated_jpeg_marker_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated JPEG marker"):
            jpeg_frame(b"\xff\xd8\xff")

    def test_english_string_ordinal_is_not_runtime_id(self):
        header = bytearray(26)
        header[:4] = b"ZST\0"
        struct.pack_into("<I", header, 4, 2)
        struct.pack_into("<H", header, 20, 2)
        raw = "None".encode("utf-16be")
        records = english_records(header+struct.pack("<H", len(raw))+raw+b"\0\0")
        self.assertEqual(records[0]["text"], "None")
        self.assertFalse(records[0]["runtime_id_verified"])

    def test_nonzero_string_terminator_rejected(self):
        header = bytearray(26)
        header[:4] = b"ZST\0"
        struct.pack_into("<I", header, 4, 2)
        struct.pack_into("<H", header, 20, 2)
        with self.assertRaisesRegex(ValueError, "terminator"):
            english_records(header+b"\x02\x00\x00N\0\x01")


if __name__ == "__main__":
    unittest.main()
