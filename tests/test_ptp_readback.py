import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from read_ptp_staged import array32, object_info


class PtpReadbackParserTests(unittest.TestCase):
    def test_storage_and_handle_arrays(self):
        self.assertEqual(array32(struct.pack("<III", 2, 65537, 35)), [65537, 35])
        self.assertEqual(array32(bytes(4)), [])

    def test_array_rejects_truncation_trailing_bytes_and_count_limit(self):
        for raw in (b"", bytes(3), struct.pack("<I", 1), bytes(5), struct.pack("<I", 129)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                array32(raw)

    @staticmethod
    def info(name="FIRMWARE.BIN"):
        header = bytearray(52)
        struct.pack_into("<IHHI", header, 0, 65537, 0x3000, 0, 19005632)
        struct.pack_into("<I", header, 38, 34)
        return bytes(header)+bytes([len(name)+1])+name.encode("utf-16-le")+bytes(2)

    def test_object_info_reads_protocol_offsets_and_unicode(self):
        self.assertEqual(object_info(self.info()), {"storage": 65537, "format": 0x3000,
                         "size": 19005632, "parent": 34, "filename": "FIRMWARE.BIN"})
        self.assertEqual(object_info(self.info("caf\u00e9.bin"))["filename"], "caf\u00e9.bin")

    def test_object_info_rejects_short_or_unterminated_filename(self):
        valid = self.info()
        for raw in (valid[:51], valid[:52], valid[:-1], valid[:-2]+b"XX", bytes(53)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                object_info(raw)

    def test_invalid_utf16_is_not_replaced_silently(self):
        raw = self.info("x")
        with self.assertRaises(UnicodeDecodeError):
            object_info(raw[:53]+b"\x00\xd8\x00\x00")


if __name__ == "__main__":
    unittest.main()
