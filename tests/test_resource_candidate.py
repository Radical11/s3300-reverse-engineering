import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from build_resource_candidate import additive, build, edit_label, replace_chunks
from resource_formats import decode_zst


def strings(records):
    header = bytearray(26)
    header[:4] = b"ZST\0"
    struct.pack_into("<I", header, 4, len(records)+1)
    struct.pack_into("<H", header, 20, 2)
    return bytes(header)+b"".join(struct.pack("<H", len(s)*2)+s.encode("utf-16-be")+bytes(2) for s in records)


class CandidateTests(unittest.TestCase):
    def test_only_one_label_changes_without_moving_other_records(self):
        raw = strings(["before", "Welcome screen", "after"])
        candidate, record = edit_label(raw)
        old, new = decode_zst(raw)["entries"], decode_zst(candidate)["entries"]
        self.assertEqual(len(candidate), len(raw))
        self.assertEqual(record["ordinal"], 2)
        self.assertEqual(new[1]["text_projection"], "Welcome studio")
        self.assertEqual(old[0], new[0])
        self.assertEqual(old[2], new[2])

    def test_ambiguous_label_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            edit_label(strings(["Welcome screen", "Welcome screen"]))

    def test_unequal_length_and_non_ascii_replacements_rejected(self):
        for text in ("short", "Welcome studi\u00f3"):
            with self.assertRaisesRegex(ValueError, "equal-length ASCII"):
                edit_label(strings(["Welcome screen"]), after=text)

    def test_fragmented_file_preserves_intervening_bytes_and_slack(self):
        raw = b"__abXYZcd!"
        chunks = [{"carrier_offset":2,"file_bytes":2}, {"carrier_offset":7,"file_bytes":2}]
        self.assertEqual(replace_chunks(raw, chunks, b"1234"), b"__12XYZ34!")
        self.assertEqual(replace_chunks(raw, chunks, b"abcd"), raw)

    def test_file_length_mismatch_rejected(self):
        chunks = [{"carrier_offset":2,"file_bytes":2}]
        for replacement in (b"1", b"123"):
            with self.assertRaises(ValueError):
                replace_chunks(b"__ab_", chunks, replacement)

    def test_overlapping_and_out_of_bounds_chunks_rejected(self):
        for chunks in ([{"carrier_offset":0,"file_bytes":2},{"carrier_offset":1,"file_bytes":2}],
                       [{"carrier_offset":3,"file_bytes":2}],
                       [{"carrier_offset":-1,"file_bytes":2}]):
            with self.assertRaises(ValueError):
                replace_chunks(b"abcd", chunks, b"1234")

    def test_additive_checksum_excludes_its_own_four_bytes(self):
        source = bytearray(range(64))
        expected = additive(source)
        source[0x2c:0x30] = b"\xff"*4
        self.assertEqual(additive(source), expected)
        source[0x30] += 1
        self.assertEqual(additive(source), expected+1)

    def test_unsupported_source_rejected_before_using_metadata(self):
        with self.assertRaisesRegex(ValueError, "source identity"):
            build(b"not firmware", {}, {})


if __name__ == "__main__":
    unittest.main()
