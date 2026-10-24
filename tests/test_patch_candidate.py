"""Cross-block regression and input-binding checks without vendor firmware."""
import copy
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from build_patch_candidate import replace_span, replacement_file, rewrite_segment, sha


TABLE = tuple([1 << 2 | 9 << 11 | 9 << 15]+
              [(i << 2) | 3 for i in range(257)]+[(3 << 2) | 1 << 11 | 3]*255)
DISTANCE = (3,)


def block(tokens, length):
    bits = "".join(f"{token:09b}" for token in tokens+[256])
    payload = int(bits+"0"*(1024-len(bits)), 2).to_bytes(128, "big")
    a, b = struct.pack(f"<{len(TABLE)}I", *TABLE), struct.pack("<I", *DISTANCE)
    return struct.pack("<IIIHH", 2, length, len(payload), len(a), len(b))+a+b+payload


def fixture():
    parts = [block([65], 1), block([257], 3)]
    source = b"prefix"+b"".join(parts)+b"suffix"
    cursor, blocks = 6, []
    for index, part in enumerate(parts):
        _, length, payload, a, b = struct.unpack_from("<IIIHH", part)
        item = {"index": index, "declared_output_bytes": length}
        position = cursor
        for name, size in (("header", 16), ("table_a", a), ("table_b", b), ("payload", payload)):
            item[name] = {"carrier_offset": position, "size": size, "sha256": sha(source[position:position+size])}
            position += size
        blocks.append(item)
        cursor += len(part)
    return source, {"carrier_offset": 6, "carrier_end_exclusive": cursor,
                    "packed_sha256": sha(source[6:cursor]), "elf_p_memsz": 4,
                    "elf_p_vaddr": 0x80000000, "block_count": 2, "blocks": blocks}


class PatchCandidateTests(unittest.TestCase):
    def test_changed_history_rewrites_continuation_to_preserve_untouched_output(self):
        source, segment = fixture()
        edits, proof = rewrite_segment(source, segment, b"AAAA", b"ZAAA")
        self.assertEqual(len(edits), 2)
        self.assertEqual(proof["decoded_changed_bytes"], 1)
        self.assertTrue(proof["full_segment_two_decoders_match"])
        self.assertEqual(proof["changed_blocks"][1]["replacement_literal_tokens"], 3)
        output = bytearray(source)
        for offset, body in edits:
            output[offset:offset+len(body)] = body
        self.assertEqual(len(output), len(source))
        self.assertEqual(output[:6], b"prefix")
        self.assertEqual(output[-6:], b"suffix")

    def test_stock_roundtrip_emits_no_payload_edits(self):
        source, segment = fixture()
        edits, proof = rewrite_segment(source, segment, b"AAAA", b"AAAA")
        self.assertEqual(edits, [])
        self.assertEqual(proof["decoded_changed_bytes"], 0)

    def test_decoded_bytes_must_match_original_payload(self):
        source, segment = fixture()
        with self.assertRaises(ValueError):
            rewrite_segment(source, segment, b"BBBB", b"ZBBB")

    def test_tampered_block_binding_rejected(self):
        source, segment = fixture()
        for name in ("header", "table_a", "table_b", "payload"):
            changed = copy.deepcopy(segment)
            changed["blocks"][0][name]["carrier_offset"] += 1
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "binding"):
                rewrite_segment(source, changed, b"AAAA", b"ZAAA")

    def test_segment_and_decoded_extents_cannot_change(self):
        source, segment = fixture()
        with self.assertRaisesRegex(ValueError, "extent"):
            rewrite_segment(source, segment, b"AAAA", b"AAA")
        altered = copy.deepcopy(segment)
        altered["block_count"] = 1
        with self.assertRaisesRegex(ValueError, "coverage"):
            rewrite_segment(source, altered, b"AAAA", b"ZAAA")
        with self.assertRaisesRegex(ValueError, "binding"):
            rewrite_segment(source[:-7]+b"!"+source[-6:], segment, b"AAAA", b"ZAAA")

    def test_patch_requires_original_identity_and_nonoverlapping_bounds(self):
        data, occupied = bytearray(b"abcdef"), []
        replace_span(data, 1, b"XY", sha(b"bc"), occupied)
        self.assertEqual(data, b"aXYdef")
        for offset, replacement, expected in ((2, b"Z", sha(b"Y")), (-1, b"Z", sha(b"a")),
                                                (5, b"ZZ", sha(b"f")), (4, b"Z", sha(b"X")),
                                                (4, b"e", sha(b"e")), (0, b"", sha(b""))):
            with self.subTest(offset=offset, replacement=replacement), self.assertRaises(ValueError):
                replace_span(data, offset, replacement, expected, occupied)

    def test_replacement_file_is_project_scoped_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"look.bin").write_bytes(b"look")
            spec = {"replacement_file": "look.bin", "replacement_sha256": sha(b"look")}
            self.assertEqual(replacement_file(root, spec), b"look")
            for changed in ({**spec, "replacement_file": "../outside.bin"},
                            {**spec, "replacement_file": str(root/"look.bin")},
                            {**spec, "replacement_sha256": sha(b"wrong")}):
                with self.assertRaises(ValueError):
                    replacement_file(root, changed)


if __name__ == "__main__":
    unittest.main()
