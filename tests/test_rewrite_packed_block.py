import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from decode_firmware import decode_block
from rewrite_packed_block import rewrite_block


def payload(bits):
    if len(bits) > 1024:
        raise ValueError("Test allocation exceeded")
    return int(bits+"0"*(1024-len(bits)), 2).to_bytes(128, "big")


class PackedRewriteTests(unittest.TestCase):
    # Nine-bit direct alphabet: all bytes, EOB, then length-three tokens.
    TABLE = tuple([1 << 2 | 9 << 11 | 9 << 15]+
                  [(i << 2) | 3 for i in range(257)]+[(3 << 2) | 1 << 11 | 3]*255)
    DISTANCE = (3,)

    def test_unchanged_block_is_byte_identical(self):
        raw = payload(f"{65:09b}{66:09b}{256:09b}")
        result, report = rewrite_block(self.TABLE, self.DISTANCE, raw, b"AB", b"AB")
        self.assertEqual(result, raw)
        self.assertEqual(report["replaced_tokens"], 0)

    def test_literal_replacement_preserves_allocation_and_eob(self):
        raw = payload(f"{65:09b}{66:09b}{256:09b}")
        result, report = rewrite_block(self.TABLE, self.DISTANCE, raw, b"AB", b"AZ")
        self.assertEqual(len(result), len(raw))
        self.assertEqual(decode_block(self.TABLE, self.DISTANCE, result, 2)[0], b"AZ")
        self.assertTrue(report["two_decoders_exactly_match_desired"])

    def test_changed_history_replaces_affected_overlapping_match(self):
        raw = payload(f"{257:09b}{256:09b}")
        result, report = rewrite_block(self.TABLE, self.DISTANCE, raw, b"AAA", b"AAA", b"A", b"Z")
        self.assertEqual(decode_block(self.TABLE, self.DISTANCE, result, 3, b"Z")[0], b"AAA")
        self.assertEqual(report["replacement_literal_tokens"], 3)

    def test_compatible_overlapping_match_is_preserved(self):
        raw = payload(f"{257:09b}{256:09b}")
        result, report = rewrite_block(self.TABLE, self.DISTANCE, raw, b"AAA", b"AAA", b"A", b"A")
        self.assertEqual(result, raw)
        self.assertEqual(report["preserved_tokens"], 1)

    def test_missing_literal_code_rejected(self):
        table = (0x8804, (65 << 2) | 3, (256 << 2) | 3)
        with self.assertRaisesRegex(ValueError, "No existing literal"):
            rewrite_block(table, self.DISTANCE, payload("01"), b"A", b"B")

    def test_changed_decoded_length_and_incorrect_original_rejected(self):
        raw = payload(f"{65:09b}{256:09b}")
        for old, desired in ((b"A", b"AA"), (b"B", b"B")):
            with self.subTest(old=old, desired=desired), self.assertRaises(ValueError):
                rewrite_block(self.TABLE, self.DISTANCE, raw, old, desired)

    def test_growth_cannot_exceed_payload_padding(self):
        # 70 repeated length-three tokens fit; replacing them by literals does not.
        raw = payload(f"{257:09b}"*70+f"{256:09b}")
        with self.assertRaisesRegex(ValueError, "exceed existing payload"):
            rewrite_block(self.TABLE, self.DISTANCE, raw, b"A"*210, b"BCD"*70, b"A", b"A")


if __name__ == "__main__":
    unittest.main()
