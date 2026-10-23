"""Hand-built format fixtures; these do not reuse the firmware table generator."""
import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from decode_firmware import BitReader, DecodeError, decode_block, decode_image, decode_symbol


def payload(bit_string):
    # DMA payloads in the supplied format occupy multiples of 128 bytes.
    padded = bit_string + '0' * ((-len(bit_string)) % 8)
    raw = int(padded, 2).to_bytes(len(padded) // 8, 'big') if padded else b''
    return raw + bytes(128 - len(raw))


class DecoderTests(unittest.TestCase):
    # Root: direct one-bit lookup at index 1, min/peek width both one.
    DIRECT = (0x8804, (65 << 2) | 3, (256 << 2) | 3)
    # Root: one leaf in each comb. Left literal A, right EOB.
    COMB = (0x8801, (65 << 2) | 3, (256 << 2) | 3)
    DISTANCE_ONE = (3,)

    def test_direct_literal_and_eob(self):
        decoded, stats = decode_block(self.DIRECT, self.DISTANCE_ONE, payload('01'), 1)
        self.assertEqual(decoded, b'A')
        self.assertEqual(stats['eob_bit_end'], 2)
        self.assertEqual(stats['literal_tokens'], 1)
        self.assertTrue(stats['zero_padding_verified'])

    def test_comb_literal_and_eob(self):
        self.assertEqual(decode_block(self.COMB, self.DISTANCE_ONE, payload('01'), 1)[0], b'A')

    def test_comb_left_chain_terminates_with_one(self):
        # Three left leaves: 01=A, 001=B, 000=C; right code 1=EOB.
        table = (0x9801, 263, 267, 271, 1027)
        self.assertEqual(decode_block(table, self.DISTANCE_ONE, payload('010010001'), 3)[0], b'ABC')

    def test_comb_right_chain_terminates_with_zero(self):
        # Left code 0=EOB; three right leaves: 10=A, 110=B, 111=C.
        table = (0x18801, 1027, 263, 267, 271)
        self.assertEqual(decode_block(table, self.DISTANCE_ONE, payload('101101110'), 3)[0], b'ABC')

    def test_direct_lookup_can_select_another_branch(self):
        # Codes 00=A, 01=B, 1=EOB. Root direct -> left comb.
        table = (0x8804, 0x8809, 1027, 263, 267)
        self.assertEqual(decode_block(table, self.DISTANCE_ONE, payload('00011'), 2)[0], b'AB')

    def test_match_overlap_with_previous_block_history(self):
        # Code 0 is length 3; code 1 is EOB. Distance 1 needs no Huffman bits.
        table = (0x8804, 0x80f, 1027)
        decoded, stats = decode_block(table, self.DISTANCE_ONE, payload('01'), 3, history=b'Q')
        self.assertEqual(decoded, b'QQQ')
        self.assertEqual(stats['match_tokens'], 1)

    def test_length_extra_bits_are_separate_from_code_bits(self):
        # Length base 11, one extra bit, leaf tag 3; count includes extra bit 1.
        length_leaf = (1 << 15) | (3 << 11) | (11 << 2) | 3
        table = (0x8804, length_leaf, 1027)
        self.assertEqual(decode_block(table, self.DISTANCE_ONE, payload('011'), 12, b'Z')[0], b'Z' * 12)

    def test_distance_extra_bits_and_cross_history_copy(self):
        # Distance leaf 6 -> base 5, one extra bit. Extra=1 produces distance 6.
        table = (0x8804, 0x80f, 1027)
        distance_six = ((6 << 2) | 3,)
        self.assertEqual(decode_block(table, distance_six, payload('011'), 3, b'ABCDEF')[0], b'ABC')

    def test_invalid_back_reference_rejected(self):
        with self.assertRaisesRegex(DecodeError, 'unavailable history'):
            decode_block((0x8804, 0x80f, 1027), self.DISTANCE_ONE, payload('01'), 3)

    def test_truncated_dma_payload_rejected(self):
        with self.assertRaisesRegex(DecodeError, '128 bytes'):
            decode_block(self.DIRECT, self.DISTANCE_ONE, payload('01')[:-1], 1)

    def test_bit_reader_rejects_read_after_end(self):
        reader = BitReader(b'\x80')
        self.assertEqual(reader.read(8), 128)
        with self.assertRaisesRegex(DecodeError, 'exceeds payload'):
            reader.read(1)

    def test_nonzero_padding_rejected(self):
        raw = bytearray(payload('01'))
        raw[-1] = 1
        with self.assertRaisesRegex(DecodeError, 'Nonzero data after EOB'):
            decode_block(self.DIRECT, self.DISTANCE_ONE, bytes(raw), 1)

    def test_early_eob_rejected(self):
        with self.assertRaisesRegex(DecodeError, 'declared output length'):
            decode_block(self.DIRECT, self.DISTANCE_ONE, payload('1'), 1)

    def test_declared_length_overflow_rejected(self):
        with self.assertRaisesRegex(DecodeError, 'exceeds declared length'):
            decode_block(self.DIRECT, self.DISTANCE_ONE, payload('001'), 1)

    def test_cyclic_table_rejected(self):
        with self.assertRaisesRegex(DecodeError, 'depth exceeded'):
            decode_symbol((0x8800,), BitReader(bytes(128)))

    def test_out_of_bounds_table_reference_rejected(self):
        with self.assertRaisesRegex(DecodeError, 'out of bounds'):
            decode_symbol((0x8ffc,), BitReader(bytes(128)))

    def test_unknown_table_instruction_rejected(self):
        with self.assertRaisesRegex(DecodeError, 'Unknown table instruction'):
            decode_symbol((2,), BitReader(bytes(128)))

    def test_modified_source_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'not-s3300.bin'
            source.write_bytes(b'not the vendor image')
            with self.assertRaisesRegex(DecodeError, 'expected S3300'):
                decode_image(source, root / 'missing-framing.json', root / 'decoded')
            self.assertFalse((root / 'decoded').exists())


if __name__ == '__main__':
    unittest.main()
