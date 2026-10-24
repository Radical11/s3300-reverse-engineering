import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from map_gamma_pipeline import expand_legacy_gamma, direct_transfers


class GammaPipelineTests(unittest.TestCase):
    def test_wrong_sizes_rejected(self):
        for length in (0, 256, 959, 961, 1344):
            with self.assertRaises(ValueError):
                expand_legacy_gamma(bytes(length))

    def test_section_boundary_is_not_rgb(self):
        raw = struct.pack('<240I', *([0x2300]*80+[0x4500]*160))
        result = expand_legacy_gamma(raw)
        self.assertEqual(result['first_1024'], [35]*1024)
        self.assertEqual(result['second_4096'], [276]*4096)

    def test_nonuniform_section_indexing(self):
        words = [(i << 8) for i in range(80)]+[(i << 8) for i in range(160)]
        result = expand_legacy_gamma(struct.pack('<240I', *words))
        first, second = result['first_1024'], result['second_4096']
        self.assertEqual([first[x] for x in (0, 3, 4, 63, 64, 1023)], [64, 64, 65, 79, 4, 63])
        self.assertEqual([second[x] for x in (0, 3, 4, 127, 128, 4095)], [0, 12, 516, 636, 16, 508])

    def test_slope_rounding_and_reserved_bits(self):
        words = [0xab0020ff]*80+[0xab0020ff]*160
        result = expand_legacy_gamma(struct.pack('<240I', *words))
        self.assertEqual([result['first_1024'][x] for x in (0, 1, 2, 3, 64, 79)], [32, 33, 34, 35, 32, 47])
        self.assertEqual([result['second_4096'][x] for x in (0, 3, 4, 5, 128, 159)], [128, 128, 128, 132, 128, 252])

    def test_direct_jump_pc_high_nibble(self):
        target = 0x8021c7a8
        raw = struct.pack('<4I', (3 << 26)|((target >> 2)&0x3ffffff),
                          (2 << 26)|((target >> 2)&0x3ffffff), 0, 0)
        region = {'virtual_start': 0x80001000, 'analysis_elf_offset': 0, 'size': len(raw)}
        self.assertEqual(direct_transfers([region], raw, {target})[f'{target:#010x}'],
                         [{'site': 0x80001000, 'instruction': 'jal'}, {'site': 0x80001004, 'instruction': 'j'}])
        region['virtual_start'] = 0x90001000
        self.assertEqual(direct_transfers([region], raw, {target})[f'{target:#010x}'], [])


if __name__ == '__main__':
    unittest.main()
