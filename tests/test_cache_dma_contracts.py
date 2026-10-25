"""Cache-line, alias and failure boundaries; no camera or MMIO operations."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import map_cache_dma_contracts as contracts


class CacheDmaContractTests(unittest.TestCase):
    def test_cached_and_uncached_tokens_have_same_low29_without_ownership(self):
        expected = {'cached': 0x81234567, 'uncached': 0xa1234567, 'low29': 0x1234567}
        self.assertEqual(contracts.kseg_aliases(0x81234567), expected)
        self.assertEqual(contracts.kseg_aliases(0xa1234567), expected)
        for value in (0, 0x7fffffff, 0xc0000000, 0x100000000, True, 0x81234567 + 0.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                contracts.kseg_aliases(value)

    def test_line_rounding_includes_both_cache_lines_at_boundary(self):
        result = contracts.line_loop(0xa000101f, 2, 5)
        self.assertEqual(result['lines'], [0x80001000, 0x80001020])
        self.assertEqual(result['end'], 0x80001021)
        self.assertFalse(result['end_wrapped'])

    def test_branch_tests_before_first_cache_but_zero_length_can_round_back(self):
        # Arithmetic only: I/D-invalidate assert first; D-WBINV selects whole cache.
        self.assertEqual(contracts.line_loop(0x80001000, 0, 5)['lines'], [])
        self.assertEqual(contracts.line_loop(0x80001001, 0, 5)['lines'], [0x80001000])
        self.assertEqual(contracts.ASSERTIONS[0x800b5514], ('b', '0x800b5524'))

    def test_overflow_is_recorded_and_unsigned_comparison_can_skip_range(self):
        result = contracts.line_loop(0xdffffff0, 0x20000020, 5)
        self.assertEqual(result['end'], 0x10)
        self.assertTrue(result['end_wrapped'])
        self.assertEqual(result['lines'], [])

    def test_mips_variable_shift_masks_exponent_and_model_bounds_pathology(self):
        self.assertEqual(contracts.line_loop(0x8000101f, 2, 37),
                         contracts.line_loop(0x8000101f, 2, 5))
        self.assertEqual(contracts.line_loop(0x80001000, 64, 5, limit=1)['state'], 'bounded-limit')
        # Synthetic, implausible cache exponent: demonstrate bounded wrap-cycle handling.
        result = contracts.line_loop(0x80000000, 0x10000000, 31)
        self.assertEqual(result['lines'], [0x80000000, 0])
        self.assertEqual(result['state'], 'cycle')

    def test_invalid_model_inputs_are_rejected(self):
        for args in ((-1, 1, 5), (0, -1, 5), (0, 1, 0x100000000), (True, 1, 5)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                contracts.line_loop(*args)
        for bound in (0, 100001, True):
            with self.assertRaises(ValueError):
                contracts.line_loop(0x80001000, 1, 5, limit=bound)

    def test_fastcopy_preparation_keeps_operation_order_and_skips_uncached_tokens(self):
        plan = contracts.fastcopy_alias_plan(0x81200000, 0x81300000, 64)
        self.assertEqual(plan['operations'], [
            {'operation': 'D-invalidate', 'address': 0x81200000, 'length': 64},
            {'operation': 'D-writeback-invalidate', 'address': 0x81300000, 'length': 64}])
        self.assertEqual(plan['destination_alias'], 0xa1200000)
        self.assertEqual(plan['source_alias'], 0xa1300000)
        self.assertEqual(contracts.fastcopy_alias_plan(0xa1200000, 0xa1300000, 64)['operations'], [])
        with self.assertRaises(ValueError):
            contracts.fastcopy_alias_plan(0x81200000, 0x81300000, True)

    def test_wrong_source_rejected_before_analysis_read(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'firmware.bin'
            source.write_bytes(b'not the authenticated image')
            with patch.object(contracts, 'load_analysis') as load:
                with self.assertRaisesRegex(ValueError, 'Source differs'):
                    contracts.build_report(Path(folder), source, Path(folder))
                load.assert_not_called()

    def test_native_bytes_and_image_identity_are_not_trusted_from_dossier_alone(self):
        class Mapping:
            def read(self, address, length):
                return b'ABCD'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'functions').mkdir()
            meta = {'executable_sha256': 'expected', 'language': 'MIPS:LE:32:default'}
            (root / 'image.json').write_text(json.dumps(meta))
            record = {'address': '80001000', 'name': 'inferred', 'pseudocode': 'return;',
                      'decompilation_completed': True,
                      'instructions': [{'address': '80001000', 'bytes': '41424344'}]}
            path = root / 'functions/80001000.json'
            path.write_text(json.dumps(record))
            result = contracts.check_dossiers(root, Mapping(), 'expected', [0x80001000])
            self.assertEqual(result['records'][0]['instructions_checked'], 1)
            record['instructions'][0]['bytes'] = '41424345'
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'Native instruction differs'):
                contracts.check_dossiers(root, Mapping(), 'expected', [0x80001000])
            with self.assertRaisesRegex(ValueError, 'identity or architecture'):
                contracts.check_dossiers(root, Mapping(), 'wrong', [0x80001000])

    def test_retained_report_limits_cache_pair_to_observed_scratchpad_path(self):
        report = json.loads((contracts.ROOT / 'evidence/cache-dma-contracts.json').read_text())
        self.assertEqual(report['source_sha256'], contracts.BASELINE)
        self.assertFalse(any(report['gates'].values()))
        self.assertFalse(report['camera_commands_issued'])
        self.assertFalse(report['target_executed'])
        self.assertFalse(report['patch_constructed'])
        self.assertEqual(len(report['instruction_checks']), len(contracts.ASSERTIONS))
        self.assertEqual(len(report['native_corroboration']['records']), len(contracts.FUNCTIONS))
        pair = next(row for row in report['contracts'] if row['id'] == 'code.observed_cache_pair')
        self.assertIn('not a general code-loader', pair['limits'])


if __name__ == '__main__':
    unittest.main()
