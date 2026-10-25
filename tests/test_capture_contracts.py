import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from map_capture_contracts import (command_context_index, command_id_parts,
                                   validate_instruction_facts, FACTS, WORKSPACE,
                                   ROOT, SOURCE_SHA)
from map_development_interfaces import AddressMap
from workspace_functions import load_analysis


class CaptureContractTests(unittest.TestCase):
    def test_context_values_and_adjacent_rejection(self):
        for context, expected in ((0x40, 0), (0x50, 1), (0xa0, 2), (0xb0, 5)):
            self.assertEqual(command_context_index(context), expected)
            self.assertEqual(command_context_index(context-1), 8)
            self.assertEqual(command_context_index(context+1), 8)
        self.assertEqual(command_context_index(0x90), 8)

    def test_command_class_boundaries(self):
        for value, expected in ((0, (0, 0)), (15, (0, 15)), (49, (0, 49)),
                                (50, (3, 0)), (99, (3, 49)), (100, (1, 0)),
                                (199, (1, 99)), (200, (4, 0)), (999, (4, 799)),
                                (1000, (2, 0))):
            self.assertEqual(command_id_parts(value), expected)

    def test_unsigned_target_semantics(self):
        self.assertEqual(command_id_parts(-1), (2, 0xffffffff-1000))
        self.assertEqual(command_context_index(0x100000040), 0)

    def test_instruction_guard_rejects_changed_or_truncated_fact(self):
        class Memory:
            def __init__(self, value):
                self.value = value
            def read(self, address, size):
                return self.value
        validate_instruction_facts(Memory(bytes.fromhex('21608000')), [(0, '21608000')])
        for body in (bytes(4), bytes.fromhex('216080')):
            with self.assertRaises(ValueError):
                validate_instruction_facts(Memory(body), [(0, '21608000')])

    @unittest.skipUnless((WORKSPACE/'analysis/s3300-v1.1-analysis-only.elf').exists(),
                         'Vendor analysis bytes are intentionally local-only')
    def test_reviewed_instructions_bind_to_authenticated_elf(self):
        manifest, raw = load_analysis(WORKSPACE)
        validate_instruction_facts(AddressMap(raw, manifest['regions']), FACTS)

    def test_evidence_keeps_static_and_runtime_boundaries(self):
        report = json.loads((ROOT/'evidence/capture-contracts.json').read_text())
        self.assertEqual(report['source_sha256'], SOURCE_SHA)
        self.assertFalse(report['rea_evidence'])
        self.assertFalse(report['target_executed'])
        self.assertFalse(report['ready_for_saved_photo_patch'])
        self.assertEqual(len(report['contracts']), 6)
        contract = next(c for c in report['contracts'] if c['id']=='capture.command15_retention')
        self.assertEqual(contract['ordinary_route']['dirty_mask'], 0x100000)
        self.assertEqual(contract['special_route']['message'], 0x1046)
        self.assertIn('Unestablished', contract['contexts_from_color_effect']['semantic_names'])


if __name__ == '__main__':
    unittest.main()
