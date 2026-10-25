"""Executable placement/hook rejection boundaries and source bindings."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import map_executable_contracts as contracts


class ExecutableContractTests(unittest.TestCase):
    def test_direct_jump_uses_pc_plus_four_and_cannot_reach_sdk_synthetic_base(self):
        self.assertEqual(contracts.jump_target(0x0c000004, 0x8ffffffc), 0x90000010)
        self.assertEqual(contracts.jump_target(0x0c034459, 0x800006dc), 0x800d1164)
        self.assertFalse(contracts.direct_jump_reachable(0x800006dc, 0x10000))
        self.assertTrue(contracts.direct_jump_reachable(0x800006dc, 0x80800000))
        self.assertTrue(contracts.direct_jump_reachable(0x8ffffffc, 0x90000010))
        for site, target in ((0x80000001, 0x80001000), (0x80000000, 0x80001001), (-4, 0), (0, 0x100000000)):
            self.assertFalse(contracts.direct_jump_reachable(site, target))

    def test_non_jump_or_unaligned_input_is_rejected(self):
        for instruction, site in ((0, 0x80000000), (0x0c000000, 1), (0x03e00008, 0x80000000)):
            with self.assertRaisesRegex(ValueError, "aligned standard MIPS"):
                contracts.jump_target(instruction, site)

    def test_signed_branch_boundaries_are_words_relative_to_pc_plus_four(self):
        self.assertEqual(contracts.branch_target(0x80010000, 0xffff), 0x80010000)
        self.assertEqual(contracts.branch_target(0x80010000, 0x7fff), 0x80030000)
        self.assertEqual(contracts.branch_target(0x80010000, 0x8000), 0x7fff0004)
        with self.assertRaises(ValueError):
            contracts.branch_target(1, 0)
        with self.assertRaises(ValueError):
            contracts.branch_target(0, 0x10000)

    def test_pool_arithmetic_retains_alias_mask_and_unsigned_wrap_without_ownership(self):
        extent = contracts.pool_extent(0xa09f4178, 0x1000000)
        self.assertEqual(extent["cached_start"], 0x809f4178)
        self.assertEqual(extent["length"], 0x1000000 - 0x9f4178 - 4)
        self.assertFalse(extent["safe_code_placement"])
        self.assertFalse(extent["runtime_inputs_measured"])
        self.assertEqual(contracts.pool_extent(0x80001000, 1)["length"], 0xffffeffd)
        for invalid in (-1, 0x100000000, True):
            with self.assertRaises(ValueError):
                contracts.pool_extent(invalid, 0x1000000)

    def test_zero_runs_preserve_every_byte_but_never_grant_code_placement(self):
        rows = contracts.zero_runs(b"A" + bytes(33) + b"B" + bytes(31) + b"C", 0x80001000)
        self.assertEqual(rows, [{"start": 0x80001001, "end_exclusive": 0x80001022,
                                 "bytes": 33, "safe_code_placement": False}])
        with self.assertRaises(ValueError):
            contracts.zero_runs(bytes(10), 0, 1)

    def test_exact_instruction_guards_reject_changed_bytes(self):
        class Mapping:
            def __init__(self, raw): self.raw = raw
            def read(self, address, length): return self.raw[address:address + length]
        self.assertEqual(contracts.checked_instructions(Mapping(b"ABCD"), {0: "41424344"}), 1)
        with self.assertRaisesRegex(ValueError, "instruction differs"):
            contracts.checked_instructions(Mapping(b"ABCE"), {0: "41424344"})

    def test_native_dossier_instructions_are_rechecked_against_authentic_bytes(self):
        class Mapping:
            def read(self, address, length): return b"ABCD"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "application/functions"
            folder.mkdir(parents=True)
            path = folder / "00001000.json"
            record = {"address": "00001000", "name": "analyst-inferred", "ranges": [],
                      "instructions": [{"address": "00001000", "bytes": "41424344"}]}
            path.write_text(json.dumps(record))
            self.assertEqual(contracts.load_dossier(root, 0x1000, Mapping())["instructions_byte_checked"], 1)
            record["instructions"][0]["bytes"] = "41424345"
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "instruction bytes differ"):
                contracts.load_dossier(root, 0x1000, Mapping())

    def test_bad_original_source_is_rejected_before_using_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "firmware.bin"
            source.write_bytes(b"wrong image")
            with patch.object(contracts, "load_analysis") as load:
                with self.assertRaisesRegex(ValueError, "source digest differs"):
                    contracts.build_report(source=source)
                load.assert_not_called()

    def test_retained_findings_keep_ownership_recovery_and_execution_gates_closed(self):
        evidence = json.loads((contracts.ROOT / "evidence/executable-contracts.json").read_text())
        self.assertEqual(evidence["source_sha256"], contracts.SOURCE_SHA)
        self.assertEqual(evidence["reviewed_instruction_assertions"], len(contracts.ASSERTIONS))
        self.assertFalse(any(evidence["gates"].values()))
        self.assertFalse(evidence["target_executed"])
        self.assertFalse(evidence["patch_constructed"])
        self.assertEqual(evidence["zero_run_scan"]["safe_candidates_proven"], 0)
        self.assertEqual(evidence["startup"]["zeroed_ranges"][1]["start"], 0x80106ff0)
        self.assertFalse(evidence["call_and_hook_constraints"]["known_first_instruction"]["native_function_entry_discovered"])


if __name__ == "__main__":
    unittest.main()
