"""Checksum boundaries and fail-closed instruction-model tests."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import map_development_contracts as contracts


def code(*words):
    return struct.pack("<49I", *(list(words) + [0] * (49 - len(words))))


class SettingsChecksumTests(unittest.TestCase):
    def test_exact_covered_and_unchecked_store_offsets(self):
        store = bytearray(0x1a0)
        store[0] = 11
        store[0x19d] = 13
        self.assertEqual(contracts.settings_store_checksum(store), 24)
        store[0x19e], store[0x19f] = 41, 73
        self.assertEqual(contracts.settings_store_checksum(store), 24)
        store[0x19d] += 1
        self.assertEqual(contracts.settings_store_checksum(store), 25)

    def test_sum_width_and_invalid_zero_length(self):
        self.assertEqual(contracts.settings_sum(bytes([255]) * 512, 513), (255 * 512) & 65535)
        self.assertEqual(contracts.settings_sum(b"", 1), 0)
        for source, length in ((b"x", 0), (b"x", -1), (b"x", 3)):
            with self.assertRaises(ValueError):
                contracts.settings_sum(source, length)
        with self.assertRaises(ValueError):
            contracts.settings_store_checksum(bytes(0x19f))

    @unittest.skipUnless((contracts.WORKSPACE / "analysis/s3300-v1.1-analysis-only.elf").exists(),
                         "Vendor-derived bytes stay local")
    def test_checked_real_helper_against_independent_model(self):
        manifest, raw = contracts.load_analysis(contracts.WORKSPACE)
        mapping = contracts.AddressMap(raw, manifest["regions"])
        body = mapping.read(0x80008f80, 0xc4)
        result = contracts.verify_checksum_model(body)
        self.assertEqual(result["cases"], 120)
        sample = bytes([1, 2, 4, 8, 16, 32, 64])
        copied = contracts.model_checksum_instructions(body, sample, 5, mode=1)
        self.assertEqual(copied["value"], 15)
        self.assertEqual(copied["destination"], sample[:6] + b"\xa5")
        self.assertEqual(copied["destination_write_offsets"], list(range(6)))
        self.assertEqual(copied["source_read_offsets"], list(range(6)))


class InstructionModelTests(unittest.TestCase):
    def test_minimal_read_write_and_return_delay_slot(self):
        # lbu v0,0(a2); sb v0,0(a1); jr ra; addiu v0,v0,1
        result = contracts.model_checksum_instructions(code(0x90c20000, 0xa0a20000, 0x03e00008, 0x24420001), b"abc", 1)
        self.assertEqual(result["value"], 98)
        self.assertEqual(result["destination"], b"a\xa5\xa5")

    def test_branch_likely_not_taken_nullifies_delay_slot(self):
        # addiu v0,zero,2; beql v0,zero,+1; addiu v0,zero,99; jr ra; nop
        result = contracts.model_checksum_instructions(code(0x24020002, 0x50400001, 0x24020063, 0x03e00008, 0), b"abc", 1)
        self.assertEqual(result["value"], 2)

    def test_branch_likely_taken_executes_delay_slot(self):
        result = contracts.model_checksum_instructions(code(0x50000001, 0x24020063, 0x03e00008, 0), b"abc", 1)
        self.assertEqual(result["value"], 99)

    def test_unknown_opcode_external_memory_and_loop_fail_closed(self):
        for body in (code(0xffffffff), code(0x90020000), code(0x1000ffff, 0)):
            with self.subTest(body=body[:4]), self.assertRaises(ValueError):
                contracts.model_checksum_instructions(body, b"abc", 1, step_limit=20)

    def test_wrong_source_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "firmware.bin"
            source.write_bytes(b"not firmware")
            with patch.object(contracts, "load_analysis") as load:
                with self.assertRaisesRegex(ValueError, "identity"):
                    contracts.build_report(Path(directory), source)
                load.assert_not_called()

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("preserve")
            with self.assertRaises(FileExistsError):
                contracts.write_report({}, Path(directory), output, Path(directory) / "listings")
            self.assertEqual(output.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
