import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/map_hardware_contracts.py"
SPEC = importlib.util.spec_from_file_location("hardware_contracts", SCRIPT)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def packed(*words):
    return struct.pack("<" + "I" * len(words), *words)


def i_type(op, rs, rt, immediate):
    return op << 26 | rs << 21 | rt << 16 | immediate & 0xffff


class HardwareContractTests(unittest.TestCase):
    def test_direct_load_and_store_have_signed_offsets(self):
        body = packed(i_type(15, 0, 2, 0xb800), i_type(35, 2, 3, 0x2010),
                      i_type(43, 2, 4, -4))
        accesses, _ = module.scan_constants(body, 0x80000000)
        self.assertEqual([(a["address"], a["operation"]) for a in accesses],
                         [(0xb8002010, "lw"), (0xb7fffffc, "sw")])

    def test_ori_different_register_and_addiu_materializations(self):
        body = packed(i_type(15, 0, 3, 0xb800), i_type(13, 3, 4, 0x2010),
                      i_type(35, 4, 3, 0), i_type(15, 0, 5, 0x8004),
                      i_type(9, 5, 6, -0x100))
        accesses, references = module.scan_constants(body, 0x1000, {0x8003ff00})
        self.assertEqual(accesses[0]["address"], 0xb8002010)
        self.assertEqual(references[0]["target"], 0x8003ff00)

    def test_register_clobber_blocks_stale_address(self):
        # LW into the same base register must invalidate it for the next LW.
        body = packed(i_type(15, 0, 2, 0xb800), i_type(35, 2, 2, 0x2010),
                      i_type(35, 2, 3, 0x2014))
        accesses, _ = module.scan_constants(body, 0x1000)
        self.assertEqual(len(accesses), 1)

    def test_branches_and_delay_slots_do_not_propagate(self):
        body = packed(i_type(15, 0, 2, 0xb800), i_type(4, 0, 0, 1),
                      i_type(15, 0, 3, 0xb080), i_type(35, 2, 4, 0x2010),
                      i_type(35, 3, 4, 0x1060))
        self.assertEqual(module.scan_constants(body, 0x1000)[0], [])

    def test_unknown_instruction_drops_constants(self):
        body = packed(i_type(15, 0, 2, 0xb800), 0xffffffff,
                      i_type(35, 2, 3, 0x2010))
        self.assertEqual(module.scan_constants(body, 0x1000)[0], [])

    def test_outside_high_address_window_not_mmio_candidate(self):
        body = packed(i_type(15, 0, 2, 0x8000), i_type(35, 2, 3, 0x2010))
        self.assertEqual(module.scan_constants(body, 0x1000)[0], [])

    def test_age_bound_and_trailing_bytes(self):
        body = packed(i_type(15, 0, 2, 0xb800), 0, 0, 0,
                      i_type(35, 2, 3, 0x2010)) + b"x"
        self.assertEqual(module.scan_constants(body, 0x1000, max_age=2)[0], [])

    def test_zero_register_lui_cannot_create_constant(self):
        body = packed(i_type(15, 0, 0, 0xb800), i_type(35, 0, 2, 0x2010))
        self.assertEqual(module.scan_constants(body, 0x1000)[0], [])

    def test_arithmetic_write_invalidates_base_but_zero_copy_preserves(self):
        # ADDU t1,t0,zero propagates; ADDU t0,t0,t2 invalidates t0.
        body = packed(i_type(15, 0, 8, 0xb800), 8 << 21 | 9 << 11 | 33,
                      8 << 21 | 10 << 16 | 8 << 11 | 33,
                      i_type(35, 8, 3, 0x2010), i_type(35, 9, 4, 0x2010))
        accesses, _ = module.scan_constants(body, 0x1000)
        self.assertEqual(len(accesses), 1)
        self.assertEqual(accesses[0]["instruction_address"], 0x1010)

    def test_original_firmware_hash_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "firmware.bin"
            source.write_bytes(b"wrong firmware")
            with patch.object(module, "recover_ranges", return_value=([], {"regions": []}, b"")):
                with self.assertRaisesRegex(ValueError, "vendor firmware identity"):
                    module.build_report(Path(directory), source)

    def test_outputs_refuse_overwrite_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            output.write_text("preserve")
            with self.assertRaises(FileExistsError):
                module.write_outputs({}, Path(directory), output, Path(directory) / "listings")
            self.assertEqual(output.read_text(), "preserve")
            self.assertFalse((Path(directory) / "listings").exists())

    def test_dram_jump_table_mismatch_rejected(self):
        class BadMap:
            def read(self, address, length):
                return bytes(length)
        with self.assertRaisesRegex(ValueError, "DRAM selector table"):
            module.reviewed_contracts(BadMap())

    def test_category_avoids_generic_address_string(self):
        self.assertEqual(module.categories("Address: 0x%x"), [])
        self.assertIn("sensor", module.categories("SENSOR_CAP_ID_FRAME_TIME_US cannot be set!"))


if __name__ == "__main__":
    unittest.main()
