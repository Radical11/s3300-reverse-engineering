"""Descriptor and arithmetic boundaries recovered from source-bound capture code."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from map_capture_buffers import (decode_frame, effective_geometry, jpeg_reviewed_guard,
                                 reference_scan, temporary_allocation_extent,
                                 validate_facts, verify_dossier)


class FrameContractTests(unittest.TestCase):
    def frame(self, **kwargs):
        values = dict(data_address=0x81234560, frame_width=640, frame_height=480,
                      left=0, top=0, width=640, height=480)
        values.update(kwargs)
        return values

    def test_descriptor_size_endianness_and_no_dereference(self):
        row = decode_frame(struct.pack("<7I", 0xb8002010, 640, 480, 2, 4, 320, 240))
        self.assertEqual(row, self.frame(data_address=0xb8002010, left=2, top=4, width=320, height=240))
        for length in (0, 24, 27, 29, 32):
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_frame(bytes(length))

    def test_generic_zero_roi_fallback_is_not_jpeg_guard_behavior(self):
        original = self.frame(left=12, top=14, width=0, height=100)
        result = effective_geometry(original)
        self.assertEqual((result["width"], result["height"]), (640, 480))
        self.assertEqual((result["left"], result["top"]), (12, 14))
        self.assertEqual(original["width"], 0)
        self.assertFalse(jpeg_reviewed_guard(original)["reviewed_guards_pass"])

    def test_roi_horizontal_equality_and_overrun_boundary(self):
        self.assertTrue(jpeg_reviewed_guard(self.frame(left=16, width=624))["reviewed_guards_pass"])
        self.assertFalse(jpeg_reviewed_guard(self.frame(left=16, width=625))["reviewed_guards_pass"])
        # A passing reviewed guard cannot imply vertical bounds or address ownership.
        result = jpeg_reviewed_guard(self.frame(top=900, data_address=0))
        self.assertTrue(result["reviewed_guards_pass"])
        self.assertFalse(result["vertical_containment_established"])
        self.assertFalse(result["buffer_address_or_capacity_validated"])

    def test_target_addition_overflow_is_exposed_not_fixed_silently(self):
        result = jpeg_reviewed_guard(self.frame(left=0xfffffff0, width=32))
        self.assertTrue(result["horizontal_target_compare_pass"])
        self.assertTrue(result["horizontal_addition_overflow"])
        # Target guards alone would accept this nonsensical wrapped coordinate.
        self.assertTrue(result["reviewed_guards_pass"])

    def test_chroma_origin_even_requirement_is_context_specific(self):
        for left, top in ((1, 0), (0, 1), (1, 1)):
            row = self.frame(left=left, top=top, width=320, height=240)
            self.assertFalse(jpeg_reviewed_guard(row, chroma420=True)["reviewed_guards_pass"])
            self.assertTrue(jpeg_reviewed_guard(row, chroma420=False)["reviewed_guards_pass"])
        self.assertTrue(jpeg_reviewed_guard(self.frame(left=2, top=4, width=320), chroma420=True)["reviewed_guards_pass"])

    def test_temporary_extent_retains_target_wrap_and_rejects_unknown_multiplier(self):
        result = temporary_allocation_extent(640, 480, 2)
        self.assertEqual(result["target_requested_bytes"], 614400)
        self.assertFalse(result["arithmetic_overflow"])
        wrapped = temporary_allocation_extent(65536, 65536, 2)
        self.assertEqual(wrapped["target_requested_bytes"], 0)
        self.assertTrue(wrapped["arithmetic_overflow"])
        self.assertFalse(wrapped["allocation_success_established"])
        for value in (0, 1, 4, 2.0, "2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                temporary_allocation_extent(640, 480, value)

    def test_signed_bool_and_oversized_fields_are_not_u32(self):
        for value in (-1, 0x100000000, True, 2.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                jpeg_reviewed_guard(self.frame(width=value))


class ByteBindingTests(unittest.TestCase):
    def test_changed_reviewed_instruction_and_native_dossier_are_rejected(self):
        class Memory:
            def read(self, address, size):
                if address != 4096 or size != 4:
                    raise ValueError("Outside synthetic map")
                return bytes.fromhex("21608000")
        validate_facts(Memory(), {4096: "21608000"})
        with self.assertRaisesRegex(ValueError, "differs"):
            validate_facts(Memory(), {4096: "00000000"})
        row = {"instructions": [{"address": "00001000", "bytes": "21608000"}]}
        self.assertEqual(verify_dossier(row, Memory()), 1)
        row["instructions"][0]["bytes"] = "00000000"
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_dossier(row, Memory())
        with self.assertRaisesRegex(ValueError, "no instructions"):
            verify_dossier({"instructions": []}, Memory())

    def test_reference_scan_keeps_negative_search_bounded(self):
        target = 0x80205918
        call = (3 << 26) | ((target >> 2) & 0x03ffffff)
        body = struct.pack("<4I", call, target, 0, 0)
        manifest = {"regions": [{"analysis_elf_offset": 0, "virtual_start": 0x80001000, "size": len(body)}]}
        result = reference_scan(manifest, body, target)
        self.assertEqual(result["direct_j_jal_encoding_candidates"], [0x80001000])
        self.assertEqual(result["aligned_pointer_words"], [0x80001004])
        self.assertEqual(reference_scan(manifest, bytes(len(body)), target)["direct_j_jal_encoding_candidates"], [])


if __name__ == "__main__":
    unittest.main()
