import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import map_label_contracts as labels


def fixture():
    return (b"ZST\0" + struct.pack("<IIHHI", 2, 100, 128, 16, 0)
            + struct.pack("<H", 2) + b"\0\xff\0\0"
            + struct.pack("<H", 4) + "AB".encode("utf-16-be") + b"\0\0")


class LabelParserTests(unittest.TestCase):
    def test_native_header_includes_default_record_and_first_id(self):
        parsed = labels.records(fixture(), base=0x80001000)
        self.assertEqual(parsed["count"], 2)
        self.assertEqual(parsed["bits"], 16)
        self.assertEqual([r["id"] for r in parsed["records"]], [100, 101])
        self.assertEqual(parsed["records"][0]["data_address"], 0x80001016)
        self.assertEqual(parsed["records"][1]["text_projection"], "AB")

    def test_invalid_records_and_unparsed_tail_are_rejected(self):
        valid = fixture()
        invalid = [valid[:10], b"BAD!" + valid[4:], valid[:-1], valid + b"x"]
        for offset, replacement in ((14, struct.pack("<H", 32)),
                                     (26, struct.pack("<H", 3)),
                                     (12, struct.pack("<H", 2))):
            item = bytearray(valid); item[offset:offset + 2] = replacement
            invalid.append(bytes(item))
        invalid.append(valid[:-2] + b"xx")
        for body in invalid:
            with self.subTest(body=body.hex()), self.assertRaises(ValueError):
                labels.records(body)

    def test_native_dossier_cannot_override_instruction_bytes(self):
        class Mapping:
            def read(self, address, size):
                return b"\0" * size
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text(json.dumps({"instructions": [
                {"address": "80001000", "bytes": "01000000"}]}))
            with self.assertRaisesRegex(ValueError, "differ"):
                labels.authenticate_dossier(path, Mapping())

    def test_modified_candidate_is_rejected_before_decode(self):
        if not (ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin").is_file():
            self.skipTest("Private original firmware absent")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.bin"; path.write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "identity"):
                labels.inspect_reviewed_candidate(path, None)


class RetainedLabelContractTests(unittest.TestCase):
    def test_static_path_stays_separate_from_camera_activation(self):
        if not labels.NATIVE.is_dir():
            self.skipTest("Private native analysis absent")
        report = labels.build()
        self.assertEqual([r["id"] for r in report["color_options"]["labels"]], list(range(560, 565)))
        self.assertEqual(report["color_options"]["labels"][3]["text_projection"], "Sepia")
        self.assertFalse(report["development_gates"]["runtime_amber_label_fixed"])
        self.assertFalse(report["development_gates"]["executable_trials_allowed"])
        self.assertEqual(report["english_table"]["count_including_default"], 3313)
        self.assertTrue(report["loader"]["returned_0x729e_is_not_parser_byte_limit"])

    def test_real_lookup_in_emulator_selects_changed_span_and_rejects_bad_ids(self):
        if not labels.NATIVE.is_dir():
            self.skipTest("Private native analysis absent")
        try:
            from verify_sdk_emulation import emulator_imports
            emulator_imports()
        except ImportError:
            self.skipTest("Optional pinned SDK emulator absent")
        manifest, raw = labels.load_analysis(ROOT / "derived/unpacked-v1.1-indexed")
        mapping = labels.AddressMap(raw, manifest["regions"])
        original = mapping.read(labels.TABLE, labels.TABLE_BYTES)
        changed = bytearray(original)
        offset = labels.LABEL - labels.TABLE
        changed[offset:offset + 10] = "Amber".encode("utf-16-be")
        result = labels.emulate_loader(mapping, bytes(changed), ids=(560, 563, 3313, 0xffffffff))
        self.assertEqual(result["all_record_pointers_checked"], 3313)
        self.assertEqual(result["selected"][0]["text_projection"], "Standard color")
        self.assertEqual(result["selected"][1]["text_projection"], "Amber")
        self.assertTrue(result["selected"][2]["rejected"])
        self.assertTrue(result["selected"][3]["rejected"])
        self.assertFalse(result["camera_executed"])


if __name__ == "__main__":
    unittest.main()
