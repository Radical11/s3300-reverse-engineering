"""SDK target-build rejection gates and real MIPS execution when tools exist."""
from io import BytesIO
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build_sdk
from setup_sdk_toolchain import executable, emulator_directory


class SDKGateTests(unittest.TestCase):
    def test_output_must_be_new_and_local_without_toolchain_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "module"
            with patch.object(build_sdk, "check_toolchain") as compiler:
                with self.assertRaisesRegex(ValueError, "new directory under derived"):
                    build_sdk.build(outside)
                compiler.assert_not_called()
            self.assertFalse(outside.exists())

    def test_changed_vendor_baseline_is_not_treated_as_abi_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"not the Nikon original")
            with self.assertRaisesRegex(ValueError, "hash differs"):
                build_sdk.baseline_declaration(root)

    def test_absent_vendor_source_is_explicit_not_an_implicit_abi_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            report = build_sdk.baseline_declaration(Path(directory))
            self.assertFalse(report["verified"])
            self.assertIn("not distributed", report["reason"])


TOOLS_READY = executable().is_file() and (emulator_directory() / "unicorn/__init__.py").is_file()


@unittest.skipUnless(TOOLS_READY, "Pinned optional compiler/emulator are installed by sdk-build --install-toolchain")
class CompiledSDKTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = build_sdk.ROOT
        cls.owned = tempfile.TemporaryDirectory(prefix="sdk-test-", dir=project / "derived")
        cls.output = Path(cls.owned.name) / "module"
        cls.report = build_sdk.build(cls.output)
        cls.module = (cls.output / "sdk-analysis-only.elf").read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.owned.cleanup()

    def test_deterministic_link_and_target_execution_keep_readiness_false(self):
        report = self.report
        self.assertTrue(report["two_builds_byte_identical"])
        self.assertEqual(report["target"]["undefined_imports"], [])
        self.assertTrue(report["emulation"]["performed"])
        self.assertGreaterEqual(report["emulation"]["reference_cases_passed"], 58)
        self.assertTrue(report["emulation"]["callee_saved_registers_preserved"])
        self.assertTrue(report["emulation"]["original_bypass_verified"])
        self.assertFalse(report["ready_for_executable_trial"])
        self.assertFalse(report["camera_integrated"])
        self.assertFalse(report["software_recovery_verified"])

    def test_wrong_isa_abi_role_and_undefined_import_are_rejected(self):
        for offset, fmt, value in ((36, "<I", 0x60001001), (36, "<I", 0x70002001), (16, "<H", 3)):
            altered = bytearray(self.module)
            struct.pack_into(fmt, altered, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                build_sdk.inspect_module(altered)
        elf = ELFFile(BytesIO(self.module))
        symtab = elf.get_section_by_name(".symtab")
        index = next(i for i, symbol in enumerate(symtab.iter_symbols()) if symbol.name == "s3300_counter_decode")
        altered = bytearray(self.module)
        # ELF32 st_shndx is the last u16 of each 16-byte symbol record.
        struct.pack_into("<H", altered, symtab["sh_offset"] + index * symtab["sh_entsize"] + 14, 0)
        with self.assertRaisesRegex(ValueError, "undefined imports"):
            build_sdk.inspect_module(altered)

    def test_bad_fp_metadata_or_instructions_fail_independent_inspection(self):
        elf = ELFFile(BytesIO(self.module))
        section = elf.get_section_by_name(".MIPS.abiflags")
        altered = bytearray(self.module)
        altered[section["sh_offset"] + 7] = 1
        with self.assertRaisesRegex(ValueError, "integer-only"):
            build_sdk.inspect_module(altered)
        text = elf.get_section_by_name(".text")
        altered = bytearray(self.module)
        struct.pack_into("<I", altered, text["sh_offset"], 0x44020000)  # mfc1 v0,f0
        with self.assertRaisesRegex(ValueError, "coprocessor/FP"):
            build_sdk.inspect_module(altered)

    def test_existing_build_is_never_replaced(self):
        original = (self.output / "manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "new directory"):
            build_sdk.build(self.output)
        self.assertEqual((self.output / "manifest.json").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
