"""Offline handoff models reject invented state and keep recovery gates closed."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import map_updater_handoff as handoff


class UpdaterHandoffTests(unittest.TestCase):
    def test_source_and_finish_bytes_are_distinct(self):
        row=handoff.split_card_source(0x12ff80ab,0x1234)
        self.assertEqual(row['source'],0xab)
        self.assertEqual(row['sfcu'],0xff)
        self.assertEqual(row['finish_mode'],0x34)
        self.assertFalse(row['device_invocation'])

    def test_success_translation_requires_exactly_one(self):
        self.assertEqual(handoff.application_result(1),0)
        for result in (0,2,0xfe,0xffffffff):
            self.assertEqual(handoff.application_result(result),0xfe)

    def test_boot_mask_preserves_unselected_bits(self):
        self.assertEqual(handoff.boot_argument(0x5555aaaa,0x55,0xff),0x55558a55)

    def test_boot_reserved_bits_participate_even_with_empty_mask(self):
        self.assertEqual(handoff.boot_argument(0xffffffff,0,0),0xffffcfff)
        self.assertEqual(handoff.boot_argument(0,0x3000,0),0x3000)

    def test_reload_bit_preserves_original_flags(self):
        for mask in (0,0xff,0xffffffff):
            self.assertEqual(handoff.boot_argument(0x12345678,0x800,mask),0x12345678)

    def test_integer_observations_reject_bool_negative_and_overflow(self):
        for bad in (True,-1,0x100000000,'1',None):
            with self.assertRaises(ValueError): handoff.boot_argument(bad,0,0)
            with self.assertRaises(ValueError): handoff.split_card_source(0,bad)
            with self.assertRaises(ValueError): handoff.application_result(bad)

    def test_package_header_does_not_promote_installed_geometry(self):
        raw=b''.join(struct.pack('<I',handoff.BURN_HEADER[offset]) for offset in range(0,64,4))
        row=handoff.describe_burn_header(raw)
        self.assertEqual(row['media_kind'],3)
        self.assertEqual(row['chunk_bytes'],0x20000)
        self.assertEqual(row['keep_user_area_flag'],1)
        self.assertEqual(row['extended_header_marker'],0x55aa)
        self.assertFalse(row['hash_enabled'])
        self.assertFalse(row['camera_geometry_established'])

    def test_header_requires_exact_observed_extent(self):
        for raw in (b'',bytes(63),bytes(65),bytearray(64),None):
            with self.assertRaises(ValueError): handoff.describe_burn_header(raw)

    def test_wrong_source_rejected_before_workspace_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'wrong.bin';source.write_bytes(b'not the authenticated carrier')
            with self.assertRaisesRegex(ValueError,'Source identity'):
                handoff.build_report(Path(tmp)/'absent',source,Path(tmp)/'absent-native')

    def test_changed_instruction_is_rejected(self):
        class ChangedMapping:
            def read(self,address,size): return bytes(size)
        with self.assertRaisesRegex(ValueError,'instruction differs'):
            handoff.check_assertions(ChangedMapping())

    def test_retained_metadata_does_not_claim_recovery_or_camera_execution(self):
        report=json.loads((ROOT/'evidence/updater-handoff.json').read_text())
        self.assertFalse(report['target_executed'])
        self.assertFalse(report['camera_commands_issued'])
        self.assertTrue(report['gates']['normal_update_route_static'])
        for key in ('boot_flags_producer_verified','reset_to_recovery_independent',
                    'complete_backup_verified','software_unbootable_recovery_verified',
                    'executable_trial_allowed'):
            self.assertFalse(report['gates'][key])
        self.assertTrue(all(not row['rom_handoff_bfc00664'] for row in report['original_elf_coverage']))


if __name__ == '__main__': unittest.main()
