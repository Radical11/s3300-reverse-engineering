"""Application write policy must not become a backup or recovery permission."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import map_application_write_scope as scope


class ApplicationWriteScopeTests(unittest.TestCase):
    def test_section3_uses_its_explicit_flag_and_exact_upgrade(self):
        self.assertTrue(scope.section_protected(3,0,100,1,1))
        self.assertFalse(scope.section_protected(3,100,0,1,0))
        self.assertFalse(scope.section_protected(3,100,0,2,1))

    def test_section6_and_other_sections_have_different_rules(self):
        self.assertTrue(scope.section_protected(6,0,0,1,0))
        self.assertFalse(scope.section_protected(6,10,0,0,1))
        self.assertFalse(scope.section_protected(0,0,0,1,1))
        self.assertTrue(scope.section_protected(0,1,0,0,0))
        self.assertFalse(scope.section_protected(0,1,1,1,1))

    def test_old_extent_has_inclusive_boundaries(self):
        self.assertFalse(scope.old_user_extent_contains(10,3,1,9))
        self.assertTrue(scope.old_user_extent_contains(10,3,1,10))
        self.assertTrue(scope.old_user_extent_contains(10,3,1,12))
        self.assertFalse(scope.old_user_extent_contains(10,3,1,13))

    def test_extent_helper_accepts_nonzero_upgrade_and_rejects_empty_extent(self):
        self.assertTrue(scope.old_user_extent_contains(0,1,2,0))
        self.assertFalse(scope.old_user_extent_contains(0,1,0,0))
        self.assertFalse(scope.old_user_extent_contains(0,0,1,0))

    def test_wrapped_extent_is_not_treated_as_two_safe_intervals(self):
        self.assertFalse(scope.old_user_extent_contains(0xffffffff,2,1,0xffffffff))
        self.assertFalse(scope.old_user_extent_contains(0xffffffff,2,1,0))

    def test_header_flags_are_independent(self):
        header=bytearray(64)
        struct.pack_into('<I',header,0x24,1)
        current=scope.update_policy(bytes(header),1)
        self.assertEqual(current['keep_section3'],1)
        self.assertFalse(current['full_erase_selected'])
        self.assertFalse(current['pre_burn_relocation_selected'])
        self.assertFalse(current['complete_calibration_preservation_proven'])
        struct.pack_into('<I',header,0x1c,1)
        struct.pack_into('<I',header,0x2c,1)
        selected=scope.update_policy(bytes(header),1)
        self.assertTrue(selected['full_erase_selected'])
        self.assertTrue(selected['pre_burn_relocation_selected'])
        struct.pack_into('<I',header,0x30,1)
        self.assertFalse(scope.update_policy(bytes(header),1)['pre_burn_relocation_selected'])

    def test_observed_values_are_bounded_not_coerced(self):
        for bad in (True,-1,0x100000000,'0'):
            with self.assertRaises(ValueError): scope.old_user_extent_contains(bad,1,1,0)
        for bad in (-1,256,True):
            with self.assertRaises(ValueError): scope.section_protected(3,1,0,bad,1)
        for bad in (-1,7,True):
            with self.assertRaises(ValueError): scope.section_protected(bad,1,0,1,1)

    def test_partial_header_is_rejected(self):
        for header in (b'',bytes(63),bytes(65),None):
            with self.assertRaises(ValueError): scope.update_policy(header,1)

    def test_wrong_source_precedes_native_or_focus_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=Path(temporary);source=p/'wrong.bin';source.write_bytes(b'other')
            with self.assertRaisesRegex(ValueError,'Source identity'):
                scope.build_report(p/'absent',source,p/'native',p/'focus')

    def test_focused_warning_and_all_gates_remain_visible(self):
        data=json.loads((ROOT/'evidence/application-write-scope.json').read_text())
        self.assertIn('Caller-seeded',data['focused_analysis']['boundary_scope'])
        self.assertIn('not settling',data['focused_analysis']['inference_warning'])
        self.assertFalse(data['focused_analysis']['existing_application_project_modified'])
        self.assertFalse(data['target_executed'])
        for key,value in data['gates'].items():
            self.assertEqual(value,key=='application_writer_static_path')


if __name__=='__main__': unittest.main()
