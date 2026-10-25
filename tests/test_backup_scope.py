"""Observed-store inspection and geometry arithmetic; no device calls."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tools/vendor')]
from map_backup_scope import inspect_store, partition_geometry, calibration_location, build_report, CALIBRATION_SLICES


def ui_store(index=23):
    value = bytearray(0x1a0); value[:2] = b'\x9c\xb6'
    struct.pack_into('<H', value, 0x19c, index)
    value[0x19f] = sum(value[:0x19e]) & 255
    return bytes(value)


class BackupScopeTests(unittest.TestCase):
    def test_ui_header_and_checksum_include_calibration_location(self):
        result = inspect_store(ui_store(0xabcd), 'ui')
        self.assertTrue(result['valid_serialized_store'])
        self.assertEqual(result['calibration_block_index'], 0xabcd)
        self.assertEqual(result['covered_offsets_inclusive'], [0,0x19d])
        self.assertFalse(result['full_backup']); self.assertFalse(result['restorable'])

    def test_ui_uncovered_byte_does_not_establish_integrity(self):
        data = bytearray(ui_store()); data[0x19e] ^= 255
        self.assertTrue(inspect_store(bytes(data), 'ui')['checksum_matches'])
        data[0x19d] ^= 1
        self.assertFalse(inspect_store(bytes(data), 'ui')['checksum_matches'])

    def test_calibration_checksum_is_distinct_and_tail_is_excluded(self):
        data = bytearray(0x24a); data[:2] = b'Tx'
        data[0x247] = 59; data[0x248] = sum(data[:0x248]) & 255
        self.assertTrue(inspect_store(bytes(data), 'calibration')['valid_serialized_store'])
        data[0x249] = 255
        self.assertTrue(inspect_store(bytes(data), 'calibration')['checksum_matches'])
        data[0x247] += 1
        self.assertFalse(inspect_store(bytes(data), 'calibration')['checksum_matches'])

    def test_invalid_header_is_not_rescued_by_correct_checksum(self):
        data = bytearray(ui_store()); data[0] = 1; data[0x19f] = sum(data[:0x19e]) & 255
        self.assertFalse(inspect_store(bytes(data), 'ui')['valid_serialized_store'])

    def test_partial_oversized_and_mutable_inputs_are_rejected(self):
        for kind, data in (('ui', b'\0'*0x19f), ('ui', b'\0'*0x1a1),
                           ('calibration', b'\0'*0x24b), ('unknown', b''), ('ui',bytearray(0x1a0))):
            with self.assertRaises(ValueError): inspect_store(data,kind)

    def test_location_is_only_a_token_not_authorized_read(self):
        result = calibration_location(ui_store(23),64)
        self.assertEqual(result['sector_token'],1472)
        self.assertFalse(result['physical_extent_verified'])
        self.assertFalse(result['read_request_authorized'])
        self.assertTrue(calibration_location(ui_store(0xffff),0xffffffff)['arithmetic_wrapped'])

    def test_bad_ui_or_geometry_does_not_produce_location(self):
        for data, unit in ((b'\0'*0x1a0,64),(ui_store(),0),(ui_store(),True),(ui_store(),0x100000000)):
            with self.assertRaises(ValueError): calibration_location(data,unit)

    def test_getter_shift_masks_low5_and_records_arithmetic_wrap(self):
        result = partition_geometry(10,3,6)
        self.assertEqual((result['start_sector_token'],result['end_sector_token']),(640,832))
        self.assertFalse(result['physical_extent_verified'])
        self.assertEqual(partition_geometry(10,3,38)['erase_unit_sectors'],64)
        self.assertTrue(partition_geometry(0xffffffff,1,0)['arithmetic_wrapped'])
        self.assertEqual(partition_geometry(0xffffffff,1,0)['end_sector_token'],0)

    def test_invalid_geometry_observations_rejected(self):
        for args in ((True,1,0),(-1,1,0),(1,0x100000000,0),(1,1,0x10000)):
            with self.assertRaises(ValueError): partition_geometry(*args)

    def test_serialized_calibration_has_unserialized_source_gaps(self):
        copied={i for source,_,size in CALIBRATION_SLICES for i in range(source,source+size)}
        self.assertIn(0x107,copied); self.assertNotIn(0x108,copied)
        self.assertNotIn(0x23f,copied); self.assertIn(0x240,copied)
        self.assertIn(0x2f3,copied); self.assertIn(0x2f4,copied)
        self.assertNotIn(0x374,copied)
        self.assertEqual(sum(size for _,_,size in CALIBRATION_SLICES),0x23c)

    def test_wrong_source_rejected_before_private_analysis_is_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); source=root/'wrong.bin'; source.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'Source identity'):
                build_report(root,source,root)


if __name__ == '__main__': unittest.main()
