import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from map_restore_path import dump_bounds


class RestoreArithmeticTests(unittest.TestCase):
    def test_fixed_loop_nominal_sizes_do_not_claim_observed_backup(self):
        bounds = dump_bounds()
        self.assertEqual(bounds["requested_sectors"], 65536)
        self.assertEqual(bounds["nominal_data_bytes_if_all_reads_and_writes_succeed"], 33554432)
        self.assertEqual(bounds["nominal_total_bytes_if_all_reads_and_writes_succeed"], 34603008)

    def test_single_sector_inclusive_bounds(self):
        bounds = dump_bounds(7, 7, 512, 16)
        self.assertEqual(bounds["requested_sectors"], 1)
        self.assertEqual(bounds["nominal_total_bytes_if_all_reads_and_writes_succeed"], 528)

    def test_invalid_bounds_and_record_sizes_rejected(self):
        for args in ((1,0), (-1,3), (0,1,0), (0,1,512,-1)):
            with self.assertRaises(ValueError):
                dump_bounds(*args)


if __name__ == "__main__":
    unittest.main()
