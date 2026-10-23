import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from workspace_functions import containing


class FunctionLookupTests(unittest.TestCase):
    def test_half_open_ranges_do_not_alias_adjacent_functions(self):
        functions = [{"start":4096, "end_exclusive":4100}, {"start":4100, "end_exclusive":4104}]
        self.assertEqual(containing(functions, 4100)["start"], 4100)
        with self.assertRaisesRegex(ValueError, "No unique"):
            containing(functions, 4104)

    def test_overlapping_ranges_cannot_select_arbitrary_function(self):
        with self.assertRaisesRegex(ValueError, "No unique"):
            containing([{"start":0,"end_exclusive":8},{"start":4,"end_exclusive":12}], 4)


if __name__ == "__main__":
    unittest.main()
