import ctypes
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from build_creative_looks import DIRECTORY, compile_native, generated_header, load_native, load_profiles, reference


class CreativeLookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        library, cls.compiler = compile_native(Path(cls.temporary.name))
        cls.native = load_native(library)
        cls.config = load_profiles()

    @classmethod
    def tearDownClass(cls):
        if sys.platform == "win32":
            import _ctypes
            _ctypes.FreeLibrary(cls.native._handle)
        cls.native = None
        cls.temporary.cleanup()

    def test_generated_header_matches_profiles(self):
        self.assertEqual((DIRECTORY/"look_tables.h").read_text(), generated_header(self.config))

    def test_native_luts_and_scalar_match_python_on_grid_and_random_pixels(self):
        grid = bytes(channel for r in range(0, 256, 17) for g in range(0, 256, 17)
                     for b in range(0, 256, 17) for channel in (r, g, b))
        randomizer = random.Random(3300)
        data = grid+bytes(randomizer.randrange(256) for _ in range(3000))
        for look in range(5):
            expected = reference(self.config, data, look)
            for name in ("s3300_look_row", "s3300_look_reference_row"):
                with self.subTest(look=look, kernel=name):
                    buffer = (ctypes.c_uint8*len(data)).from_buffer_copy(data)
                    self.assertEqual(getattr(self.native, name)(buffer, len(data)//3, look), 1)
                    self.assertEqual(bytes(buffer), expected)

    def test_monochrome_is_neutral_and_gray_ramp_is_monotonic(self):
        data = bytes(channel for value in range(256) for channel in (value, value, value))
        output = reference(self.config, data, 4)
        self.assertEqual(output[::3], output[1::3])
        self.assertEqual(output[::3], output[2::3])
        self.assertEqual(list(output[::3]), sorted(output[::3]))

    def test_rejected_arguments_leave_buffer_and_row_guards_unchanged(self):
        for name in ("s3300_look_row", "s3300_look_reference_row"):
            function = getattr(self.native, name)
            data = (ctypes.c_uint8*9)(99, 98, 97, 10, 20, 30, 96, 95, 94)
            pointer = ctypes.cast(ctypes.byref(data, 3), ctypes.POINTER(ctypes.c_uint8))
            self.assertEqual(function(pointer, 1, 99), 0)
            self.assertEqual(bytes(data), bytes([99,98,97,10,20,30,96,95,94]))
            self.assertEqual(function(None, 1, 1), 0)
            self.assertEqual(function(None, ctypes.c_size_t(-1).value//3+1, 1), 0)
            self.assertEqual(function(None, 0, 0), 1)
            self.assertEqual(function(pointer, 1, 2), 1)
            self.assertEqual(bytes(data[:3]), bytes([99,98,97]))
            self.assertEqual(bytes(data[6:]), bytes([96,95,94]))

    def test_invalid_profiles_rejected_before_code_generation(self):
        for change in (lambda c: c["anchors_x"].__setitem__(1, 0),
                       lambda c: c["looks"][0]["tone"].__setitem__(2, 0),
                       lambda c: c["looks"][0]["gain_q8"].__setitem__(0, 513),
                       lambda c: c["looks"][3]["offset"].__setitem__(0, 1)):
            config = json.loads(json.dumps(self.config))
            change(config)
            path = Path(self.temporary.name)/"bad-profile.json"
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                load_profiles(path)


if __name__ == "__main__":
    unittest.main()
