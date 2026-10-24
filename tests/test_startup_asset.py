"""Check resource-format boundaries rather than firmware acceptance claims."""
from io import BytesIO
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from PIL import Image
from build_startup_asset import artwork, jpeg_contract


def make_jpeg(**kwargs):
    buf = BytesIO()
    Image.new("RGB", kwargs.pop("size", (640, 480)), (240, 230, 200)).save(
        buf, format="JPEG", subsampling=kwargs.pop("subsampling", 1), **kwargs)
    return buf.getvalue()


class StartupAssetTests(unittest.TestCase):
    def test_baseline_camera_geometry(self):
        contract = jpeg_contract(make_jpeg())
        self.assertEqual(contract["frame"]["components"], [[1, 33, 0], [2, 17, 1], [3, 17, 1]])
        self.assertTrue(contract["complete_decode"])

    def test_reject_progressive_sampling_and_dimension_changes(self):
        for options in ({"progressive": True}, {"subsampling": 2}, {"size": (320, 240)}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                jpeg_contract(make_jpeg(**options))

    def test_reject_trailing_bytes_and_truncation(self):
        data = make_jpeg()
        for malformed in (data+b"\x00", data[:-1], data[:32], b"not a JPEG"):
            with self.subTest(size=len(malformed)), self.assertRaises(ValueError):
                jpeg_contract(malformed)

    def test_reject_invalid_marker_length(self):
        data = bytearray(make_jpeg())
        data[4:6] = b"\xff\xff"
        with self.assertRaises(ValueError):
            jpeg_contract(bytes(data))

    def test_artwork_independent_of_fonts_and_repeatable(self):
        first, svg = artwork()
        second, same_svg = artwork()
        self.assertEqual(first.tobytes(), second.tobytes())
        self.assertEqual(svg, same_svg)
        self.assertNotIn("<text", svg)
        self.assertIn("POCKET STUDIO", svg)


if __name__ == "__main__":
    unittest.main()
