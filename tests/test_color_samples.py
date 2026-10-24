from pathlib import Path
import sys
import unittest

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from analyze_color_samples import histogram_stats, image_summary


class ColorSampleTests(unittest.TestCase):
    def test_neutral_mono_has_exact_rgb_equality_and_neutral_chroma(self):
        image = Image.new("RGB", (2, 1))
        image.putdata([(80, 80, 80), (180, 180, 180)])
        result = image_summary(image)
        self.assertTrue(result["rgb_channels_exactly_equal"])
        for channel in ("cb", "cr"):
            self.assertEqual(result["all_pixels"][channel]["mean"], 128)
            self.assertEqual(result["all_pixels"][channel]["standard_deviation"], 0)

    def test_color_is_not_misclassified_from_average_neutral_chroma(self):
        image = Image.new("RGB", (2, 1))
        image.putdata([(200, 80, 40), (40, 160, 200)])
        self.assertFalse(image_summary(image)["rgb_channels_exactly_equal"])

    def test_clipping_mask_excludes_any_near_clipped_channel(self):
        image = Image.new("RGB", (4, 1))
        image.putdata([(0, 40, 80), (50, 255, 80), (80, 80, 250), (120, 120, 120)])
        result = image_summary(image)
        self.assertEqual(result["all_pixels"]["cb"]["pixels"], 4)
        self.assertEqual(result["unclipped_rgb_8_to_247"]["cb"]["pixels"], 1)
        self.assertEqual(result["unclipped_rgb_8_to_247"]["cr"]["mean"], 128)

    def test_empty_mask_is_explicit_and_not_a_neutral_result(self):
        result = image_summary(Image.new("RGB", (1, 1), "black"))
        self.assertIsNone(result["unclipped_rgb_8_to_247"]["cb"]["mean"])

    def test_histogram_statistics_weight_counts(self):
        values = [0]*256
        values[10], values[30] = 1, 3
        result = histogram_stats(values)
        self.assertEqual(result["pixels"], 4)
        self.assertEqual(result["mean"], 25)
        self.assertEqual(result["median"], 30)
        self.assertAlmostEqual(result["standard_deviation"], 75**0.5)


if __name__ == "__main__":
    unittest.main()
