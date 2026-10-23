import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from analyze_benchmarks import summarize


def row(firmware="stock-v1.1", trial="1", condition="daylight-card-A", latency="100"):
    return dict(firmware=firmware, resolution_mp="16", condition_id=condition, trial_id=trial,
                metric="next_shot_ready", latency_ms=latency, uncertainty_ms="4.2",
                outcome="ok", evidence="fixture-only", notes="synthetic test; not a camera measurement")


class BenchmarkTests(unittest.TestCase):
    def test_empty_template_cannot_claim_measurements(self):
        report = summarize([])
        self.assertFalse(report["hardware_measurements_present"])
        self.assertEqual(report["comparisons"], [])

    def test_different_conditions_not_compared(self):
        report = summarize([row(), row("candidate", condition="different-card")])
        self.assertEqual(report["comparisons"], [])

    def test_insufficient_samples_do_not_show_improvement(self):
        report = summarize([row(), row("candidate", latency="90")])
        self.assertIsNone(report["comparisons"][0]["median_reduction_ms"])

    def test_slow_tail_not_hidden_by_better_median(self):
        rows = [row(trial=str(i)) for i in range(20)]
        rows += [row("candidate", trial=str(i), latency="200" if i == 19 else "90") for i in range(20)]
        comparison = summarize(rows)["comparisons"][0]
        self.assertEqual(comparison["median_reduction_ms"], 10)
        self.assertFalse(comparison["worst_success_did_not_increase"])
        self.assertFalse(comparison["automatic_acceptance"])

    def test_duplicate_trials_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            summarize([row(), row()])

    def test_nonfinite_timing_rejected(self):
        with self.assertRaisesRegex(ValueError, "finite"):
            summarize([row(latency="NaN")])


if __name__ == "__main__":
    unittest.main()
