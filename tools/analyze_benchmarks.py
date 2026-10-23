"""Summarize measured camera timings. Never invent missing hardware observations.

One CSV row is one independently observed stage, in milliseconds. Matching
condition_id values assert the same scene/settings/card and measurement method.
Battery observations belong in a separate experiment, not this timing table.
"""
import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

FIELDS = ["firmware", "resolution_mp", "condition_id", "trial_id", "metric", "latency_ms",
          "uncertainty_ms", "outcome", "evidence", "notes"]
METRICS = {"startup_ready", "autofocus", "shutter_response", "processing", "card_write", "next_shot_ready", "button_feedback"}
OUTCOMES = {"ok", "crash", "corrupt_photo", "timeout", "cancel_failure"}


def percentile(values, proportion):
    values = sorted(values)
    position = (len(values)-1)*proportion
    low, high = math.floor(position), math.ceil(position)
    return values[low]+(values[high]-values[low])*(position-low)


def summarize(rows, baseline_name="stock-v1.1"):
    groups = defaultdict(list)
    identities = set()
    for line, row in enumerate(rows, 2):
        if any(not row.get(key) for key in FIELDS if key != "notes"):
            raise ValueError(f"Missing observation field at line {line}")
        if row["metric"] not in METRICS or row["outcome"] not in OUTCOMES:
            raise ValueError(f"Unknown metric/outcome at line {line}")
        resolution = int(row["resolution_mp"])
        if resolution not in (8, 16):
            raise ValueError("Use the measured 8 MP or 16 MP setting")
        latency, uncertainty = float(row["latency_ms"]), float(row["uncertainty_ms"])
        if not all(math.isfinite(x) and x >= 0 for x in (latency, uncertainty)):
            raise ValueError("Timing and uncertainty must be finite and nonnegative")
        key = row["firmware"], resolution, row["condition_id"], row["metric"]
        identity = key+(row["trial_id"],)
        if identity in identities:
            raise ValueError(f"Duplicate observation at line {line}")
        identities.add(identity)
        groups[key].append({**row, "latency_ms": latency, "uncertainty_ms": uncertainty})
    results = []
    for key, observations in sorted(groups.items()):
        successful = [r["latency_ms"] for r in observations if r["outcome"] == "ok"]
        results.append({"firmware": key[0], "resolution_mp": key[1], "condition_id": key[2], "metric": key[3],
                        "observations": len(observations), "successful_observations": len(successful),
                        "failures": [r for r in observations if r["outcome"] != "ok"],
                        "median_ms": statistics.median(successful) if successful else None,
                        "p95_ms": percentile(successful, .95) if successful else None,
                        "worst_success_ms": max(successful) if successful else None,
                        "max_uncertainty_ms": max(r["uncertainty_ms"] for r in observations),
                        "minimum_20_successes_observed": len(successful) >= 20})
    comparisons = []
    for candidate in results:
        for baseline in results:
            if baseline["firmware"] != baseline_name or candidate["firmware"].startswith("stock-"):
                continue
            if any(candidate[k] != baseline[k] for k in ("resolution_mp", "condition_id", "metric")):
                continue
            usable = candidate["minimum_20_successes_observed"] and baseline["minimum_20_successes_observed"]
            delta = baseline["median_ms"]-candidate["median_ms"] if usable else None
            comparisons.append({"baseline": baseline_name, "candidate": candidate["firmware"],
                                "resolution_mp": candidate["resolution_mp"], "condition_id": candidate["condition_id"],
                                "metric": candidate["metric"], "enough_observations": usable,
                                "median_reduction_ms": delta,
                                "p95_did_not_increase": candidate["p95_ms"] <= baseline["p95_ms"] if usable else None,
                                "worst_success_did_not_increase": candidate["worst_success_ms"] <= baseline["worst_success_ms"] if usable else None,
                                "no_failures_observed": not candidate["failures"] and not baseline["failures"],
                                "automatic_acceptance": False})
    return {"observed_rows": len(identities), "groups": results, "comparisons": comparisons,
            "hardware_measurements_present": bool(identities),
            "limitations": ["Rows require real evidence; this script does not instrument the camera.",
                            "A timing summary does not prove image integrity, battery savings or long-term reliability.",
                            "Condition identifiers must be documented; matching text does not independently verify matched conditions.",
                            "20 observations is a preliminary sampling floor, not a statistical guarantee."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--init", action="store_true", help="Create an EMPTY template, never sample measurements")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", default="stock-v1.1", help="Exact matching stock build; do not attribute v1.0/v1.1 differences to our patch")
    args = parser.parse_args()
    if args.init:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("x", newline="", encoding="utf-8") as handle:
            csv.writer(handle).writerow(FIELDS)
        print("Created empty template; no camera measurements recorded.")
        return
    with args.csv.open(newline="", encoding="utf-8-sig") as handle:
        report = summarize(csv.DictReader(handle), args.baseline)
    result = json.dumps(report, indent=2)+"\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(result)
    print(result)


if __name__ == "__main__":
    main()
