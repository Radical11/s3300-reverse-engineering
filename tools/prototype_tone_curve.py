"""Build a host-only 8-bit tone-curve experiment from S3300 resource evidence.

This does not patch firmware. Directly replacing a resource is not yet validated.
The candidate assumes a full-range 8-bit sample; actual pipeline ranges/colour
space and resource consumers must be recovered before camera integration.
"""
import csv
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    source = root / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    data = source.read_bytes()
    expected = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("Firmware identity mismatch; re-map resources first")
    curves = {f"vendor_dde_{i}": list(data[offset:offset + 256])
              for i, offset in enumerate([0xb212c0, 0xb216c0, 0xb21ac0, 0xb21ec0], 1)}
    # Offline generation uses integer arithmetic. On-target lookup would use
    # one 256-byte table, provided the recovered consumer accepts this format.
    curves["candidate_gentle_lift"] = [
        x + (48 * x * (255 - x) + 32512) // 65025 for x in range(256)
    ]
    candidate = curves["candidate_gentle_lift"]
    if (candidate[0], candidate[-1]) != (0, 255):
        raise RuntimeError("Endpoint check failed")
    if any(not 0 <= value <= 255 for value in candidate):
        raise RuntimeError("Range check failed")
    if any(a > b for a, b in zip(candidate, candidate[1:])):
        raise RuntimeError("Monotonicity check failed")
    if curves["vendor_dde_1"] != list(range(256)):
        raise RuntimeError("Expected identity resource changed")
    output = root / "prototype"
    output.mkdir(exist_ok=True)
    (output / "gentle_lift_luma8.bin").write_bytes(bytes(candidate))
    with (output / "tone_curves.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["input", *curves])
        writer.writerows([x, *(curve[x] for curve in curves.values())] for x in range(256))
    (output / "tone_curve.h").write_text(
        "/* OFFLINE PROTOTYPE ONLY. Camera consumer/ranges/integrity unverified. */\n"
        "#include <stdint.h>\n"
        "static const uint8_t gentle_lift_luma8[256] = {\n"
        + ",\n".join("    " + ", ".join(map(str, candidate[i:i+16])) for i in range(0, 256, 16))
        + "\n};\n", encoding="utf-8")
    metrics = {name: {"entries": len(values), "black_output_inputs": values.count(0),
                      "white_output_inputs": values.count(255),
                      "first_white_input": values.index(255),
                      "monotonic": all(a <= b for a, b in zip(values, values[1:])),
                      "max_adjacent_step": max(b-a for a, b in zip(values, values[1:])),
                      "sha256": hashlib.sha256(bytes(values)).hexdigest()}
               for name, values in curves.items()}
    (output / "metrics.json").write_text(json.dumps({
        "firmware_sha256": expected, "metrics": metrics,
        "verification": "All 256 inputs checked for candidate range, endpoints and monotonicity.",
        "interpretation": "Vendor resources numerically resemble 8-bit tone curves. Their exact consumer, input domain and active modes are unknown.",
        "limitations": "No camera integration, image-quality evaluation, timing or power measurements. No claim of efficiency gain or improvement over Nikon's intended effect."
    }, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
