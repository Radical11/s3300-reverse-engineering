"""Evaluate an integer tone-lift design on local original S3300 JPEG copies.

Host-only experiment. This is neither a firmware patch nor raw development.
No inference about device power/speed, recovered detail, or denoising is made.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageOps


def table_from_anchors(xs, ys):
    table = []
    for value in range(256):
        index = next(i for i in range(len(xs) - 1) if value <= xs[i + 1])
        width = xs[index + 1] - xs[index]
        table.append(ys[index] + ((value - xs[index]) * (ys[index+1] - ys[index]) + width//2)//width)
    return np.asarray(table, dtype=np.uint8)


def apply_lift(rgb, table, band_rows=64):
    """64-row band processing, integer luma delta, preserve RGB headroom."""
    output = np.empty_like(rgb)
    changed = clipped = bright_changed = 0
    for row in range(0, rgb.shape[0], band_rows):
        band = rgb[row:row+band_rows].astype(np.uint16)
        y = (77 * band[:, :, 0] + 150 * band[:, :, 1] + 29 * band[:, :, 2] + 128) >> 8
        # Coefficients sum to 256; uint16 intermediate maximum is 65408.
        lift = table[y].astype(np.int16) - y.astype(np.int16)
        if np.any(lift < 0):
            raise ValueError("This kernel accepts nonnegative lift tables only")
        delta = np.minimum(lift, 255 - band.max(axis=2)).astype(np.uint16)
        result = (band + delta[:, :, None]).astype(np.uint8)
        output[row:row+band_rows] = result
        changed += int(np.count_nonzero(delta))
        clipped += int(np.count_nonzero((result == 255) & (band < 255)))
        bright_changed += int(np.count_nonzero((y >= 224) & (delta != 0)))
    return output, {"changed_pixels": changed, "new_channel_values_at_255": clipped,
                    "changed_pixels_with_input_luma_ge_224": bright_changed}


def summarize(rgb):
    band = rgb.astype(np.uint16)
    y = ((77 * band[:, :, 0] + 150 * band[:, :, 1] + 29 * band[:, :, 2] + 128) >> 8).astype(np.uint8)
    return {"luma_percentiles": [float(x) for x in np.percentile(y, [1, 10, 50, 90, 99])],
            "fraction_luma_below_32": float(np.mean(y < 32)),
            "fraction_luma_at_255": float(np.mean(y == 255))}


def verify_kernel(table):
    # Every grayscale input plus a bounded 3-D colour grid checks headroom.
    ramp = np.arange(256, dtype=np.uint8)
    ramp_rgb = np.repeat(ramp[None, :, None], 3, axis=2)
    identity, _ = apply_lift(ramp_rgb, ramp)
    if not np.array_equal(identity, ramp_rgb):
        raise RuntimeError("Identity table changed grayscale pixels")
    actual, _ = apply_lift(ramp_rgb, table)
    if not np.array_equal(actual[0, :, 0], table):
        raise RuntimeError("Grayscale lookup did not match the table")
    grid = np.asarray(np.meshgrid(np.arange(0, 256, 17), np.arange(0, 256, 17),
                                 np.arange(0, 256, 17), indexing="ij"), dtype=np.uint8)
    grid = grid.transpose(1, 2, 3, 0).reshape(-1, 1, 3)
    actual, counts = apply_lift(grid, table)
    if np.any(actual < grid) or counts["changed_pixels_with_input_luma_ge_224"]:
        raise RuntimeError("Colour-grid brightness or highlight invariant failed")
    if np.any(np.max(actual.astype(np.int16)-grid.astype(np.int16), axis=2) > int(np.max(table.astype(int)-ramp))):
        raise RuntimeError("Colour grid exceeded maximum lift")
    return {"all_256_grayscale_inputs_verified": True, "colour_grid_samples": len(grid),
            "highlight_guard_verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    # Preserve deep black and high luminance; peak lift is 26 code values.
    table = table_from_anchors([0, 8, 24, 64, 112, 176, 224, 255],
                              [0, 8, 34, 90, 138, 186, 224, 255])
    checks = verify_kernel(table)
    (args.output / "shadow_lift_luma8.bin").write_bytes(table.tobytes())
    paths = sorted(args.input.glob("*.JPG"))
    if not paths:
        raise ValueError("No JPG inputs")
    sheet = Image.new("RGB", (1200, len(paths)*260), "#161b22")
    draw = ImageDraw.Draw(sheet)
    rows = []
    for i, path in enumerate(paths):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        original = ImageOps.exif_transpose(Image.open(path)).convert("RGB")
        pixels = np.asarray(original)
        started = time.perf_counter()
        processed, changes = apply_lift(pixels, table)
        elapsed = time.perf_counter() - started
        result = Image.fromarray(processed)
        result.save(args.output / f"{path.stem}-shadow-lift.png")
        for j, (label, img) in enumerate([("Original JPEG", original), ("Host-only shadow lift", result)]):
            thumb = img.copy()
            thumb.thumbnail((590, 224))
            x, y = j * 600, i * 260
            sheet.paste(thumb, (x + (600-thumb.width)//2, y+28))
            draw.text((x+12, y+8), f"{path.name} | {label}", fill="white")
        rows.append({"source": path.name, "source_sha256": digest,
                     "size": list(original.size), "original_metrics": summarize(pixels),
                     "candidate_metrics": summarize(processed), "changes": changes,
                     "host_processing_seconds_excluding_decode_encode": elapsed,
                     "result_file": f"{path.stem}-shadow-lift.png"})
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Original sample changed")
    sheet.save(args.output / "comparison.jpg", quality=93)
    report = {"method": "Integer luminance-delta shadow lift on already processed JPEGs",
              "checks": checks, "table": table.tolist(), "files": rows,
              "limitations": ["Not equivalent to applying a table inside the sensor/ISP pipeline.",
                              "No denoising or recovery of clipped JPEG detail.",
                              "Shadow lift can make noise more visible; no quality ground truth supplied.",
                              "Timing is host NumPy only; it says nothing about camera speed or power.",
                              "No firmware resources or camera files were changed."]}
    (args.output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"images": len(rows), "checks": checks,
                      "comparison": str((args.output / "comparison.jpg").resolve())}, indent=2))


if __name__ == "__main__":
    main()
