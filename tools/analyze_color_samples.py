"""Measure saved-JPEG chroma without changing images or assuming mode labels.

RGB-to-YCbCr values are decoded-image measurements, not raw camera ISP values.
Only metadata/histogram summaries are published; input photographs stay local.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from PIL import Image, ImageChops


def histogram_stats(histogram):
    count = sum(histogram)
    if count == 0:
        return {"pixels": 0, "mean": None, "standard_deviation": None, "median": None}
    mean = sum(i*n for i, n in enumerate(histogram))/count
    variance = sum((i-mean)**2*n for i, n in enumerate(histogram))/count
    threshold, cumulative, median = (count+1)//2, 0, None
    for i, n in enumerate(histogram):
        cumulative += n
        if cumulative >= threshold:
            median = i
            break
    return {"pixels": count, "mean": mean, "standard_deviation": math.sqrt(variance), "median": median}


def image_summary(image):
    rgb = image.convert("RGB")
    red, green, blue = rgb.split()
    grayscale_exact = ImageChops.difference(red, green).getbbox() is None and ImageChops.difference(green, blue).getbbox() is None
    cb, cr = rgb.convert("YCbCr").split()[1:]
    # Exclude near-clipped RGB values; this is an analysis mask, not denoising.
    masks = [channel.point([255 if 8 <= i <= 247 else 0 for i in range(256)]) for channel in (red, green, blue)]
    mask = ImageChops.multiply(ImageChops.multiply(masks[0], masks[1]), masks[2])
    return {"dimensions": list(rgb.size), "rgb_channels_exactly_equal": grayscale_exact,
            "all_pixels": {"cb": histogram_stats(cb.histogram()), "cr": histogram_stats(cr.histogram())},
            "unclipped_rgb_8_to_247": {"cb": histogram_stats(cb.histogram(mask)), "cr": histogram_stats(cr.histogram(mask))}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    if args.evidence.exists():
        raise ValueError("Use a new evidence path")
    records = []
    for path in sorted(args.folder.rglob("*")):
        if path.suffix.lower() not in (".jpg", ".jpeg") or not path.is_file():
            continue
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with Image.open(path) as image:
            exif = image.getexif()
            summary = image_summary(image)
            summary.update(model=str(exif.get(272, "")), software=str(exif.get(305, "")).rstrip("\0"))
        if hashlib.sha256(path.read_bytes()).hexdigest() != before:
            raise ValueError("Source changed during read-only analysis")
        records.append({"file": path.name, "sha256": before, **summary})
    if not records:
        raise ValueError("No JPEG samples")
    report = {"method": "Full-resolution Pillow decode, exact RGB equality and YCbCr histograms; no source writes",
              "samples": records, "input_photographs_published": False,
              "limitations": ["Mode names are not inferred solely from filename, EXIF saturation or histogram.",
                              "Decoded RGB-to-YCbCr conversion includes JPEG conversion/rounding/clipping.",
                              "A stock tint matching constants is corroboration, not proof of every hardware call or a modified firmware result."]}
    with args.evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"samples": len(records), "evidence": str(args.evidence),
                      "exact_gray_files": [r["file"] for r in records if r["rgb_channels_exactly_equal"]]}, indent=2))


if __name__ == "__main__":
    main()
