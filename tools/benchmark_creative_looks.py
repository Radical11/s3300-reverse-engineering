"""Compile and benchmark native kernels on a private S3300 JPEG COPY.

These are host kernel timings against an equivalent scalar reference, not
camera timings or comparisons against Nikon's existing ISP/firmware.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import statistics
import time

from build_creative_looks import DIRECTORY, ROOT, compile_native, load_native, load_profiles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path)
    parser.add_argument("output", type=Path, help="New local directory under derived/")
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/"derived").resolve()) or not 3 <= args.repetitions <= 15:
        raise ValueError("Choose new derived output and 3..15 repetitions")
    from PIL import Image
    input_bytes = args.sample.read_bytes()
    source_sha = hashlib.sha256(input_bytes).hexdigest()
    with Image.open(args.sample) as opened:
        exif = opened.getexif()
        if "COOLPIX S3300" not in str(exif.get(272, "")) or opened.size != (4608,3456):
            raise ValueError("Expected an original full-resolution S3300 JPEG copy")
        original = opened.convert("RGB")
    library_path, compiler = compile_native(output/"native")
    library = load_native(library_path)
    report = {"method": "Native C LUT versus exactly equivalent native scalar profile evaluation",
              "timing_domain": "host_only", "host_platform": platform.platform(), "compiler": compiler,
              "input_sha256": source_sha, "profiles_sha256": hashlib.sha256((DIRECTORY/"profiles.json").read_bytes()).hexdigest(),
              "c_source_sha256": hashlib.sha256((DIRECTORY/"looks.c").read_bytes()).hexdigest(),
              "host_library_sha256": hashlib.sha256(library_path.read_bytes()).hexdigest(),
              "lookup_table_bytes": 2560, "kernel_heap_allocations": 0,
              "kernel_full_frame_working_buffer_bytes": 0, "measurements": [],
              "camera_integrated": False, "camera_speedup_measured": False,
              "limitations": ["RGB8 developed-JPEG domain; capture buffer format/stage is not verified.",
                              "8 MP input is host-resized, not an on-camera 8 MP capture measurement.",
                              "Only kernel execution is timed; caller buffer preparation, JPEG decode, hashing and I/O are excluded.",
                              "Scalar profile evaluation is our reference, not Nikon's stock processing algorithm.",
                              "No autofocus, shutter, startup, write latency, battery improvement or overall camera speed is measured."]}
    for size in ((4608,3456), (3264,2448)):
        image = original if original.size == size else original.resize(size, Image.Resampling.LANCZOS)
        data, pixels = image.tobytes(), size[0]*size[1]
        for look in load_profiles()["looks"]:
            timings, hashes = {}, {}
            for name, function in (("lut", library.s3300_look_row), ("scalar_reference", library.s3300_look_reference_row)):
                values = []
                for repetition in range(args.repetitions+1):
                    buffer = (ctypes.c_uint8*len(data)).from_buffer_copy(data)
                    start = time.perf_counter_ns()
                    result = function(buffer, pixels, look["id"])
                    elapsed = (time.perf_counter_ns()-start)/1e6
                    if result != 1:
                        raise ValueError("Native processing failed")
                    digest = hashlib.sha256(buffer).hexdigest()
                    if name in hashes and hashes[name] != digest:
                        raise ValueError("Native output is not repeatable")
                    hashes[name] = digest
                    if repetition:
                        values.append(elapsed)
                timings[name] = {"milliseconds": values, "median_ms": statistics.median(values), "max_ms": max(values)}
            if hashes["lut"] != hashes["scalar_reference"]:
                raise ValueError("LUT and scalar full-resolution outputs differ")
            report["measurements"].append({"look": look["name"], "size": size, "pixels": pixels,
                                           "outputs_exact_by_sha256": True, "output_sha256": hashes["lut"],
                                           "timings": timings,
                                           "host_reference_to_lut_median_ratio": timings["scalar_reference"]["median_ms"]/timings["lut"]["median_ms"]})
            print(f"{look['name']} {size}: native LUT {timings['lut']['median_ms']:.2f} ms, scalar {timings['scalar_reference']['median_ms']:.2f} ms", flush=True)
    if hashlib.sha256(args.sample.read_bytes()).hexdigest() != source_sha:
        raise ValueError("Source copy changed")
    report["source_unchanged"] = True
    (output/"benchmark.json").write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    main()
