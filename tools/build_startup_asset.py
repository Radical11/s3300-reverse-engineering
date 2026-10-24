"""Build original POCKET STUDIO artwork as an exact-size research resource.

Writes local artwork and a source-bound patch plan only. Never stages or flashes.
JPEG size is matched by visible fine texture, never trailing bytes or padding.
"""
import argparse
from io import BytesIO
import json
from pathlib import Path
import random
import struct

from PIL import Image, ImageDraw, __version__ as PILLOW_VERSION

from map_embedded_resources import BASELINE, ROOT, sha


GLYPHS = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "I": ["11111", "00100", "00100", "00100", "00100", "00100", "11111"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "/": ["00001", "00001", "00010", "00100", "01000", "10000", "10000"],
    " ": ["00000"] * 7,
}


def artwork():
    """Source geometry is shared by SVG and raster: no external fonts/assets."""
    rectangles = [(0, 0, 640, 480, "#f2e8cc"), (34, 31, 572, 4, "#24241f"),
                  (34, 443, 572, 4, "#24241f"), (501, 57, 105, 74, "#ee6239")]

    def text(value, x, y, scale, color):
        for n, char in enumerate(value):
            for row, bits in enumerate(GLYPHS[char]):
                for col, bit in enumerate(bits):
                    if bit == "1":
                        rectangles.append((x+(6*n+col)*scale, y+row*scale, scale, scale, color))

    text("S3300 /", 38, 68, 3, "#24241f")
    text("POCKET", 39, 158, 14, "#24241f")
    text("STUDIO", 39, 269, 14, "#24241f")
    text("MAKE A LITTLE MEMORY", 39, 399, 4, "#24241f")
    # A small viewfinder cross on the orange corner.
    rectangles.extend([(546, 71, 15, 46, "#f2e8cc"), (530, 87, 47, 15, "#f2e8cc")])
    image = Image.new("RGB", (640, 480))
    draw = ImageDraw.Draw(image)
    for x, y, w, h, color in rectangles:
        draw.rectangle((x, y, x+w-1, y+h-1), fill=color)
    svg = '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="480" viewBox="0 0 640 480">\n'
    svg += '<title>POCKET STUDIO - S3300 / make a little memory</title>\n'
    svg += "\n".join(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{c}"/>'
                     for x, y, w, h, c in rectangles) + "\n</svg>\n"
    return image, svg


def jpeg_contract(data):
    """Conservative baseline, single-scan JPEG structure; no trailing payload."""
    if data[:2] != b"\xff\xd8":
        raise ValueError("JPEG SOI missing")
    cursor, markers, frame, scans = 2, [], None, 0
    while cursor < len(data):
        if data[cursor] != 255:
            raise ValueError("Expected JPEG marker")
        while cursor < len(data) and data[cursor] == 255:
            cursor += 1
        if cursor >= len(data):
            raise ValueError("Truncated JPEG marker")
        marker = data[cursor]
        cursor += 1
        if marker == 0xd9:
            if cursor != len(data) or frame is None or scans != 1:
                raise ValueError("EOI/trailing bytes/frame/scan mismatch")
            with Image.open(BytesIO(data)) as image:
                image.load()
                if image.mode != "RGB" or image.size != (640, 480):
                    raise ValueError("Decoded JPEG dimensions/mode differ")
            return {"frame": frame, "scan_count": scans, "markers": markers,
                    "bytes": len(data), "sha256": sha(data), "complete_decode": True}
        if marker in [0xd8, 0x00, 0x01] or 0xd0 <= marker <= 0xd7:
            raise ValueError("Unexpected standalone JPEG marker")
        if cursor+2 > len(data):
            raise ValueError("Missing JPEG segment length")
        size = int.from_bytes(data[cursor:cursor+2], "big")
        if size < 2 or cursor+size > len(data):
            raise ValueError("Truncated JPEG segment")
        payload = data[cursor+2:cursor+size]
        markers.append(marker)
        if 0xc0 <= marker <= 0xcf and marker not in (0xc4, 0xc8, 0xcc):
            if marker != 0xc0 or frame is not None or len(payload) < 6:
                raise ValueError("Only one baseline SOF0 frame supported")
            depth, height, width, components = struct.unpack(">BHHB", payload[:6])
            if (depth, width, height, components) != (8, 640, 480, 3) or len(payload) != 15:
                raise ValueError("JPEG frame differs from camera resource")
            component_fields = [list(payload[p:p+3]) for p in range(6, 15, 3)]
            if component_fields != [[1, 0x21, 0], [2, 0x11, 1], [3, 0x11, 1]]:
                raise ValueError("JPEG component IDs/sampling/table selectors differ")
            frame = {"marker": marker, "precision": depth, "width": width,
                     "height": height, "components": component_fields}
        cursor += size
        if marker == 0xda:
            scans += 1
            if frame is None or scans != 1 or payload != bytes.fromhex("03010002110311003f00"):
                raise ValueError("Unexpected JPEG scan layout")
            # Walk entropy bytes, permitting only stuffed FF and restart markers.
            while cursor < len(data):
                if data[cursor] != 255:
                    cursor += 1
                    continue
                if cursor+1 >= len(data):
                    raise ValueError("Truncated entropy escape")
                nxt = data[cursor+1]
                if nxt == 0 or 0xd0 <= nxt <= 0xd7:
                    cursor += 2
                else:
                    break
    raise ValueError("JPEG EOI missing")


def encode_exact(image, target):
    """Bounded natural-encoding search over small visible texture variations."""
    base = image.tobytes()
    rng = random.Random(3300)
    order = list(range(640*480))
    rng.shuffle(order)
    noise = [rng.choice((-8, -6, -4, -2, 2, 4, 6, 8)) for _ in order]

    def raster(n):
        body = bytearray(base)
        for pixel, delta in zip(order[:n], noise[:n]):
            for c in range(3):
                p = pixel*3+c
                body[p] = max(0, min(255, body[p]+delta))
        return body

    def encode(body, quality):
        buf = BytesIO()
        Image.frombytes("RGB", image.size, bytes(body)).save(
            buf, format="JPEG", quality=quality, subsampling=1, dpi=(72, 72),
            optimize=False, progressive=False)
        return buf.getvalue()

    attempts = 0
    for quality in (31, 32, 30, 29):
        lo, hi = 0, len(order)
        for _ in range(20):
            n = (lo+hi)//2
            encoded = encode(raster(n), quality)
            attempts += 1
            if len(encoded) == target:
                return encoded, {"quality": quality, "texture_pixels": n, "attempts": attempts}
            if len(encoded) < target:
                lo = n+1
            else:
                hi = n-1
            if lo > hi:
                break
        # Length need not be monotonic locally; examine both sides exhaustively.
        start, end = max(0, hi-2500), min(len(order), lo+2500)
        body = raster(start)
        for n in range(start, end+1):
            encoded = encode(body, quality)
            attempts += 1
            if len(encoded) == target:
                return encoded, {"quality": quality, "texture_pixels": n, "attempts": attempts}
            if n < len(order):
                for c in range(3):
                    p = order[n]*3+c
                    body[p] = max(0, min(255, base[p]+noise[n]))
        if attempts > 15000:
            break
    raise ValueError("No exact-length natural JPEG within bounded search; no padded asset emitted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory under ignored derived/")
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to((ROOT/"derived").resolve()):
        raise ValueError("Use a new directory under ignored derived/")
    source = (ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    if sha(source) != BASELINE:
        raise ValueError("Unsupported baseline")
    filesystem = json.loads((ROOT/"evidence/resource-filesystem.json").read_text())
    entry = next(f for f in filesystem["entries"] if f["path"] == "JPG/Startup1.jpg")
    original = b"".join(source[c["carrier_offset"]:c["carrier_offset"]+c["file_bytes"]]
                         for c in entry["chunks"])
    if sha(original) != entry["sha256"] or len(original) != 24210:
        raise ValueError("Startup JPEG binding differs")
    stock_contract = jpeg_contract(original)
    image, svg = artwork()
    replacement, search = encode_exact(image, len(original))
    contract = jpeg_contract(replacement)
    if contract["frame"] != stock_contract["frame"] or contract["markers"] != stock_contract["markers"]:
        raise ValueError("Replacement JPEG frame/marker layout differs from source")
    out.mkdir(parents=True)
    (out/"startup.svg").write_text(svg, encoding="utf-8")
    (out/"Startup1.jpg").write_bytes(replacement)
    plan = {"schema_version": 1, "name": "pocket-studio-startup-art", "source_sha256": BASELINE,
            "patches": [{"kind": "resource", "path": entry["path"],
                         "expected_sha256": sha(original),
                         "replacement_file": (out/"Startup1.jpg").relative_to(ROOT).as_posix(),
                         "replacement_sha256": sha(replacement)}]}
    (out/"patch-plan.json").write_text(json.dumps(plan, indent=2)+"\n")
    report = {"source_sha256": BASELINE, "source_contract": stock_contract,
              "replacement_contract": contract, "encoding_search": search,
              "pillow_version": PILLOW_VERSION, "source_svg_sha256": sha(svg.encode()),
              "no_padding_or_trailing_bytes": True, "source_geometry_fonts": "repository-defined 5x7 pixel glyphs",
              "hardware_startup_activation_verified": False, "staged": False, "flashed": False,
              "limitations": ["Host JPEG validation does not prove acceptance by the camera JPEG decoder.",
                              "No measured startup performance or battery improvement.",
                              "No executable code, update policy, firmware version or sound changes."]}
    (out/"manifest.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
