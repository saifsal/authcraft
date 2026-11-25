#!/usr/bin/env python3
"""Regenerate favicon.ico from favicon.svg (ADR 0027).

Renders the SVG at 16, 32, and 48 px with rsvg-convert and packs the PNGs
into one ICO (PNG-compressed entries, supported by every current browser).
Run from this directory: ./make-favicon.py
"""
import struct
import subprocess

SIZES = (16, 32, 48)

images = [
    subprocess.run(
        ["rsvg-convert", "-w", str(n), "-h", str(n), "favicon.svg"],
        check=True,
        capture_output=True,
    ).stdout
    for n in SIZES
]
header = struct.pack("<HHH", 0, 1, len(images))
offset = len(header) + 16 * len(images)
entries = b""
for size, png in zip(SIZES, images):
    entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset)
    offset += len(png)
with open("favicon.ico", "wb") as f:
    f.write(header + entries + b"".join(images))
