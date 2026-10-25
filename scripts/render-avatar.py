#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Render original geometric UVM artwork using only the Python standard library.

No fonts, external artwork, network, or runtime state are used. Writes only the
selected public SVG source and package avatar. --check compares without writes.
"""
import argparse
import math
from pathlib import Path
import struct
import zlib

SIZE = 256
BACKGROUND = (16, 27, 37)
# Rotate intact letters around their meeting baseline corners; never shear.
# Their baselines are tangents to one circle below the mark. The inner stems
# imply a V; there is no separate V polygon or contrasting overlay.
ANGLE = math.atan(1 / 4)


def rotate(points, angle):
    cosine, sine = math.cos(angle), math.sin(angle)
    return [(x * cosine - y * sine, x * sine + y * cosine) for x, y in points]


U_SOURCE = [(-53, -92), (-38, -92), (-38, -15), (-15, -15),
            (-15, -92), (0, -92), (0, 0), (-53, 0)]
M_SOURCE = [(0, 0), (0, -92), (15, -92), (36, -57),
            (57, -92), (72, -92), (72, 0), (57, 0),
            (57, -63), (36, -28), (15, -63), (15, 0)]
U_ROTATED = rotate(U_SOURCE, -ANGLE)
M_ROTATED = rotate(M_SOURCE, ANGLE)
X_OFFSET = SIZE / 2 - (min(x for x, _ in U_ROTATED + M_ROTATED)
                       + max(x for x, _ in U_ROTATED + M_ROTATED)) / 2
BASELINE_Y = 156
U = [(x + X_OFFSET, y + BASELINE_Y) for x, y in U_ROTATED]
M = [(x + X_OFFSET, y + BASELINE_Y) for x, y in M_ROTATED]
# A six-pixel circular band, mirrored vertically within its original bounds.
ARC_RADIUS = 220
ARC_CENTER = (128, 408)
ARC_HALF_ANGLE = math.asin(104 / ARC_RADIUS)
ARC_ANGLES = [-ARC_HALF_ANGLE + 2 * ARC_HALF_ANGLE * i / 48 for i in range(49)]
ARC = [(ARC_CENTER[0] + radius * math.sin(angle),
        ARC_CENTER[1] - radius * math.cos(angle))
       for radius, angles in ((ARC_RADIUS + 3, ARC_ANGLES),
                              (ARC_RADIUS - 3, list(reversed(ARC_ANGLES))))
       for angle in angles]
ARC_REFLECTION_Y = min(y for _, y in ARC) + max(y for _, y in ARC)
ARC = [(x, ARC_REFLECTION_Y - y) for x, y in ARC]
SHAPES = [
    ((96, 224, 195), U),
    ((96, 224, 195), M),
    ((96, 224, 195), ARC),
]


def inside(x, y, polygon):
    result = False
    previous = polygon[-1]
    for current in polygon:
        x1, y1 = previous
        x2, y2 = current
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            result = not result
        previous = current
    return result


def chunk(kind, data):
    return (struct.pack('>I', len(data)) + kind + data
            + struct.pack('>I', zlib.crc32(kind + data)))


def render_png():
    rows = bytearray()
    for y in range(SIZE):
        rows.append(0)
        for x in range(SIZE):
            samples = []
            for dy in (0.25, 0.75):
                for dx in (0.25, 0.75):
                    color = BACKGROUND
                    for fill, points in SHAPES:
                        if inside(x + dx, y + dy, points):
                            color = fill
                    samples.append(color)
            rows.extend(sum(color[c] for color in samples) // 4 for c in range(3))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', SIZE, SIZE, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(bytes(rows), 9)) + chunk(b'IEND', b''))


def render_svg():
    def color(rgb):
        return '#' + ''.join(f'{value:02x}' for value in rgb)
    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256" role="img" aria-labelledby="title desc">',
        '  <title id="title">UVM — Urbit Vere Manager</title>',
        '  <desc id="desc">Whole mint U and M letters rotated along a circular baseline, their inner strokes implying a V, above a mint circular arc on dark blue.</desc>',
        '  <!-- SPDX-License-Identifier: GPL-3.0-only; see LICENSE.md. -->',
        f'  <rect width="256" height="256" fill="{color(BACKGROUND)}"/>',
    ]
    for fill, points in SHAPES:
        coords = ' '.join(f'{x},{y}' for x, y in points)
        lines.append(f'  <polygon points="{coords}" fill="{color(fill)}"/>')
    lines.append('</svg>')
    return ('\n'.join(lines) + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    outputs = {'assets/uvm-avatar.svg': render_svg(), 'avatar-urbit.png': render_png()}
    for relative, data in outputs.items():
        path = root / relative
        if args.check:
            if path.read_bytes() != data:
                raise SystemExit(f'Artwork differs from generator: {relative}')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print(f'{"verified" if args.check else "rendered"}: {relative}')


if __name__ == '__main__':
    main()
