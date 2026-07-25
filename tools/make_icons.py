"""Render the application icon set.

The UI draws its icons at runtime with QPainter, but PyInstaller and Inno Setup
need a real ``.ico`` file. This script produces one from the same shield
geometry, so the installer, the executable and the running window all match.

Usage::

    python tools/make_icons.py --output packaging/assets
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)

ACCENT = (91, 140, 255, 255)
ACCENT_DARK = (58, 106, 214, 255)
WHITE = (255, 255, 255, 255)


def _shield_points(size: int) -> list[tuple[float, float]]:
    """Polygon approximation of the shield used by the Qt renderer."""
    margin = size * 0.08
    x, y = margin, margin
    w = h = size - margin * 2

    return [
        (x + w * 0.50, y),
        (x + w * 0.94, y + h * 0.18),
        (x + w * 0.94, y + h * 0.52),
        (x + w * 0.88, y + h * 0.68),
        (x + w * 0.74, y + h * 0.84),
        (x + w * 0.50, y + h),
        (x + w * 0.26, y + h * 0.84),
        (x + w * 0.12, y + h * 0.68),
        (x + w * 0.06, y + h * 0.52),
        (x + w * 0.06, y + h * 0.18),
    ]


def render(size: int) -> "Image.Image":  # type: ignore[name-defined]  # noqa: F821
    from PIL import Image, ImageDraw

    # Supersample, then downscale: cheap antialiasing without a vector renderer.
    scale = 4
    canvas = size * scale
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.polygon(_shield_points(canvas), fill=ACCENT, outline=ACCENT_DARK)

    if size >= 24:
        width = max(2, int(canvas * 0.085))
        draw.line(
            [
                (canvas * 0.34, canvas * 0.50),
                (canvas * 0.45, canvas * 0.62),
                (canvas * 0.68, canvas * 0.38),
            ],
            fill=WHITE,
            width=width,
            joint="curve",
        )
        radius = width / 2
        for point in ((canvas * 0.34, canvas * 0.50), (canvas * 0.68, canvas * 0.38)):
            draw.ellipse(
                [point[0] - radius, point[1] - radius, point[0] + radius, point[1] + radius],
                fill=WHITE,
            )

    return image.resize((size, size), Image.Resampling.LANCZOS)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render PDFSafe icons.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("packaging/assets"),
        help="Directory to write pdfsafe.ico and pdfsafe.png into.",
    )
    arguments = parser.parse_args()

    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print("Pillow is required: pip install pillow", file=sys.stderr)
        return 1

    output = arguments.output
    output.mkdir(parents=True, exist_ok=True)

    images = [render(size) for size in ICO_SIZES]

    ico_path = output / "pdfsafe.ico"
    images[-1].save(ico_path, format="ICO", sizes=[(s, s) for s in ICO_SIZES])
    print(f"wrote {ico_path}")

    png_path = output / "pdfsafe.png"
    images[-1].save(png_path, format="PNG")
    print(f"wrote {png_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
