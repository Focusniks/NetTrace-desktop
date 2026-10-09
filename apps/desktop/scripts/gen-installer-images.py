"""Generates the NSIS installer artwork (header and welcome/finish sidebar).

Run from apps/desktop:  python scripts/gen-installer-images.py
Needs Pillow and the Segoe UI fonts (Windows). The output BMPs are committed,
so this only has to be rerun when the artwork changes.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent.parent / "src-tauri" / "installer"
FONTS = Path("C:/Windows/Fonts")
SS = 4  # supersampling factor for smooth lines

BG_TOP = (27, 34, 48)
BG_BOTTOM = (14, 17, 23)
GRID = (36, 45, 62)
ACCENT = (90, 162, 255)
DOT = (232, 163, 61)
TEXT = (232, 236, 242)
MUTED = (139, 150, 168)

# The logo waveform from icons/source.svg (1024x1024 viewBox).
WAVE = [(190, 560), (330, 560), (390, 380), (470, 700), (560, 300), (640, 620), (690, 520), (834, 520)]


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size * SS)


def canvas(w: int, h: int) -> Image.Image:
    img = Image.new("RGB", (w * SS, h * SS))
    d = ImageDraw.Draw(img)
    for y in range(h * SS):
        k = y / (h * SS - 1)
        d.line([(0, y), (w * SS, y)], fill=tuple(round(a + (b - a) * k) for a, b in zip(BG_TOP, BG_BOTTOM)))
    return img


def grid(img: Image.Image, step: int) -> None:
    d = ImageDraw.Draw(img)
    w, h = img.size
    for x in range(0, w, step * SS):
        d.line([(x, 0), (x, h)], fill=GRID, width=1)
    for y in range(0, h, step * SS):
        d.line([(0, y), (w, y)], fill=GRID, width=1)


def wave(img: Image.Image, x: float, y: float, size: float, width: float) -> None:
    """Draws the logo waveform scaled to `size` px, top-left of its 1024 box at (x, y)."""
    d = ImageDraw.Draw(img)
    k = size / 1024
    pts = [((x + px * k) * SS, (y + py * k) * SS) for px, py in WAVE]
    w = max(1, round(width * SS))
    d.line(pts, fill=ACCENT, width=w, joint="curve")
    r = w / 2
    for px, py in pts:
        d.ellipse([px - r, py - r, px + r, py + r], fill=ACCENT)
    cx, cy = pts[-1]
    dr = 34 * k * SS * 1.25
    d.ellipse([cx - dr, cy - dr, cx + dr, cy + dr], fill=DOT)


def logo_tile(img: Image.Image, x: float, y: float, size: float) -> None:
    d = ImageDraw.Draw(img)
    k = size / 1024
    box = [(x + 64 * k) * SS, (y + 64 * k) * SS, (x + 960 * k) * SS, (y + 960 * k) * SS]
    d.rounded_rectangle(box, radius=200 * k * SS, fill=BG_TOP, outline=(47, 59, 82), width=max(1, round(16 * k * SS)))
    wave(img, x, y, size, 56 * k)


def text(img: Image.Image, xy: tuple[float, float], s: str, f: ImageFont.FreeTypeFont, fill, anchor: str = "la") -> None:
    ImageDraw.Draw(img).text((xy[0] * SS, xy[1] * SS), s, font=f, fill=fill, anchor=anchor)


def save(img: Image.Image, w: int, h: int, name: str) -> None:
    # NSIS needs a plain 24-bit BMP without alpha.
    img.resize((w, h), Image.LANCZOS).convert("RGB").save(OUT / name, format="BMP")
    print("wrote", OUT / name)


def sidebar() -> None:
    w, h = 164, 314
    img = canvas(w, h)
    grid(img, 16)
    # A long trace across the panel, as on a capture timeline.
    wave(img, -34, -24, 230, 4)
    logo_tile(img, 18, 176, 40)
    text(img, (64, 184), "NetTrace", font("segoeuib.ttf", 17), TEXT)
    text(img, (18, 226), "Анализатор", font("segoeui.ttf", 12), MUTED)
    text(img, (18, 242), "сетевого трафика", font("segoeui.ttf", 12), MUTED)
    text(img, (18, 290), "PCAP · PCAPNG · Live", font("segoeui.ttf", 9), (98, 110, 130))
    save(img, w, h, "sidebar.bmp")


def header() -> None:
    w, h = 150, 57
    img = canvas(w, h)
    logo_tile(img, 8, 8, 41)
    text(img, (54, 28.5), "NetTrace", font("segoeuib.ttf", 16), TEXT, anchor="lm")
    save(img, w, h, "header.bmp")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    sidebar()
    header()
