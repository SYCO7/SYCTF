#!/usr/bin/env python3
"""Render a colorful hero banner PNG for the README (headless, Pillow).

Output: assets/banner.png

    pip install pillow
    python scripts/make_banner.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "banner.png"

W, H = 1200, 340
BG_TOP = (13, 17, 23)
BG_BOT = (17, 24, 33)
GREEN = (63, 185, 80)
CYAN = (57, 197, 207)
DIM = (139, 148, 158)

SANS_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def _v_gradient(size, top, bot):
    w, h = size
    base = Image.new("RGB", (1, h))
    for y in range(h):
        t = y / max(1, h - 1)
        base.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    return base.resize((w, h))


def _h_gradient(size, left, right):
    w, h = size
    base = Image.new("RGB", (w, 1))
    for x in range(w):
        t = x / max(1, w - 1)
        base.putpixel((x, 0), tuple(int(left[i] + (right[i] - left[i]) * t) for i in range(3)))
    return base.resize((w, h))


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img = _v_gradient((W, H), BG_TOP, BG_BOT).convert("RGB")
    d = ImageDraw.Draw(img)

    # very faint scanlines for a terminal vibe (kept subtle so text stays crisp)
    for y in range(0, H, 6):
        d.line([(0, y), (W, y)], fill=(18, 24, 32))

    wordmark = ImageFont.truetype(SANS_BOLD, 150)
    tag = ImageFont.truetype(MONO_BOLD, 26)
    tagline = ImageFont.truetype(MONO, 24)

    text = "SYCTF"
    tw = d.textlength(text, font=wordmark)
    tx, ty = (W - tw) / 2 - 30, 40

    # gradient-filled wordmark via mask
    mask = Image.new("L", (W, H), 0)
    md = ImageDraw.Draw(mask)
    md.text((tx, ty), text, font=wordmark, fill=255)
    glow = mask.filter(ImageFilter.GaussianBlur(10))
    grad = _h_gradient((W, H), GREEN, CYAN)
    img.paste(grad, (0, 0), Image.eval(glow, lambda p: int(p * 0.35)))  # soft glow
    img.paste(grad, (0, 0), mask)                                       # crisp letters
    d = ImageDraw.Draw(img)

    # [ AI ] chip near the wordmark
    chip = "[ AI ]"
    cx = tx + tw + 18
    d.rounded_rectangle([cx, ty + 24, cx + d.textlength(chip, font=tag) + 20, ty + 60], radius=8, outline=CYAN, width=2)
    d.text((cx + 10, ty + 28), chip, font=tag, fill=CYAN)

    # accent underline
    d.line([(W / 2 - 300, 232), (W / 2 + 300, 232)], fill=CYAN, width=2)

    sub = "Autonomous · menu-driven · local-first CTF framework"
    d.text(((W - d.textlength(sub, font=tagline)) / 2, 254), sub, font=tagline, fill=DIM)
    tail = "point it at a challenge · it proves the flag before it trusts it"
    small = ImageFont.truetype(MONO, 18)
    d.text(((W - d.textlength(tail, font=small)) / 2, 292), tail, font=small, fill=(88, 166, 100))

    img.save(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
