#!/usr/bin/env python3
"""Render a colorful preview of the SYCTF grouped main menu (Pillow, headless).

Output: assets/menu.png
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "menu.png"

W, H = 900, 660
BG = (13, 17, 23)
BAR = (22, 27, 34)
CYAN = (57, 197, 207)
GREEN = (86, 211, 100)
WHITE = (230, 237, 243)
DIM = (139, 148, 158)
MAG = (188, 140, 255)
YEL = (210, 168, 60)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
font = ImageFont.truetype(MONO, 18)
bold = ImageFont.truetype(MONO_BOLD, 18)
head = ImageFont.truetype(MONO_BOLD, 17)
small = ImageFont.truetype(MONO_BOLD, 15)

LEFT = [
    ("h", "AUTONOMOUS", GREEN),
    ("r", "1", "Autonomous Solve"),
    ("r", "2", "Autonomous Agent"),
    ("h", "CATEGORIES", CYAN),
    ("r", "3", "Crypto"), ("r", "4", "Pwn"), ("r", "5", "Web"),
    ("r", "6", "Reverse Engineering"), ("r", "7", "Forensics"),
    ("r", "8", "Mobile"), ("r", "9", "Cloud"), ("r", "10", "OSINT"),
    ("r", "11", "Recon"), ("r", "12", "Fuzz"), ("r", "13", "Misc / Decode"),
]
RIGHT = [
    ("h", "AI", MAG),
    ("r", "14", "AI Providers"), ("r", "15", "AI Setup"),
    ("r", "16", "AI Exploit"), ("r", "17", "AI Writeup"),
    ("h", "TOOLS", YEL),
    ("r", "18", "Auto-Decode"), ("r", "19", "Workspace"),
    ("r", "20", "Plugins"), ("r", "21", "About / Author"),
    ("g", "", None), ("r", "0", "Exit"),
]


def _draw_col(d: ImageDraw.ImageDraw, rows, x: int, y0: int) -> None:
    y = y0
    for row in rows:
        if row[0] == "g":
            y += 20
            continue
        if row[0] == "h":
            d.rectangle([x - 12, y + 3, x - 7, y + 19], fill=row[2])
            d.text((x, y), row[1], font=head, fill=row[2])
            y += 34
            continue
        _, num, label = row
        d.text((x, y), f"[{num:>2}]", font=bold, fill=CYAN)
        d.text((x + 62, y), label, font=font, fill=WHITE)
        y += 30


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 40], fill=BAR)
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([20 + i * 22, 15, 32 + i * 22, 27], fill=col)
    d.text((W / 2 - 90, 12), "SYCTF — main menu", font=small, fill=DIM)

    d.rounded_rectangle([24, 58, W - 24, H - 66], radius=12, outline=CYAN, width=2)
    d.text((W / 2 - 62, 74), "MAIN  MENU", font=bold, fill=CYAN)
    d.line([(44, 104), (W - 44, 104)], fill=(30, 40, 50), width=1)

    _draw_col(d, LEFT, 70, 124)
    _draw_col(d, RIGHT, 480, 124)

    d.text((44, H - 50), "syctf ▸ select #:", font=bold, fill=GREEN)
    px = 44 + d.textlength("syctf ▸ select #: ", font=bold)
    d.rectangle([px, H - 48, px + 11, H - 28], fill=WHITE)

    img.save(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
