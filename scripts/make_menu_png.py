#!/usr/bin/env python3
"""Render a colorful preview of the SYCTF main menu (headless, Pillow).

Output: assets/menu.png
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "menu.png"

W, H = 760, 660
BG = (13, 17, 23)
BAR = (22, 27, 34)
CYAN = (57, 197, 207)
GREEN = (86, 211, 100)
WHITE = (230, 237, 243)
DIM = (139, 148, 158)
MAG = (188, 140, 255)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

font = ImageFont.truetype(MONO, 20)
bold = ImageFont.truetype(MONO_BOLD, 20)
small = ImageFont.truetype(MONO_BOLD, 15)

ROWS = [
    ("1", "Autonomous Solve", GREEN),
    ("2", "Autonomous Agent", GREEN),
    ("3", "Crypto", WHITE), ("4", "Pwn", WHITE), ("5", "Web", WHITE),
    ("6", "Reverse Engineering", WHITE), ("7", "Forensics", WHITE),
    ("8", "Mobile", WHITE), ("9", "Cloud", WHITE), ("10", "OSINT", WHITE),
    ("11", "Recon  ·  12 Misc  ·  13 Fuzz  ·  14 Workspace", DIM),
    ("15", "AI Providers  ·  16 AI Setup  ·  17 Plugins", MAG),
    ("0", "Exit", DIM),
]


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # window chrome
    d.rectangle([0, 0, W, 40], fill=BAR)
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([20 + i * 22, 15, 32 + i * 22, 27], fill=col)
    d.text((W / 2 - 55, 12), "SYCTF — menu", font=small, fill=DIM)

    # panel
    d.rounded_rectangle([24, 60, W - 24, H - 70], radius=12, outline=CYAN, width=2)
    d.text((W / 2 - 70, 76), "MAIN  MENU", font=bold, fill=CYAN)
    d.line([(44, 108), (W - 44, 108)], fill=(30, 40, 50), width=1)

    y = 126
    for num, label, color in ROWS:
        d.text((60, y), f"[{num:>2}]", font=bold, fill=CYAN)
        d.text((130, y), label, font=font, fill=color)
        y += 34

    # prompt
    d.text((44, H - 52), "syctf ▸ select #:", font=bold, fill=GREEN)
    px = 44 + d.textlength("syctf ▸ select #: ", font=bold)
    d.rectangle([px, H - 50, px + 11, H - 30], fill=WHITE)

    img.save(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
