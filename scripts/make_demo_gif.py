#!/usr/bin/env python3
"""Render a terminal-style demo GIF for SYCTF (no screen recorder needed).

Frames are drawn with Pillow, so this runs headless in CI or on a server.
Output: assets/demo.gif

    pip install pillow
    python scripts/make_demo_gif.py
"""

from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "demo.gif"

W, H = 920, 560
PAD = 24
LINE_H = 26
TOP = 64
BG = (13, 17, 23)
BAR = (22, 27, 34)
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

C = {
    "prompt": (63, 185, 80),
    "cmd": (230, 237, 243),
    "dim": (139, 148, 158),
    "cyan": (57, 197, 207),
    "flag": (86, 211, 100),
    "magenta": (188, 140, 255),
    "yellow": (210, 168, 60),
    "red": (248, 81, 73),
}

font = ImageFont.truetype(FONT_PATH, 18)
bold = ImageFont.truetype(FONT_BOLD, 18)
title_font = ImageFont.truetype(FONT_BOLD, 15)
CW = font.getlength("M")


class Term:
    def __init__(self) -> None:
        self.lines: list[list[tuple[str, tuple[int, int, int], bool]]] = []
        self.frames: list[Image.Image] = []
        self.max_lines = (H - TOP - PAD) // LINE_H

    def _draw(self, partial=None, cursor=False) -> None:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, 40], fill=BAR)
        for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([PAD + i * 22, 15, PAD + i * 22 + 12, 27], fill=col)
        d.text((W / 2 - 60, 12), "SYCTF — demo", font=title_font, fill=C["dim"])

        visible = self.lines[-(self.max_lines - 1):] if len(self.lines) >= self.max_lines else self.lines
        y = TOP
        for line in visible:
            x = PAD
            for text, color, is_bold in line:
                d.text((x, y), text, font=(bold if is_bold else font), fill=color)
                x += CW * len(text)
            y += LINE_H
        if partial is not None:
            x = PAD
            for text, color, is_bold in partial:
                d.text((x, y), text, font=(bold if is_bold else font), fill=color)
                x += CW * len(text)
            if cursor:
                d.rectangle([x + 2, y + 2, x + 2 + CW, y + 20], fill=C["cmd"])
        self.frames.append(img)

    def hold(self, n: int) -> None:
        for _ in range(n):
            self._draw()

    def out(self, segments, hold=5) -> None:
        self.lines.append(segments)
        self._draw()
        self.hold(hold - 1)

    def blank(self, hold=3) -> None:
        self.out([("", C["dim"], False)], hold=hold)

    def type_cmd(self, prompt: str, cmd: str, hold_after=8) -> None:
        chars = list(cmd)
        for k in range(0, len(chars) + 1, 2):
            partial = [(prompt, C["prompt"], True), ("".join(chars[:k]), C["cmd"], False)]
            self._draw(partial=partial, cursor=True)
        self.lines.append([(prompt, C["prompt"], True), (cmd, C["cmd"], False)])
        self.hold(hold_after)


def seg(*pairs, bold=False):
    return [(t, c, bold) for t, c in pairs]


def _menu(t: "Term") -> None:
    t.out(seg(("  SYCTF · MAIN MENU", C["cyan"]), bold=True))
    t.out(seg(("   [1] ", C["cyan"]), ("Autonomous Solve", C["flag"]),
              ("    [2] ", C["cyan"]), ("Autonomous Agent", C["flag"])))
    t.out(seg(("   [3] Crypto   [4] Pwn   [5] Web   [7] Forensics", C["cmd"])))
    t.out(seg(("   [8] Mobile   [9] Cloud   [10] OSINT   [14] AI Providers", C["cmd"])))
    t.out(seg(("   [0] Exit", C["dim"])))


def build() -> Term:
    t = Term()
    t.hold(6)

    # --- fully menu-driven: launch shows the menu ---
    _menu(t)
    t.type_cmd("syctf ▸ select #: ", "1")            # pick Autonomous Solve
    t.out(seg(("▸ Autonomous Solve", C["magenta"]), bold=True))
    t.type_cmd("  target ▸ ", "ZmxhZ3tzeWN0Zl9pc19saXZlfQ==")
    t.out(seg(("  [1] classify-text ", C["dim"]), ("base64-like", C["cyan"])))
    t.out(seg(("  [2] auto-decode   ", C["dim"]), ("decoded via base64", C["cyan"])))
    t.out(seg(("  FLAG (verified) ", C["flag"]), ("flag{syctf_is_live}", C["flag"]), bold=True), hold=14)
    t.blank()

    # --- back to menu, pick the autonomous agent ---
    _menu(t)
    t.type_cmd("syctf ▸ select #: ", "2")            # pick Autonomous Agent
    t.out(seg(("▸ Autonomous Agent", C["magenta"]), bold=True))
    t.out(seg(("  [1] pwn/rop-finder     ", C["dim"]), ("pop rdi; ret @ 0x401234", C["cyan"])))
    t.out(seg(("  [2] crypto/rsa-attacks ", C["dim"]), ("factored n (Fermat)", C["cyan"])))
    t.out(seg(("  [guard] ", C["yellow"]), ("ignored decoy flag{try_harder}", C["yellow"])))
    t.out(seg(("  FLAG (verified) ", C["flag"]), ("flag{autonomous_win}", C["flag"]), bold=True), hold=16)
    t.blank()

    # --- any AI, anywhere ---
    t.out(seg(("  17 AI providers · local-first · proves the flag before it trusts it", C["cyan"]), bold=True), hold=20)
    t.hold(10)
    return t


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    term = build()
    frames = term.frames
    print(f"rendered {len(frames)} frames")
    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=90,
        loop=0,
        optimize=True,
    )
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main()
