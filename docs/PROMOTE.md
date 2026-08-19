# SYCTF — launch / promotion kit

Everything you need to post SYCTF on LinkedIn and make it travel.

---

## 📸 Assets to capture (in this order)

Record one short screen capture (30–60s) and grab 4–5 stills from it:

1. **The menu** — run `syctf`, let the banner animate, show the numbered menu. *(hero shot)*
2. **Solve** — `syctf solve "<base64>"` → `flag{...}` verified.
3. **Decoy reject** — `syctf solve examples/challenges/misc_decoy.bin --no-ai` →
   it prints the **real** flag and ignores the fakes. *(the "wow, it's honest" shot)*
4. **Agent** — `syctf agent ./chal` picking real modules to a verified flag.
5. **Bring any AI** — `syctf ai providers` (17 backends table).

Turn the capture into a GIF/MP4 for the post. (There's already
`assets/demo.gif` you can use directly.)

Recording tips: dark terminal theme, font ≥ 16pt, window ~100 cols, hide other
tabs. Use `--no-banner` for tighter frames, or keep the banner for branding.

---

## ✍️ LinkedIn post (copy-paste, then tweak)

> 🚩 I built **SYCTF** — an autonomous, menu-driven CTF framework that solves
> challenges *and refuses to lie about it.*
>
> Most AI solvers happily hallucinate a flag. SYCTF won't:
> ✅ it only reports a flag that **actually appears in real tool output**
> ✅ it detects and **skips planted decoy flags** (`fake`, `try_harder`, …)
> ✅ you can prove the answer against a hash/checker — zero guessing
>
> What makes it different:
> 🧠 **Bring any AI** — local Ollama by default, or Claude / OpenAI / Gemini /
> Groq / NVIDIA … 17 backends, one interface. Runs fully offline.
> 🎯 **Menu-driven** — no flags to memorize; pick a number.
> 🤖 **Agent mode** — the model drives the *actual* tools (RSA, ROP, stego,
> JWT, SQLi, OSINT…) in a loop.
> 🧩 **Every CTF type** — crypto · pwn · web · rev · forensics · mobile · cloud · OSINT.
> 🐍 Pure-Python internals (even the PNG decoder & binary-AXML parser) — light install.
>
> Free & open source. ⭐ it, break it, PR it:
> 👉 github.com/SYCO7/SYCTF
>
> #CTF #CyberSecurity #InfoSec #AI #Python #OpenSource #Hacking #RedTeam #LLM #DFIR

**Shorter variant (for the hook / reshare):**
> Autonomous CTF solver that won't hallucinate a flag — it proves it, rejects
> decoys, runs on any AI (or fully offline), and it's menu-driven. 🚩
> github.com/SYCO7/SYCTF #CTF #CyberSecurity #AI #Python

---

## 🧵 Follow-up content (keep momentum)

- **Carousel** — one slide per category (crypto/pwn/web/forensics/mobile/cloud/OSINT)
  with a before→flag screenshot.
- **"How it stays honest"** post — the grounding + decoy + oracle idea (people
  love the anti-hallucination angle).
- **"Build a plugin in 20 lines"** post — the `plugin.name / add_arguments / run`
  contract, to pull contributors.
- **Demo video** — narrate the runbook in `docs/DEMO.md` end-to-end.

## 📈 Where else to post

Reddit r/netsec r/securityCTF · X/Twitter (infosec) · Discord CTF servers ·
Hacker News (Show HN) · dev.to · your portfolio.

## ⭐ Repo hygiene that boosts stars

- Pin a great banner + demo GIF at the top of the README (done).
- Add GitHub **topics**: `ctf`, `ctf-tools`, `security`, `ai`, `llm`, `python`,
  `pentesting`, `automation`.
- Green CI badge (done). Good first issues labeled for contributors.
