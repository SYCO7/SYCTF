# SYCTF — manual feature walkthrough (screenshot / video runbook)

Every step below is **offline and reproducible** — it uses the sample
challenges in `examples/challenges/` (regenerate any time with
`python scripts/make_samples.py`). Each step prints a real flag, so it is
screenshot-worthy. Suggested order for a demo video is top → bottom.

```bash
# setup (once)
python3 -m venv ctfvenv && source ctfvenv/bin/activate
pip install -r requirements.txt
```

> Tip: add `--no-banner` to any command for a cleaner screenshot, or omit it to
> show the animated startup banner with your operator identity.

---

## 0 · Launch the menu + set the flag format  📸

```bash
python -m syctf          # or: syctf
```
Pick numbers to drive everything. `0` exits. **Screenshot the menu.**

At the **start of a challenge**, set the flag format (menu item **Set Flag
Format**, or the prompt shown when you pick Solve/Agent). It is stored for the
whole session and used by **every** module — the header shows the active format.
Accepts `picoCTF`, `HTB`, `flag`, a full `NAME{}`, or a regex. On the CLI:
`syctf solve <target> --flag-format picoCTF{}`.

---

## 1 · Autonomous Solve  📸

```bash
syctf solve "$(cat examples/challenges/crypto_b64.txt)" --no-ai
```
**Expected:** `FLAG (verified)  flag{base64_layers_are_fun}` (multi-layer base64, auto-detected).

---

## 2 · Decoy rejection + anti-hallucination  📸  ⭐

```bash
syctf solve examples/challenges/misc_decoy.bin --no-ai
```
The file contains `flag{fake_try_harder}`, `flag{decoy_nice_try}` **and** the real
`flag{the_real_one_2024}`.
**Expected:** it reports **`flag{the_real_one_2024}`** and ignores the decoys.

Why it can't be fooled or guess:
- A flag is reported **only if it literally appears in tool output** (never invented).
- Known **decoys** (`fake`, `try_harder`, `decoy`, `nope`, `troll`, `honeypot`, …) are skipped.
- For certainty, verify against an oracle (a published hash or a checker) — see step 12.

---

## 3 · Autonomous Agent (LLM drives real tools)  📸

Needs a reachable AI backend (local Ollama or a hosted key — see step 11).

```bash
export ANTHROPIC_API_KEY=sk-...          # or run Ollama locally
SYCTF_AI_PROVIDER=anthropic syctf agent examples/challenges/crypto_b64.txt
```
**Expected:** the agent picks modules step-by-step and returns a **verified** flag.
Without a backend it degrades gracefully and tells you to configure one.

---

## 4 · Crypto  📸

```bash
# RSA — factors n (Fermat, close primes) and decrypts
syctf crypto-helper rsa-attacks \
  --n "$(grep -oP 'n = \K.*' examples/challenges/crypto_rsa.txt)" \
  --e 65537 \
  --c "$(grep -oP 'c = \K.*' examples/challenges/crypto_rsa.txt)"
# Expected: method = Fermat (close primes) → FLAG flag{rsa_fermat_close_primes}

# XOR — single-byte brute force
syctf crypto-helper xor-tools --data "$(cat examples/challenges/crypto_xor.hex)"
# Expected: FLAG (single-byte key=0x42) flag{single_byte_xor_0x42}
```

---

## 5 · Web  📸

```bash
syctf web-helper jwt-tool --token "$(cat examples/challenges/web_token.jwt)"
# Expected: alg=none forgery emitted + "HS256 secret cracked: 'secret'"
```
Network probes (need a target URL with `FUZZ`):
```bash
syctf web-helper sqli-probe --url "http://TARGET/item?id=FUZZ"
syctf web-helper lfi-probe  --url "http://TARGET/?page=FUZZ"
syctf web-helper xss-probe  --url "http://TARGET/search?q=FUZZ"
```

---

## 6 · Forensics  📸

```bash
syctf forensics stegano      --file examples/challenges/forensics_stego.png
# Expected: FLAG (LSB 1-bit) flag{lsb_stego_hidden_pixels}

syctf forensics pcap-extract --file examples/challenges/forensics_capture.pcap
# Expected: flag{sniffed_from_the_wire} + Authorization header surfaced

syctf forensics zip-crack    --file examples/challenges/forensics_secret.zip
# Expected: FLAG in flag.txt flag{zip_archive_recovered}
```

---

## 7 · Mobile (APK)  📸

```bash
syctf mobile apk-info    --file examples/challenges/mobile_app.apk   # manifest + security flags
syctf mobile apk-secrets --file examples/challenges/mobile_app.apk   # AKIA... AWS key + URLs
syctf mobile dex-strings --file examples/challenges/mobile_app.apk   # flag{apk_reverse_engineered}
```

---

## 8 · Cloud  📸

```bash
syctf cloud cloud-keys --text "aws=AKIAIOSFODNN7EXAMPLE"     # finds the AWS key
syctf cloud s3-enum    --bucket flags-bucket                 # existence + public-listing
syctf cloud imds-ssrf  --url "http://TARGET/proxy?url=FUZZ"  # AWS/GCP/Azure metadata via SSRF
```

---

## 9 · OSINT (live network)  📸

```bash
syctf osint dns-recon      --domain example.com     # A/AAAA/MX/NS/TXT via DoH
syctf osint subdomains     --domain example.com     # crt.sh certificate transparency
syctf osint whois          --domain example.com     # RDAP registration
syctf osint username-enum  --username SYCO7          # presence across platforms
```

---

## 10 · Pwn  📸

```bash
syctf pwn-helper rop-finder --file /bin/ls           # ROP gadgets + /bin/sh + syscalls
syctf pwn-helper fmtstr --offset 6 --addr 0x601050 --value 0xdeadbeef --arch 64
```

---

## 11 · Bring any AI  📸

```bash
syctf ai providers        # table of all 17 backends + which keys are configured
```
Switch backend with `SYCTF_AI_PROVIDER` + `SYCTF_AI_MODEL` + that provider's key
env (see `.env.example`). Local Ollama needs no key.

---

## 12 · Prove a flag (oracle) — no guessing

In Python / a plugin, confirm a flag against something authoritative:
```python
from syctf.ai.verifier import Verifier
v = Verifier()
v.verify_flag("flag{x}", expected_sha256="<hash the challenge published>")   # True/False
v.verify_flag("flag{x}", checker=my_submit_function)                          # True/False
```
No oracle → it returns `False` (it will not *claim* certainty it cannot prove).

---

## ✅ Feature checklist

| # | Feature | Command | Expected |
|---|---|---|---|
| 1 | Solve | `solve <b64>` | flag{base64_layers_are_fun} |
| 2 | Decoy reject | `solve misc_decoy.bin` | flag{the_real_one_2024} |
| 3 | Agent | `agent <target>` | verified flag (needs AI) |
| 4 | RSA / XOR | `crypto-helper …` | flag{rsa_…} / flag{single_byte_…} |
| 5 | JWT | `web-helper jwt-tool` | secret cracked / alg=none |
| 6 | Stego / pcap / zip | `forensics …` | 3 flags |
| 7 | Mobile | `mobile …` | AWS key + flag{apk_…} |
| 8 | Cloud | `cloud …` | key found / bucket state |
| 9 | OSINT | `osint …` | live DNS / subdomains |
| 10 | Pwn | `pwn-helper rop-finder` | gadgets |
| 11 | AI providers | `ai providers` | 17 backends |

Run `pytest tests/unit -q` for the automated suite.

---

## 🎯 Live walkthrough — picoCTF (or any free CTF)

picoCTF (play.picoctf.org) is free and beginner-friendly. Two challenge shapes:

**1) Set the flag format once** — picoCTF flags are `picoCTF{...}`:
```bash
syctf                       # menu → Tools & Settings → Set Flag Format → picoCTF
# or on the CLI, add:  --flag-format picoCTF{}
```

**2) Downloadable-file challenges** (Forensics / Crypto / Reverse / General):
```bash
# download the file(s) from the challenge page, then:
syctf solve ./thefile --flag-format picoCTF{}          # hands-free deterministic pass
syctf agent ./thefile --flag-format picoCTF{}          # AI-driven (needs Ollama or a key)

# or target the right tool directly:
syctf forensics metadata     --file ./picture.jpg      # "information", EXIF challenges
syctf forensics stegano      --file ./image.png        # LSB stego
syctf forensics pcap-extract --file ./capture.pcap     # packet-capture challenges
syctf crypto-helper rsa-attacks --n <n> --e <e> --c <c> # RSA (values from the file)
syctf auto-decode "<blob>"                             # base64/hex/rot chains
```
Worked examples: *Mod26 / rotation* → `syctf solve "picoCTF{...}" --flag-format picoCTF{}`;
*base64* → same; *information* → `forensics metadata`; *Trivial Flag Transfer* →
`forensics pcap-extract`.

**3) Remote-service challenges** (Web `http://…:port`, or `nc host port`):
```bash
syctf web-helper jwt-tool   --token "<cookie/JWT from the site>"
syctf web-helper sqli-probe --url "http://HOST:PORT/page?id=FUZZ"
syctf web-helper lfi-probe  --url "http://HOST:PORT/?file=FUZZ"
```
> Remote `nc` pwn interaction isn't automated — SYCTF gives you gadgets
> (`pwn-helper rop-finder`) + heap math (`pwn-helper heap-helper`); finish in pwntools.

**4) Sweep a downloaded set** — one board for a whole event:
```bash
syctf arena ./picoCTF_downloads --flag-format picoCTF{}
```

Only test on platforms/challenges you're authorized to (picoCTF, HTB, CTFtime
events — all fine).
