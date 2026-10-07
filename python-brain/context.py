"""
XSSHunter — Context Detection Engine

Determines WHERE a payload lands in the response:
  - html        : <div>PAYLOAD</div>
  - attr_double : value="PAYLOAD"
  - attr_single : value='PAYLOAD'
  - attr_unquoted : value=PAYLOAD
  - js_string_single : var x = 'PAYLOAD'
  - js_string_double : var x = "PAYLOAD"
  - js_template : var x = `PAYLOAD`
  - script_block : <script>PAYLOAD</script>
  - comment     : <!-- PAYLOAD -->
  - url         : reflected in href/src (url context)
  - unknown
"""

from dataclasses import dataclass, field
from typing import Optional
import re

# =========================================================
# Developer Info
# =========================================================
__author__ = "ATHEX BLACK HAT"
__version__ = "0.1.0"
__license__ = "MIT"

DEVELOPER_INFO = {
    "name": "XSSHunter",
    "version": __version__,
    "author": __author__,
    "license": __license__,
    "description": "Advanced XSS Hunter — Go + Python hybrid",
    "module": "context.py",
}


# =========================================================
# ASCII Banner (used by CLI / brain)
# =========================================================
BANNER = r"""
 __  __ ____  ____  _   _             _
 \ \/ // ___|/ ___|| | | |_   _ _ __ | |_ ___ _ __
  \  / \___ \\___ \| |_| | | | | '_ \| __/ _ \ '__|
  /  \  ___) |___) |  _  | |_| | | | | ||  __/ |
 /_/\_\|____/|____/|_| |_|\__,_|_| |_|\__\___|_|

        Advanced XSS Hunter  •  Go + Python Hybrid
        Author : ATHEX BLACK HAT
        Version: 0.1.0  |  License: MIT
        Modules: crawler • injector • callback • waf
                 context • payloads • dom • report
"""


def print_banner():
    """Print ASCII banner to stdout."""
    print(BANNER)


def print_developer_info():
    """Print developer info block."""
    print(f"  {DEVELOPER_INFO['name']} v{DEVELOPER_INFO['version']}")
    print(f"  Author : {DEVELOPER_INFO['author']}")
    print(f"  License: {DEVELOPER_INFO['license']}")
    print(f"  Module : {DEVELOPER_INFO['module']}")
    print()


# =========================================================
# Context Result
# =========================================================
@dataclass
class ContextResult:
    context: str = "unknown"          # html, attr_double, js_string_single, ...
    confidence: int = 0               # 0-100
    before: str = ""                  # chars before marker
    after: str = ""                   # chars after marker
    tag: str = ""                     # surrounding tag name (e.g., "div", "input")
    attr: str = ""                    # attribute name if in attr context
    quote: str = ""                   # quote char used ('"' or "'")
    in_script: bool = False
    in_comment: bool = False
    in_url: bool = False
    raw_snippet: str = ""             # full snippet for report
    notes: list = field(default_factory=list)


# =========================================================
# Regex helpers
# =========================================================
RE_TAG_OPEN = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9\-]*)")
RE_ATTR = re.compile(r"""([a-zA-Z_:][a-zA-Z0-9_:\.\-]*)\s*=\s*(["']?)""")
RE_SCRIPT_OPEN = re.compile(r"<\s*script\b", re.IGNORECASE)
RE_SCRIPT_CLOSE = re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE)
RE_COMMENT_OPEN = re.compile(r"<!--")
RE_COMMENT_CLOSE = re.compile(r"-->")
RE_JS_STRING = re.compile(r"""(?P<q>["'`])(?P<content>[^"'`\\]*(?:\\.[^"'`\\]*)*)(?P=q)""")


# =========================================================
# Main detection function
# =========================================================
def detect_context(body: str, marker: str) -> ContextResult:
    """
    Find marker in body and classify its context.
    Returns ContextResult with best guess.
    """
    if not body or not marker:
        return ContextResult(context="unknown", confidence=0)

    idx = body.find(marker)
    if idx == -1:
        # try case-insensitive
        idx = body.lower().find(marker.lower())
    if idx == -1:
        return ContextResult(context="unknown", confidence=0, notes=["marker not found"])

    before = body[max(0, idx - 200): idx]
    after = body[idx + len(marker): idx + len(marker) + 200]

    result = ContextResult(
        before=before,
        after=after,
        raw_snippet=_snippet(body, idx, len(marker)),
    )

    # 1. Comment context
    if _in_comment(body, idx):
        result.context = "comment"
        result.confidence = 90
        result.in_comment = True
        return result

    # 2. Script block context
    if _in_script(body, idx):
        result.in_script = True
        # Are we inside a JS string?
        js_ctx = _detect_js_string(body, idx)
        if js_ctx:
            result.context = js_ctx
            result.confidence = 85
            result.quote = "`" if "template" in js_ctx else (
                "'" if "single" in js_ctx else '"'
            )
            return result
        # Plain script block
        result.context = "script_block"
        result.confidence = 80
        return result

    # 3. Attribute context
    attr_ctx = _detect_attr(body, idx)
    if attr_ctx:
        result.context = attr_ctx["context"]
        result.confidence = attr_ctx["confidence"]
        result.tag = attr_ctx.get("tag", "")
        result.attr = attr_ctx.get("attr", "")
        result.quote = attr_ctx.get("quote", "")
        if result.attr in ("href", "src", "action", "data", "formaction"):
            result.in_url = True
        return result

    # 4. URL context (if marker is in href/src but tag not parsed)
    if _in_url(body, idx):
        result.context = "url"
        result.confidence = 60
        result.in_url = True
        return result

    # 5. Plain HTML context
    if _in_html(body, idx):
        result.context = "html"
        result.confidence = 75
        return result

    result.context = "unknown"
    result.confidence = 20
    return result


# =========================================================
# Comment detection
# =========================================================
def _in_comment(body: str, idx: int) -> bool:
    last_open = body.rfind("<!--", 0, idx)
    if last_open == -1:
        return False
    last_close = body.rfind("-->", 0, idx)
    return last_close < last_open


# =========================================================
# Script block detection
# =========================================================
def _in_script(body: str, idx: int) -> bool:
    last_open = -1
    for m in RE_SCRIPT_OPEN.finditer(body, 0, idx):
        last_open = m.start()
    if last_open == -1:
        return False
    last_close = -1
    for m in RE_SCRIPT_CLOSE.finditer(body, 0, idx):
        last_close = m.start()
    return last_close < last_open


# =========================================================
# JS string detection (inside <script>)
# =========================================================
def _detect_js_string(body: str, idx: int) -> Optional[str]:
    # Find script boundaries
    open_matches = list(RE_SCRIPT_OPEN.finditer(body, 0, idx))
    if not open_matches:
        return None
    script_start = open_matches[-1].end()

    close_matches = list(RE_SCRIPT_CLOSE.finditer(body, script_start, idx + 50))
    if close_matches:
        script_end = close_matches[0].start()
    else:
        script_end = min(len(body), idx + 500)

    js = body[script_start:script_end]
    rel = idx - script_start
    if rel < 0 or rel > len(js):
        return None

    # Walk through JS, tracking string state
    in_single = False
    in_double = False
    in_template = False
    escaped = False
    i = 0
    while i < rel:
        ch = js[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == '"':
                in_double = False
        elif in_template:
            if ch == "`":
                in_template = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "`":
                in_template = True
        i += 1

    if in_single:
        return "js_string_single"
    if in_double:
        return "js_string_double"
    if in_template:
        return "js_template"
    return None


# =========================================================
# Attribute context detection
# =========================================================
def _detect_attr(body: str, idx: int) -> Optional[dict]:
    # Find nearest '<' before marker (start of tag)
    lt = body.rfind("<", 0, idx)
    if lt == -1:
        return None
    gt_before = body.rfind(">", 0, idx)
    if gt_before > lt:
        # We're between tags, not inside one
        return None

    # Tag name
    tag_match = RE_TAG_OPEN.match(body, lt)
    tag = tag_match.group(1).lower() if tag_match else ""

    # Find nearest '>' after marker
    gt_after = body.find(">", idx)
    if gt_after == -1:
        gt_after = min(len(body), idx + 200)

    tag_str = body[lt: gt_after + 1]

    # Locate marker inside tag_str and figure out which attribute
    local_idx = idx - lt

    # Parse attributes up to marker
    i = 0
    # skip tag name
    m = RE_TAG_OPEN.match(tag_str)
    if m:
        i = m.end()

    last_attr = None
    last_quote = ""
    in_quote = None
    quote_start = -1
    while i < len(tag_str):
        ch = tag_str[i]
        if in_quote:
            if ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_quote = ch
            quote_start = i
            i += 1
            continue
        # Try to read attribute
        am = RE_ATTR.match(tag_str, i)
        if am:
            last_attr = am.group(1).lower()
            last_quote = am.group(2) or ""
            i = am.end()
            if last_quote:
                in_quote = last_quote
                quote_start = i - 1
            continue
        i += 1

    # Determine context based on where marker is relative to quote
    if in_quote == '"':
        return {
            "context": "attr_double",
            "confidence": 90,
            "tag": tag,
            "attr": last_attr or "",
            "quote": '"',
        }
    if in_quote == "'":
        return {
            "context": "attr_single",
            "confidence": 90,
            "tag": tag,
            "attr": last_attr or "",
            "quote": "'",
        }

    # Marker is inside tag but not quoted → unquoted attr value OR between attrs
    return {
        "context": "attr_unquoted",
        "confidence": 70,
        "tag": tag,
        "attr": last_attr or "",
        "quote": "",
    }


# =========================================================
# URL context detection
# =========================================================
def _in_url(body: str, idx: int) -> bool:
    before = body[max(0, idx - 100): idx]
    after = body[idx: idx + 100]
    window = before + after
    return bool(re.search(r'(?:href|src|action|formaction|data)\s*=\s*["\']?[^"\'>]*$',
                          before, re.IGNORECASE))


# =========================================================
# Plain HTML context check
# =========================================================
def _in_html(body: str, idx: int) -> bool:
    lt = body.rfind("<", 0, idx)
    gt = body.rfind(">", 0, idx)
    # If last '>' is after last '<', we're between tags (plain HTML)
    return gt > lt or lt == -1


# =========================================================
# Snippet extraction
# =========================================================
def _snippet(body: str, idx: int, marker_len: int, window: int = 80) -> str:
    start = max(0, idx - window)
    end = min(len(body), idx + marker_len + window)
    s = body[start:end]
    s = s.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return ("..." if start > 0 else "") + s + ("..." if end < len(body) else "")


# =========================================================
# Public helper — recommended payload category
# =========================================================
def recommend_payload_category(ctx: ContextResult) -> list[str]:
    """
    Given a ContextResult, return list of payload category keys
    (as used in payloads.yaml) that are most likely to work.
    """
    c = ctx.context
    if c == "html":
        return ["html_context", "polyglots", "mxss"]
    if c == "attr_double":
        return ["attr_double", "polyglots"]
    if c == "attr_single":
        return ["attr_single", "polyglots"]
    if c == "attr_unquoted":
        return ["attr_unquoted", "polyglots"]
    if c == "js_string_single":
        return ["js_string_single", "js_template"]
    if c == "js_string_double":
        return ["js_string_double", "js_template"]
    if c == "js_template":
        return ["js_template"]
    if c == "script_block":
        return ["script_block"]
    if c == "comment":
        return ["comment"]
    if c == "url":
        return ["dom_sinks", "html_context"]
    # unknown
    return ["polyglots", "html_context", "attr_double", "attr_single"]


# =========================================================
# CLI self-test
# =========================================================
if __name__ == "__main__":
    print_banner()
    print_developer_info()

    tests = [
        ('<div>XSS_HUNTER_BY_ATHEX</div>', "XSS_HUNTER_BY_ATHEX"),
        ('<input value="XSS_HUNTER_BY_ATHEX">', "XSS_HUNTER_BY_ATHEX"),
        ("<input value='XSS_HUNTER_BY_ATHEX'>", "XSS_HUNTER_BY_ATHEX"),
        ('<input value=XSS_HUNTER_BY_ATHEX>', "XSS_HUNTER_BY_ATHEX"),
        ('<script>var x = "XSS_HUNTER_BY_ATHEX";</script>', "XSS_HUNTER_BY_ATHEX"),
        ("<script>var x = 'XSS_HUNTER_BY_ATHEX';</script>", "XSS_HUNTER_BY_ATHEX"),
        ("<script>var x = `XSS_HUNTER_BY_ATHEX`;</script>", "XSS_HUNTER_BY_ATHEX"),
        ('<script>XSS_HUNTER_BY_ATHEX</script>', "XSS_HUNTER_BY_ATHEX"),
        ('<!-- XSS_HUNTER_BY_ATHEX -->', "XSS_HUNTER_BY_ATHEX"),
        ('<a href="XSS_HUNTER_BY_ATHEX">link</a>', "XSS_HUNTER"),
    ]

    for body, marker in tests:
        ctx = detect_context(body, marker)
        cats = ", ".join(recommend_payload_category(ctx))
        print(f"  {ctx.context:18s} conf={ctx.confidence:3d}  cats=[{cats}]  tag={ctx.tag} attr={ctx.attr} quote={ctx.quote}")