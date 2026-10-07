"""
XSSHunter — Payload Engine

Loads payloads.yaml, provides:
  - context-aware payload selection
  - encoding variants (URL, HTML entity, unicode, hex, base64)
  - mutation (case, whitespace, comments)
  - WAF bypass payloads
  - blind XSS payload builder
  - search + stats
"""

import base64
import html
import random
import re
import string
from pathlib import Path
from typing import Optional
from urllib.parse import quote, quote_plus

import yaml


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
    "module": "payloads.py",
}


# =========================================================
# Context → YAML category mapping
# =========================================================
CONTEXT_MAP = {
    "html":              ["html_context", "polyglots", "mxss"],
    "attr_double":       ["attr_double", "polyglots"],
    "attr_single":       ["attr_single", "polyglots"],
    "attr_unquoted":     ["attr_unquoted", "polyglots"],
    "js_string_single":  ["js_string_single", "js_template"],
    "js_string_double":  ["js_string_double", "js_template"],
    "js_template":       ["js_template"],
    "script_block":      ["script_block"],
    "comment":           ["comment"],
    "url":               ["dom_sinks", "html_context"],
    "unknown":           ["polyglots", "html_context", "attr_double", "attr_single"],
}

# Encodings auto-generated for every payload (configurable)
DEFAULT_ENCODINGS = ["raw", "url", "html_dec", "html_hex"]


# =========================================================
# PayloadEngine
# =========================================================
class PayloadEngine:
    """
    Loads payloads.yaml and provides selection + encoding.

    Usage:
        engine = PayloadEngine("payloads.yaml")
        payloads = engine.select_for_context("attr_double", waf_bypass=True)
        print(payloads[0]["raw"], payloads[0]["encoded"])
    """

    def __init__(self, yaml_path: str = "payloads.yaml", encodings: Optional[list] = None):
        self.yaml_path = yaml_path
        self.encodings = encodings or DEFAULT_ENCODINGS
        self.db = {}
        self._counter = 0
        self._load()

    # -----------------------------------------------------
    # Load YAML
    # -----------------------------------------------------
    def _load(self):
        p = Path(self.yaml_path)
        if not p.exists():
            raise FileNotFoundError(f"Payload file not found: {self.yaml_path}")

        with p.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        # Keep only list-valued keys for payload categories
        for k, v in raw.items():
            if isinstance(v, list):
                self.db[k] = v

        # waf_bypass is a dict of {vendor: [payloads]}
        self.waf_db = raw.get("waf_bypass", {}) if isinstance(raw.get("waf_bypass"), dict) else {}

        # encoding_variants metadata (if any)
        self.encoding_meta = raw.get("encoding_variants", {})

    # -----------------------------------------------------
    # Stats
    # -----------------------------------------------------
    def stats(self) -> dict:
        out = {}
        for cat, items in self.db.items():
            out[cat] = len(items)
        for vendor, items in self.waf_db.items():
            out[f"waf_bypass/{vendor}"] = len(items)
        return out

    def total(self) -> int:
        return sum(self.stats().values())

    # -----------------------------------------------------
    # ID generator
    # -----------------------------------------------------
    def _next_id(self, prefix: str = "p") -> str:
        self._counter += 1
        return f"{prefix}_{self._counter:04d}"

    # -----------------------------------------------------
    # ENCODERS
    # -----------------------------------------------------
    def enc_url(self, payload: str, double: bool = False) -> str:
        """URL encode. If double=True, encode twice (WAF bypass)."""
        e = quote(payload, safe="")
        if double:
            e = quote(e, safe="")
        return e

    def enc_url_plus(self, payload: str) -> str:
        return quote_plus(payload, safe="")

    def enc_html_dec(self, payload: str) -> str:
        """HTML decimal entities: < → &#60;"""
        return "".join(f"&#{ord(c)};" if c in "<>\"'&" else c for c in payload)

    def enc_html_hex(self, payload: str) -> str:
        """HTML hex entities: < → &#x3c;"""
        return "".join(f"&#x{ord(c):x};" if c in "<>\"'&" else c for c in payload)

    def enc_html_named(self, payload: str) -> str:
        """HTML named entities (basic)."""
        mapping = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "&": "&amp;"}
        return "".join(mapping.get(c, c) for c in payload)

    def enc_unicode(self, payload: str) -> str:
        """JS unicode escapes: < → \\u003c"""
        return "".join(f"\\u{ord(c):04x}" if c in "<>\"'\\/" else c for c in payload)

    def enc_hex_js(self, payload: str) -> str:
        """JS hex escapes: < → \\x3c"""
        return "".join(f"\\x{ord(c):02x}" if c in "<>\"'\\/" else c for c in payload)

    def enc_base64(self, payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    def enc_mixed_case(self, payload: str) -> str:
        """Randomly uppercase letters: <script> → <ScRiPt>"""
        out = []
        for c in payload:
            if c.isalpha() and random.random() < 0.5:
                out.append(c.upper())
            else:
                out.append(c.lower())
        return "".join(out)

    def enc_whitespace(self, payload: str) -> str:
        """Replace spaces with tab/newline/comment."""
        variants = ["\t", "\n", "\r", "/**/", "%09", "%0a", "%0d"]
        out = []
        for c in payload:
            if c == " ":
                out.append(random.choice(variants))
            else:
                out.append(c)
        return "".join(out)

    def apply_encoding(self, payload: str, kind: str) -> str:
        """Apply named encoding."""
        kind = kind.lower()
        if kind == "raw":
            return payload
        if kind == "url":
            return self.enc_url(payload)
        if kind == "url2":
            return self.enc_url(payload, double=True)
        if kind == "url_plus":
            return self.enc_url_plus(payload)
        if kind == "html_dec":
            return self.enc_html_dec(payload)
        if kind == "html_hex":
            return self.enc_html_hex(payload)
        if kind == "html_named":
            return self.enc_html_named(payload)
        if kind == "unicode":
            return self.enc_unicode(payload)
        if kind == "hex_js":
            return self.enc_hex_js(payload)
        if kind == "base64":
            return self.enc_base64(payload)
        if kind == "mixed_case":
            return self.enc_mixed_case(payload)
        if kind == "whitespace":
            return self.enc_whitespace(payload)
        return payload

    # -----------------------------------------------------
    # Wrap a raw string into payload dict with encodings
    # -----------------------------------------------------
    def _wrap(self, raw: str, context: str, vendor: str = "") -> dict:
        pid = self._next_id("p" if not vendor else f"waf_{vendor}")
        encoded = []
        for kind in self.encodings:
            try:
                e = self.apply_encoding(raw, kind)
                if e != raw or kind == "raw":
                    encoded.append({"kind": kind, "value": e})
            except Exception:
                pass

        return {
            "id": pid,
            "raw": raw,
            "context": context,
            "vendor": vendor,
            "encodings": encoded,
        }

    # -----------------------------------------------------
    # Select payloads by context
    # -----------------------------------------------------
    def select_for_context(
        self,
        context: str = "unknown",
        waf_bypass: bool = False,
        vendor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list:
        """
        Return list of payload dicts for the given context.
        Each dict has: id, raw, context, vendor, encodings[]
        """
        cats = CONTEXT_MAP.get(context, CONTEXT_MAP["unknown"])
        out = []

        for cat in cats:
            for raw in self.db.get(cat, []):
                out.append(self._wrap(raw, context=context))

        # WAF bypass additions
        if waf_bypass:
            if vendor and vendor.lower() in self.waf_db:
                for raw in self.waf_db[vendor.lower()]:
                    out.append(self._wrap(raw, context=context, vendor=vendor.lower()))
            else:
                # Add all vendors' generic bypasses
                for v, items in self.waf_db.items():
                    for raw in items:
                        out.append(self._wrap(raw, context=context, vendor=v))

        # Dedup by raw
        seen = set()
        unique = []
        for p in out:
            if p["raw"] not in seen:
                seen.add(p["raw"])
                unique.append(p)

        if limit:
            unique = unique[:limit]
        return unique

    # -----------------------------------------------------
    # Blind XSS payload builder
    # -----------------------------------------------------
    def blind_payloads(self, callback_base: str, token: str) -> list:
        """
        Build blind XSS payloads with {CALLBACK} replaced.
        Returns list of dicts with raw + context = 'blind'.
        """
        cb = f"{callback_base.rstrip('/')}/c/{token}"
        templates = self.db.get("blind", [])
        out = []
        for tpl in templates:
            raw = tpl.replace("{CALLBACK}", cb)
            out.append(self._wrap(raw, context="blind", vendor=""))
        return out

    # -----------------------------------------------------
    # Search
    # -----------------------------------------------------
    def search(self, needle: str) -> list:
        needle_l = needle.lower()
        out = []
        for cat, items in self.db.items():
            for raw in items:
                if needle_l in raw.lower():
                    out.append(self._wrap(raw, context=cat))
        for v, items in self.waf_db.items():
            for raw in items:
                if needle_l in raw.lower():
                    out.append(self._wrap(raw, context="waf_bypass", vendor=v))
        return out

    # -----------------------------------------------------
    # Get raw list for a category (no encoding)
    # -----------------------------------------------------
    def raw_category(self, category: str) -> list:
        if category in self.db:
            return list(self.db[category])
        if category in self.waf_db:
            return list(self.waf_db[category])
        return []

    # -----------------------------------------------------
    # Flatten payload to list of strings (all encodings)
    # -----------------------------------------------------
    def flatten(self, payload: dict, include_kinds: Optional[list] = None) -> list:
        """
        Return list of (kind, value) tuples for firing.
        If include_kinds is None, all encodings are returned.
        """
        out = []
        for enc in payload.get("encodings", []):
            if include_kinds and enc["kind"] not in include_kinds:
                continue
            out.append((enc["kind"], enc["value"]))
        return out


# =========================================================
# Self-test
# =========================================================
if __name__ == "__main__":
    from context import print_banner, print_developer_info, BANNER

    print(BANNER)
    print_developer_info()

    engine = PayloadEngine("payloads.yaml")

    print("[*] Payload DB stats:")
    stats = engine.stats()
    for k, v in stats.items():
        print(f"    {k:30s} {v}")
    print(f"    {'TOTAL':30s} {engine.total()}\n")

    print("[*] Sample: context=attr_double")
    for p in engine.select_for_context("attr_double", waf_bypass=False)[:3]:
        print(f"    {p['id']}  {p['raw']}")
        for e in p["encodings"]:
            print(f"        [{e['kind']:12s}] {e['value'][:80]}")

    print("\n[*] Sample: context=html + WAF (cloudflare)")
    for p in engine.select_for_context("html", waf_bypass=True, vendor="cloudflare")[:3]:
        print(f"    {p['id']}  vendor={p['vendor']}  {p['raw']}")

    print("\n[*] Search 'svg':")
    for p in engine.search("svg")[:5]:
        print(f"    {p['id']}  {p['raw']}")