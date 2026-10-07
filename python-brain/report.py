"""
XSSHunter — Report Builder

Generates:
  - JSON report (machine readable)
  - HTML report (human readable, self-contained)
  - PoC HTML files (one per finding, one-click reproduce)
  - Screenshots embedded (base64)
  - Executive summary + technical details
"""

import base64
import html
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


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
    "module": "report.py",
}


# =========================================================
# Report Builder
# =========================================================
class ReportBuilder:
    """
    Builds JSON + HTML + PoC reports from scan results.

    Usage:
        rb = ReportBuilder()
        paths = rb.build(scan_result, out_dir="./reports")
        # → {"json": ..., "html": ..., "pocs": [...]}
    """

    def __init__(self, template_dir: Optional[str] = None):
        self.template_dir = template_dir

    # -----------------------------------------------------
    # Main build
    # -----------------------------------------------------
    def build(self, data: dict, out_dir: str = "./reports") -> dict:
        """
        data: dict with keys:
            target, duration, endpoints, payloads_fired,
            reflected, confirmed, contexts, findings[]
        """
        target = data.get("target", "unknown")
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_host = self._safe_host(target)
        run_dir = Path(out_dir) / f"{safe_host}_{ts}"
        run_dir.mkdir(parents=True, exist_ok=True)

        paths = {
            "dir": str(run_dir),
            "json": "",
            "html": "",
            "pocs": [],
        }

        # 1. JSON
        json_path = run_dir / "findings.json"
        json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        paths["json"] = str(json_path)

        # 2. PoCs
        pocs = self._write_pocs(data.get("findings", []), run_dir)
        paths["pocs"] = pocs

        # 3. HTML
        html_path = run_dir / "report.html"
        html_path.write_text(self._render_html(data, pocs), encoding="utf-8")
        paths["html"] = str(html_path)

        # 4. Console summary
        print(f"\n[+] Reports saved to: {run_dir}")
        print(f"    ├── findings.json")
        print(f"    ├── report.html")
        for i, p in enumerate(pocs, 1):
            print(f"    ├── poc_{i}.html")

        return paths

    # -----------------------------------------------------
    # PoC files
    # -----------------------------------------------------
    def _write_pocs(self, findings: list, run_dir: Path) -> list:
        pocs = []
        for i, f in enumerate(findings, 1):
            try:
                html_doc = self._render_poc(f, i)
                p = run_dir / f"poc_{i}.html"
                p.write_text(html_doc, encoding="utf-8")
                pocs.append(str(p))
            except Exception as e:
                print(f"[-] PoC {i} failed: {e}")
        return pocs

    # -----------------------------------------------------
    # PoC HTML — one-click reproduce
    # -----------------------------------------------------
    def _render_poc(self, f: dict, idx: int) -> str:
        url = f.get("url", "")
        param = f.get("param", "")
        payload = f.get("payload", "")
        method = (f.get("method") or "GET").upper()
        evidence = f.get("evidence", "")
        screenshot = f.get("screenshot_b64", "")
        dialogs = f.get("dialogs") or []
        dom_mutations = f.get("dom_mutations") or []

        # Build final URL/body for reproduction
        final_url = self._inject_param(url, param, payload)
        curl_cmd = self._build_curl(method, final_url, param, payload)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSSHunter PoC #{idx}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background:#0d1117; color:#e6edf3; margin:0; padding:24px; }}
  h1 {{ color:#ff6b6b; border-bottom:1px solid #30363d; padding-bottom:8px; }}
  h2 {{ color:#58a6ff; margin-top:28px; font-size:16px; }}
  .row {{ margin:10px 0; }}
  .label {{ color:#8b949e; font-size:13px; text-transform:uppercase; letter-spacing:1px; }}
  .value {{ background:#161b22; padding:10px; border-radius:6px;
            border:1px solid #30363d; word-break:break-all; font-family:monospace; }}
  .payload {{ color:#ff7b72; }}
  pre {{ background:#161b22; padding:12px; border-radius:6px;
         border:1px solid #30363d; overflow:auto; color:#c9d1d9; }}
  a {{ color:#58a6ff; }}
  .shot {{ max-width:100%; border:1px solid #30363d; border-radius:8px; margin-top:8px; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:12px;
            background:#da3633; color:#fff; font-size:12px; font-weight:bold; }}
  .badge.exec {{ background:#238636; }}
</style>
</head>
<body>
  <h1>🔥 XSS PoC #{idx} <span class="badge {'exec' if dialogs or dom_mutations else ''}">
    {'EXECUTED' if dialogs or dom_mutations else 'REFLECTED'}</span></h1>

  <div class="row">
    <div class="label">Method</div>
    <div class="value">{html.escape(method)}</div>
  </div>

  <div class="row">
    <div class="label">Target URL</div>
    <div class="value">{html.escape(url)}</div>
  </div>

  <div class="row">
    <div class="label">Injection Param</div>
    <div class="value">{html.escape(param)}</div>
  </div>

  <div class="row">
    <div class="label">Payload</div>
    <div class="value payload">{html.escape(payload)}</div>
  </div>

  <h2>▶ Reproduce (click to open)</h2>
  <div class="row">
    <a href="{html.escape(final_url)}" target="_blank" rel="noopener">
      {html.escape(final_url)}
    </a>
  </div>

  <h2>💻 curl command</h2>
  <pre>{html.escape(curl_cmd)}</pre>

  {'<h2>🎯 Dialog Evidence</h2><pre>' + html.escape('\\n'.join(dialogs)) + '</pre>' if dialogs else ''}
  {'<h2>🧬 DOM Sink Evidence</h2><pre>' + html.escape('\\n'.join(dom_mutations[:20])) + '</pre>' if dom_mutations else ''}

  {'<h2>📄 Response Snippet</h2><pre>' + html.escape(evidence[:2000]) + '</pre>' if evidence else ''}

  {'<h2>📸 Screenshot</h2><img class="shot" src="data:image/png;base64,' + screenshot + '" />' if screenshot else ''}

  <hr style="border-color:#30363d;margin-top:32px;">
  <p style="color:#8b949e;font-size:12px;">
    Generated by <b>XSSHunter v{__version__}</b> — {__author__}
  </p>
</body>
</html>
"""

    # -----------------------------------------------------
    # Main HTML report
    # -----------------------------------------------------
    def _render_html(self, data: dict, poc_paths: list) -> str:
        target = data.get("target", "")
        duration = data.get("duration", 0)
        endpoints = data.get("endpoints", 0)
        payloads_fired = data.get("payloads_fired", 0)
        reflected = data.get("reflected", 0)
        confirmed = data.get("confirmed", 0)
        contexts = data.get("contexts", {})
        findings = data.get("findings", [])

        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Context rows
        ctx_rows = "".join(
            f"<tr><td>{html.escape(k)}</td><td style='text-align:right'>{v}</td></tr>"
            for k, v in contexts.items()
        ) or "<tr><td colspan='2' style='color:#8b949e'>No data</td></tr>"

        # Findings
        findings_html = ""
        for i, f in enumerate(findings, 1):
            poc_rel = f"poc_{i}.html"
            shot = f.get("screenshot_b64", "")
            dialogs = f.get("dialogs") or []
            dom_mutations = f.get("dom_mutations") or []
            evidence = html.escape(f.get("evidence", "")[:1500])

            findings_html += f"""
            <div class="finding">
              <h3>#{i} — {html.escape(f.get('url', ''))}</h3>
              <table class="kv">
                <tr><td>Param</td><td><code>{html.escape(f.get('param', ''))}</code></td></tr>
                <tr><td>Method</td><td>{html.escape(f.get('method', 'GET'))}</td></tr>
                <tr><td>Payload</td><td><code class="payload">{html.escape(f.get('payload', ''))}</code></td></tr>
                <tr><td>Status</td><td>{f.get('status_code', '')}</td></tr>
                <tr><td>Executed</td><td>{'✅ YES' if f.get('executed') else '❌ no'}</td></tr>
                <tr><td>Duration</td><td>{html.escape(f.get('duration', ''))}</td></tr>
                <tr><td>PoC</td><td><a href="{poc_rel}" target="_blank">Open PoC #{i}</a></td></tr>
              </table>
              {f'<h4>Dialogs</h4><pre>{html.escape(chr(10).join(dialogs))}</pre>' if dialogs else ''}
              {f'<h4>DOM Sinks</h4><pre>{html.escape(chr(10).join(dom_mutations[:10]))}</pre>' if dom_mutations else ''}
              {f'<h4>Evidence</h4><pre>{evidence}</pre>' if evidence else ''}
              {f'<h4>Screenshot</h4><img class="shot" src="data:image/png;base64,{shot}" />' if shot else ''}
            </div>
            """

        if not findings_html:
            findings_html = "<p style='color:#8b949e'>No confirmed XSS findings.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSSHunter Report — {html.escape(target)}</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:#0d1117; color:#e6edf3; margin:0; padding:32px; line-height:1.5; }}
  .container {{ max-width:1200px; margin:0 auto; }}
  h1 {{ color:#ff6b6b; margin:0 0 6px 0; }}
  h2 {{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:6px; margin-top:36px; }}
  h3 {{ color:#e6edf3; margin-top:24px; }}
  h4 {{ color:#8b949e; margin:16px 0 6px 0; font-size:13px; text-transform:uppercase; letter-spacing:1px; }}
  .sub {{ color:#8b949e; font-size:14px; margin-bottom:24px; }}
  .banner {{ color:#58a6ff; font-family:monospace; font-size:11px; white-space:pre;
             line-height:1.2; margin-bottom:16px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
            gap:12px; margin:20px 0; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; }}
  .card .num {{ font-size:28px; font-weight:bold; color:#58a6ff; }}
  .card.danger .num {{ color:#ff6b6b; }}
  .card .lbl {{ font-size:12px; color:#8b949e; text-transform:uppercase; letter-spacing:1px; }}
  table {{ width:100%; border-collapse:collapse; margin:8px 0; }}
  th, td {{ padding:8px 10px; text-align:left; border-bottom:1px solid #21262d; font-size:14px; }}
  th {{ color:#8b949e; font-weight:600; }}
  .kv td:first-child {{ color:#8b949e; width:140px; }}
  code {{ background:#161b22; padding:2px 6px; border-radius:4px; font-size:13px;
          border:1px solid #30363d; word-break:break-all; }}
  code.payload {{ color:#ff7b72; }}
  pre {{ background:#161b22; padding:12px; border-radius:6px; border:1px solid #30363d;
         overflow:auto; color:#c9d1d9; font-size:12px; }}
  .finding {{ background:#0f141b; border:1px solid #30363d; border-left:4px solid #da3633;
              border-radius:8px; padding:16px 20px; margin:20px 0; }}
  .shot {{ max-width:100%; border:1px solid #30363d; border-radius:8px; margin-top:6px; }}
  a {{ color:#58a6ff; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  footer {{ margin-top:48px; padding-top:16px; border-top:1px solid #30363d;
            color:#8b949e; font-size:12px; text-align:center; }}
</style>
</head>
<body>
<div class="container">

  <div class="banner">XSSHunter — Advanced XSS Hunter  •  Go + Python Hybrid</div>
  <h1>🎯 XSS Scan Report</h1>
  <div class="sub">
    Target: <b>{html.escape(target)}</b> &nbsp;|&nbsp; Generated: {ts}
  </div>

  <div class="cards">
    <div class="card"><div class="num">{endpoints}</div><div class="lbl">Endpoints</div></div>
    <div class="card"><div class="num">{payloads_fired}</div><div class="lbl">Payloads Fired</div></div>
    <div class="card"><div class="num">{reflected}</div><div class="lbl">Reflected</div></div>
    <div class="card danger"><div class="num">{confirmed}</div><div class="lbl">Confirmed XSS</div></div>
    <div class="card"><div class="num">{duration}s</div><div class="lbl">Duration</div></div>
  </div>

  <h2>📊 Context Breakdown</h2>
  <table>
    <thead><tr><th>Context</th><th style="text-align:right">Count</th></tr></thead>
    <tbody>{ctx_rows}</tbody>
  </table>

  <h2>🔥 Findings ({len(findings)})</h2>
  {findings_html}

  <footer>
    Generated by <b>XSSHunter v{__version__}</b> — {__author__}<br>
    License: {__license__} &nbsp;|&nbsp; Module: report.py
  </footer>

</div>
</body>
</html>
"""

    # -----------------------------------------------------
    # Helpers
    # -----------------------------------------------------
    def _safe_host(self, url: str) -> str:
        try:
            host = urlparse(url).netloc or "target"
        except Exception:
            host = "target"
        host = host.replace(":", "_").replace("/", "_")
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in host)[:60] or "target"

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_q = urlencode(qs, doseq=True)
            return urlunparse(parsed._replace(query=new_q))
        except Exception:
            if "?" in url:
                return url + "&" + param + "=" + payload
            return url + "?" + param + "=" + payload

    def _build_curl(self, method: str, url: str, param: str, payload: str) -> str:
        if method.upper() == "POST":
            return f"curl -i -X POST '{url.split('?')[0]}' \\\n  --data-urlencode '{param}={payload}'"
        return f"curl -i '{url}'"


# =========================================================
# Self-test
# =========================================================
if __name__ == "__main__":
    from context import print_banner, print_developer_info

    print_banner()
    print_developer_info()

    sample = {
        "target": "https://example.com",
        "duration": 42.3,
        "endpoints": 47,
        "payloads_fired": 8648,
        "reflected": 23,
        "confirmed": 2,
        "contexts": {"html": 12, "attr_double": 8, "js_string_single": 5, "unknown": 22},
        "findings": [
            {
                "url": "https://example.com/search",
                "param": "q",
                "payload": "<svg onload=alert(1)>",
                "method": "GET",
                "status_code": 200,
                "executed": True,
                "dialogs": ["alert:1"],
                "dom_mutations": [],
                "evidence": "...<div>You searched for: <svg onload=alert(1)></div>...",
                "duration": "142ms",
                "screenshot_b64": "",
            },
            {
                "url": "https://example.com/profile",
                "param": "name",
                "payload": "\" onmouseover=\"alert(1)",
                "method": "POST",
                "status_code": 200,
                "executed": True,
                "dialogs": ["alert:1"],
                "dom_mutations": ["innerHTML:\" onmouseover=\"alert(1)"],
                "evidence": "...<input value=\"\" onmouseover=\"alert(1)\">...",
                "duration": "98ms",
                "screenshot_b64": "",
            },
        ],
    }

    rb = ReportBuilder()
    paths = rb.build(sample, out_dir="./reports")
    print("\n[*] Generated files:")
    for k, v in paths.items():
        print(f"    {k}: {v}")