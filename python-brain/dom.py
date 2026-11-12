"""
XSSHunter — DOM Verifier (Playwright)

Reflected payloads ko actual browser me load karta hai aur confirm karta
ke JS execute hua ya nahi:
  - dialog intercept (alert/confirm/prompt)
  - DOM mutation monitoring (innerHTML, document.write)
  - console error capture
  - screenshot on hit
  - DOM dump on hit
"""

import asyncio
import base64
import os
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Dialog,
    Playwright,
    TimeoutError as PWTimeout,
)


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
    "module": "dom.py",
}


# =========================================================
# Result dataclass
# =========================================================
@dataclass
class DOMResult:
    url: str = ""
    executed: bool = False
    dialogs: list = field(default_factory=list)     # ["alert:1", "confirm:1"]
    console_errors: list = field(default_factory=list)
    dom_mutations: list = field(default_factory=list)
    screenshot_b64: str = ""
    dom_dump: str = ""
    duration_ms: int = 0
    error: str = ""


# =========================================================
# DOM Verifier
# =========================================================
class DOMVerifier:
    """
    Playwright-based XSS execution verifier.

    Usage:
        v = DOMVerifier(headless=True)
        result = await v.verify(url, param, payload, method="GET")
        if result.executed:
            print(result.dialogs)
        await v.close()
    """

    def __init__(
        self,
        headless: bool = True,
        browser_type: str = "chromium",
        user_agent: Optional[str] = None,
        timeout_ms: int = 8000,
        screenshot_on_hit: bool = True,
        save_screenshots_dir: Optional[str] = "./evidence",
    ):
        self.headless = headless
        self.browser_type = browser_type
        self.user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.timeout_ms = timeout_ms
        self.screenshot_on_hit = screenshot_on_hit
        self.save_dir = save_screenshots_dir

        self._pw: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None

        # Preload init script (hooks JS sinks + dialogs)
        self._init_script = self._build_init_script()

    # -----------------------------------------------------
    # Init script — runs BEFORE any page JS
    # -----------------------------------------------------
    def _build_init_script(self) -> str:
        """
        Hooks alert/confirm/prompt, DOM sinks, and stores evidence
        on window.__xsshunter__.
        """
        return r"""
        (function(){
          if (window.__xsshunter__) return;
          window.__xsshunter__ = {
            dialogs: [],
            mutations: [],
            sinks: [],
            errors: []
          };

          // --- Hook dialogs ---
          const _alert = window.alert;
          const _confirm = window.confirm;
          const _prompt = window.prompt;

          window.alert = function(msg){
            try { window.__xsshunter__.dialogs.push("alert:" + String(msg)); } catch(e){}
            return;
          };
          window.confirm = function(msg){
            try { window.__xsshunter__.dialogs.push("confirm:" + String(msg)); } catch(e){}
            return true;
          };
          window.prompt = function(msg, def){
            try { window.__xsshunter__.dialogs.push("prompt:" + String(msg)); } catch(e){}
            return def || "";
          };

          // --- Hook eval / Function ---
          const _eval = window.eval;
          window.eval = function(code){
            try { window.__xsshunter__.sinks.push("eval:" + String(code).slice(0,200)); } catch(e){}
            return _eval.apply(this, arguments);
          };
          const _Function = window.Function;
          window.Function = function(){
            try { window.__xsshunter__.sinks.push("Function:" + Array.from(arguments).join(",").slice(0,200)); } catch(e){}
            return _Function.apply(this, arguments);
          };

          // --- Hook innerHTML / outerHTML setters ---
          try {
            const d = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
            if (d && d.set) {
              Object.defineProperty(Element.prototype, "innerHTML", {
                get: d.get,
                set: function(v){
                  try { window.__xsshunter__.sinks.push("innerHTML:" + String(v).slice(0,200)); } catch(e){}
                  return d.set.call(this, v);
                },
                configurable: true
              });
            }
          } catch(e){}

          try {
            const d2 = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
            if (d2 && d2.set) {
              Object.defineProperty(Element.prototype, "outerHTML", {
                get: d2.get,
                set: function(v){
                  try { window.__xsshunter__.sinks.push("outerHTML:" + String(v).slice(0,200)); } catch(e){}
                  return d2.set.call(this, v);
                },
                configurable: true
              });
            }
          } catch(e){}

          // --- Hook document.write ---
          const _write = document.write;
          document.write = function(){
            try { window.__xsshunter__.sinks.push("document.write:" + Array.from(arguments).join("").slice(0,200)); } catch(e){}
            return _write.apply(this, arguments);
          };

          // --- Hook setTimeout/setInterval with string args ---
          const _st = window.setTimeout;
          window.setTimeout = function(fn, t){
            if (typeof fn === "string") {
              try { window.__xsshunter__.sinks.push("setTimeout:" + fn.slice(0,200)); } catch(e){}
            }
            return _st.apply(this, arguments);
          };
          const _si = window.setInterval;
          window.setInterval = function(fn, t){
            if (typeof fn === "string") {
              try { window.__xsshunter__.sinks.push("setInterval:" + fn.slice(0,200)); } catch(e){}
            }
            return _si.apply(this, arguments);
          };

          // --- Catch console errors ---
          window.addEventListener("error", function(e){
            try { window.__xsshunter__.errors.push(String(e.message || e)); } catch(err){}
          });
        })();
        """

    # -----------------------------------------------------
    # Lazy browser init
    # -----------------------------------------------------
    async def _ensure_browser(self):
        if self._browser is not None:
            return
        self._pw = await async_playwright().start()
        launcher = getattr(self._pw, self.browser_type)
        self._browser = await launcher.launch(
            headless=self.headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        self._context = await self._browser.new_context(
            user_agent=self.user_agent,
            ignore_https_errors=True,
        )
        await self._context.add_init_script(self._init_script)

    # -----------------------------------------------------
    # Public — verify one (url, param, payload)
    # -----------------------------------------------------
    async def verify(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        extra_params: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> DOMResult:
        """
        Inject payload into URL/body and observe execution.
        """
        start = time.time()
        result = DOMResult(url=url)

        try:
            await self._ensure_browser()

            page = await self._context.new_page()
            page.set_default_timeout(self.timeout_ms)

            # Capture page errors
            page_errors = []
            page.on("pageerror", lambda e: page_errors.append(str(e)))

            # Also catch Playwright-native dialog handler (belt + suspenders)
            pw_dialogs = []
            page.on("dialog", lambda d: asyncio.create_task(self._handle_dialog(d, pw_dialogs)))

            # Build final URL
            final_url, post_body = self._build_target(url, param, payload, method, extra_params)

            # Navigate
            try:
                if method.upper() == "POST":
                    await page.goto(self._strip_query(url), wait_until="domcontentloaded")
                    # Submit via fetch from page context
                    await page.evaluate(
                        """async ([u, body]) => {
                            try {
                                await fetch(u, {
                                    method: "POST",
                                    headers: {"Content-Type": "application/x-www-form-urlencoded"},
                                    body: body,
                                    credentials: "include"
                                });
                            } catch(e){}
                        }""",
                        [final_url, post_body],
                    )
                else:
                    await page.goto(final_url, wait_until="domcontentloaded")
            except PWTimeout:
                pass
            except Exception as e:
                result.error = f"navigate error: {e}"

            # Wait a bit for JS execution
            await page.wait_for_timeout(1200)

            # Collect evidence from window.__xsshunter__
            evidence = await self._collect_evidence(page)

            result.dialogs = evidence.get("dialogs", []) + pw_dialogs
            result.dom_mutations = evidence.get("sinks", [])
            result.console_errors = evidence.get("errors", []) + page_errors

            # DOM dump (truncated)
            try:
                html = await page.content()
                result.dom_dump = html[:8000]
            except Exception:
                pass

            # Executed?
            result.executed = (
                len(result.dialogs) > 0
                or len(result.dom_mutations) > 0
            )

            # Screenshot on hit
            if result.executed and self.screenshot_on_hit:
                try:
                    shot = await page.screenshot(full_page=False)
                    result.screenshot_b64 = base64.b64encode(shot).decode()
                    self._save_screenshot(url, result.screenshot_b64)
                except Exception:
                    pass

            await page.close()

        except Exception as e:
            result.error = str(e)

        result.duration_ms = int((time.time() - start) * 1000)
        return result

    # -----------------------------------------------------
    # Verify multiple hits in parallel
    # -----------------------------------------------------
    async def verify_batch(self, hits: list, concurrency: int = 5) -> list:
        """
        hits: list of dicts with keys: url, param, payload, method
        """
        sem = asyncio.Semaphore(concurrency)
        results = []

        async def one(h):
            async with sem:
                r = await self.verify(
                    url=h.get("url", ""),
                    param=h.get("param", ""),
                    payload=h.get("payload", ""),
                    method=h.get("method", "GET"),
                )
                results.append((h, r))

        await asyncio.gather(*[one(h) for h in hits])
        return results

    # -----------------------------------------------------
    # Helpers
    # -----------------------------------------------------
    def _build_target(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        extra_params: Optional[dict],
    ) -> tuple[str, str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if extra_params:
            for k, v in extra_params.items():
                qs[k] = [v]
        qs[param] = [payload]

        new_qs = urlencode(qs, doseq=True)

        if method.upper() == "POST":
            return url, new_qs
        return urlunparse(parsed._replace(query=new_qs)), ""

    def _strip_query(self, url: str) -> str:
        p = urlparse(url)
        return urlunparse(p._replace(query=""))

    async def _handle_dialog(self, dialog: Dialog, sink: list):
        try:
            sink.append(f"{dialog.type}:{dialog.message}")
        except Exception:
            pass
        try:
            await dialog.dismiss()
        except Exception:
            pass

    async def _collect_evidence(self, page: Page) -> dict:
        try:
            data = await page.evaluate(
                "() => window.__xsshunter__ || {dialogs:[],mutations:[],sinks:[],errors:[]}"
            )
            return data or {}
        except Exception:
            return {}

    def _save_screenshot(self, url: str, b64: str):
        if not self.save_dir:
            return
        try:
            os.makedirs(self.save_dir, exist_ok=True)
            host = urlparse(url).netloc.replace(":", "_") or "unknown"
            ts = int(time.time())
            path = os.path.join(self.save_dir, f"{host}_{ts}.png")
            with open(path, "wb") as f:
                f.write(base64.b64decode(b64))
        except Exception:
            pass

    # -----------------------------------------------------
    # Cleanup
    # -----------------------------------------------------
    async def close(self):
        try:
            if self._context:
                await self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._context = None
        self._browser = None
        self._pw = None


# =========================================================
# Standalone self-test
# =========================================================
async def _selftest():
    print(f"[*] {DEVELOPER_INFO['name']} DOM verifier — self-test")

    # Local test — uses a simple data: URL won't work; use example
    v = DOMVerifier(headless=True, screenshot_on_hit=False)

    # This URL won't actually reflect — but tests that pipeline runs
    r = await v.verify(
        url="https://example.com/",
        param="q",
        payload="<script>alert(1)</script>",
        method="GET",
    )
    print(f"[*] executed={r.executed} dialogs={r.dialogs} error={r.error} "
          f"duration={r.duration_ms}ms")

    await v.close()


if __name__ == "__main__":
    asyncio.run(_selftest())