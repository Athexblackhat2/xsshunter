"""
XSSHunter Brain — orchestrator
Go core se baat karta, context detect karta, payloads mutate karta,
DOM verify karta, aur report banata hai.
"""

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
import yaml

from context import detect_context, ContextResult
from payloads import PayloadEngine
from dom import DOMVerifier
from report import ReportBuilder


# =========================================================
# Config
# =========================================================
GO_CORE = "http://127.0.0.1:8080"
CALLBACK_BASE = "http://127.0.0.1:8888"


class Brain:
    """Main orchestrator."""

    def __init__(
        self,
        go_core: str = GO_CORE,
        callback_base: str = CALLBACK_BASE,
        headers: Optional[list[str]] = None,
        timeout: int = 15,
    ):
        self.go_core = go_core.rstrip("/")
        self.callback_base = callback_base.rstrip("/")
        self.headers = headers or []
        self.timeout = timeout

        # HTTP client to Go core
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )

        # Payload engine
        self.payloads = PayloadEngine("payloads.yaml")

        # DOM verifier (lazy)
        self.dom = DOMVerifier(headless=True)

        # Report builder
        self.report = ReportBuilder()

    # -----------------------------------------------------
    # Health check
    # -----------------------------------------------------
    async def health(self) -> dict:
        try:
            r = await self.client.get(f"{self.go_core}/health")
            return r.json()
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # -----------------------------------------------------
    # Main scan pipeline
    # -----------------------------------------------------
    async def scan(
        self,
        target: str,
        depth: int = 2,
        max_pages: int = 100,
        waf_bypass: bool = True,
        dom_verify: bool = True,
        workers: int = 50,
    ) -> dict:
        start = time.time()
        print(f"\n🎯 Target: {target}")
        print(f"   depth={depth} max_pages={max_pages} waf_bypass={waf_bypass} dom={dom_verify}\n")

        # 1. CRAWL
        print("[1/5] Crawling...")
        endpoints = await self._crawl(target, depth, max_pages)
        if not endpoints:
            print("[-] No endpoints found.")
            return self._empty_result(target, "no endpoints")
        print(f"      → {len(endpoints)} endpoints found")

        # 2. CONTEXT DETECTION (fetch each endpoint once, detect context)
        print("[2/5] Detecting context...")
        endpoint_contexts = await self._detect_contexts(endpoints)
        ctx_summary = self._summarize_contexts(endpoint_contexts)
        print(f"      → {ctx_summary}")

        # 3. PAYLOAD SELECTION + ENCODING
        print("[3/5] Building payloads...")
        all_payloads = []
        for ep in endpoints:
            ctx = endpoint_contexts.get(ep["url"], ContextResult(context="unknown"))
            payloads = self.payloads.select_for_context(
                context=ctx.context,
                waf_bypass=waf_bypass,
            )
            for p in payloads:
                all_payloads.append({
                    "id": p["id"],
                    "raw": p["raw"],
                    "context": ctx.context,
                    "vendor": p.get("vendor", ""),
                })
        # Dedup
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            key = p["raw"]
            if key not in seen:
                seen.add(key)
                unique_payloads.append(p)
        print(f"      → {len(unique_payloads)} unique payloads")

        # 4. FIRE (Go core does the heavy lifting)
        print("[4/5] Firing payloads...")
        fire_results = await self._fire(
            endpoints=endpoints,
            payloads=unique_payloads,
            workers=workers,
        )
        hits = [r for r in fire_results if r.get("reflected")]
        print(f"      → {len(fire_results)} requests, {len(hits)} reflected")

        # 5. DOM VERIFY (Playwright on reflected ones)
        confirmed = []
        if dom_verify and hits:
            print("[5/5] Verifying DOM execution...")
            confirmed = await self._verify_dom(hits)
            print(f"      → {len(confirmed)} confirmed XSS")
        else:
            confirmed = hits

        # Build report
        duration = round(time.time() - start, 2)
        report_data = {
            "target": target,
            "duration": duration,
            "endpoints": len(endpoints),
            "payloads_fired": len(fire_results),
            "reflected": len(hits),
            "confirmed": len(confirmed),
            "contexts": ctx_summary,
            "findings": confirmed,
        }

        # Save reports
        self.report.build(report_data, out_dir="./reports")

        await self._shutdown()
        return report_data

    # -----------------------------------------------------
    # 1. Crawl via Go core
    # -----------------------------------------------------
    async def _crawl(self, url: str, depth: int, max_pages: int) -> list[dict]:
        try:
            r = await self.client.post(
                f"{self.go_core}/crawl",
                json={
                    "url": url,
                    "depth": depth,
                    "js_crawl": True,
                    "max_pages": max_pages,
                },
            )
            data = r.json()
            if not data.get("success"):
                print(f"[-] Crawl error: {data.get('error')}")
                return []
            return data.get("endpoints", [])
        except Exception as e:
            print(f"[-] Crawl exception: {e}")
            return []

    # -----------------------------------------------------
    # 2. Context detection (parallel, lightweight GET)
    # -----------------------------------------------------
    async def _detect_contexts(self, endpoints: list[dict]) -> dict:
        sem = asyncio.Semaphore(20)

        async def one(ep: dict) -> tuple[str, ContextResult]:
            async with sem:
                try:
                    # Fetch with a marker to see where it lands
                    marker = "XSS_MARKER_1337"
                    params = dict(ep.get("params") or {})
                    if not params:
                        params = {"__xss__": marker}
                    else:
                        # pick first param
                        first = next(iter(params))
                        params[first] = marker

                    r = await self.client.get(
                        ep["url"],
                        params=params,
                        headers=self._headers_dict(),
                        follow_redirects=True,
                    )
                    return ep["url"], detect_context(r.text, marker)
                except Exception:
                    return ep["url"], ContextResult(context="unknown")

        results = await asyncio.gather(*[one(ep) for ep in endpoints])
        return dict(results)

    def _summarize_contexts(self, contexts: dict) -> dict:
        summary = {}
        for ctx in contexts.values():
            c = ctx.context
            summary[c] = summary.get(c, 0) + 1
        return summary

    # -----------------------------------------------------
    # 3. Fire via Go core
    # -----------------------------------------------------
    async def _fire(
        self,
        endpoints: list[dict],
        payloads: list[dict],
        workers: int,
    ) -> list[dict]:
        try:
            r = await self.client.post(
                f"{self.go_core}/fire",
                json={
                    "endpoints": endpoints,
                    "payloads": payloads,
                    "headers": self.headers,
                    "workers": workers,
                    "timeout_ms": self.timeout * 1000,
                },
                timeout=httpx.Timeout(600.0),
            )
            data = r.json()
            if not data.get("success"):
                print(f"[-] Fire error: {data.get('error')}")
                return []
            return data.get("results", [])
        except Exception as e:
            print(f"[-] Fire exception: {e}")
            return []

    # -----------------------------------------------------
    # 4. DOM verify — Playwright
    # -----------------------------------------------------
    async def _verify_dom(self, hits: list[dict]) -> list[dict]:
        verified = []
        for h in hits:
            url = h.get("url", "")
            param = h.get("param", "")
            payload = h.get("payload", "")
            method = h.get("method", "GET")

            if not url or not payload:
                continue

            try:
                executed = await self.dom.verify(
                    url=url,
                    param=param,
                    payload=payload,
                    method=method,
                )
                h["executed"] = executed
                if executed:
                    verified.append(h)
            except Exception as e:
                h["executed"] = False
                h["dom_error"] = str(e)

        return verified

    # -----------------------------------------------------
    # Headers helper
    # -----------------------------------------------------
    def _headers_dict(self) -> dict:
        out = {}
        for h in self.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    # -----------------------------------------------------
    # Cleanup
    # -----------------------------------------------------
    async def _shutdown(self):
        try:
            await self.client.aclose()
        except Exception:
            pass
        try:
            await self.dom.close()
        except Exception:
            pass

    def _empty_result(self, target: str, reason: str) -> dict:
        return {
            "target": target,
            "duration": 0,
            "endpoints": 0,
            "payloads_fired": 0,
            "reflected": 0,
            "confirmed": 0,
            "contexts": {},
            "findings": [],
            "error": reason,
        }


# =========================================================
# Standalone test
# =========================================================
async def _main():
    brain = Brain()
    h = await brain.health()
    print(f"Go core health: {h}")


if __name__ == "__main__":
    asyncio.run(_main())