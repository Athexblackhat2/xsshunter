"""
XSSHunter — CLI Entry Point

Commands:
    scan        Full scan pipeline (crawl → context → fire → DOM → report)
    crawl       Only crawl + list endpoints
    fire        Fire payloads against a URL (quick test)
    callback    Manage blind XSS callbacks (list / clear / watch)
    payloads    Payload DB stats / list / search
    banner      Print ASCII banner + developer info
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.syntax import Syntax

# Local imports
from brain import Brain
from context import BANNER, DEVELOPER_INFO, print_banner, print_developer_info
from payloads import PayloadEngine


# =========================================================
# App + Console
# =========================================================
app = typer.Typer(
    name="xsshunter",
    help="Advanced XSS Hunter — Go core + Python brain",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


# =========================================================
# Constants
# =========================================================
GO_CORE_DEFAULT = "http://127.0.0.1:8080"
CALLBACK_DEFAULT = "http://127.0.0.1:8888"
PAYLOAD_FILE = "payloads.yaml"


# =========================================================
# Helper — print banner once
# =========================================================
def _banner(quiet: bool = False):
    if quiet:
        return
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        f"[dim]Author : {DEVELOPER_INFO['author']}  |  "
        f"Version: {DEVELOPER_INFO['version']}  |  "
        f"License: {DEVELOPER_INFO['license']}[/dim]\n"
    )


# =========================================================
# Command: banner
# =========================================================
@app.command()
def banner():
    """Show ASCII banner and developer info."""
    _banner(quiet=False)
    table = Table(title="Developer Info", show_header=False, border_style="cyan")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for k, v in DEVELOPER_INFO.items():
        table.add_row(k, str(v))
    console.print(table)


# =========================================================
# Command: scan
# =========================================================
@app.command()
def scan(
    url: str = typer.Option(..., "-u", "--url", help="Target URL"),
    depth: int = typer.Option(2, "-d", "--depth", help="Crawl depth"),
    max_pages: int = typer.Option(100, "--max-pages", help="Max pages to crawl"),
    workers: int = typer.Option(50, "-w", "--workers", help="Concurrent workers"),
    header: list[str] = typer.Option(
        None, "-H", "--header",
        help="Custom header (repeatable). e.g. -H 'Cookie: x=y'",
    ),
    waf_bypass: bool = typer.Option(True, "--waf-bypass/--no-waf-bypass",
                                    help="Enable WAF bypass payloads"),
    dom: bool = typer.Option(True, "--dom/--no-dom",
                             help="Verify DOM execution with Playwright"),
    go_core: str = typer.Option(GO_CORE_DEFAULT, "--go-core", help="Go core URL"),
    callback: str = typer.Option(CALLBACK_DEFAULT, "--callback", help="Callback base URL"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Suppress banner"),
    output: Optional[str] = typer.Option(None, "-o", "--output",
                                         help="Save report JSON to file"),
):
    """Run a full scan against a target URL."""
    _banner(quiet)

    console.print(Panel.fit(
        f"[bold]Target[/bold]     : {url}\n"
        f"[bold]Depth[/bold]      : {depth}\n"
        f"[bold]Max Pages[/bold]  : {max_pages}\n"
        f"[bold]Workers[/bold]    : {workers}\n"
        f"[bold]WAF Bypass[/bold] : {waf_bypass}\n"
        f"[bold]DOM Verify[/bold] : {dom}\n"
        f"[bold]Go Core[/bold]    : {go_core}\n"
        f"[bold]Callback[/bold]   : {callback}",
        title="[cyan]Scan Config[/cyan]",
        border_style="cyan",
    ))

    async def _run():
        brain = Brain(
            go_core=go_core,
            callback_base=callback,
            headers=header or [],
        )

        # Health check
        h = await brain.health()
        if h.get("status") != "ok":
            console.print(f"[red]✗ Go core not reachable at {go_core}[/red]")
            console.print(f"  {h}")
            sys.exit(1)
        console.print(f"[green]✓ Go core healthy[/green]\n")

        result = await brain.scan(
            target=url,
            depth=depth,
            max_pages=max_pages,
            waf_bypass=waf_bypass,
            dom_verify=dom,
            workers=workers,
        )
        return result

    result = asyncio.run(_run())

    # Print summary
    console.print()
    table = Table(title="Scan Summary", border_style="green")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Target", result.get("target", url))
    table.add_row("Duration", f"{result.get('duration', 0)}s")
    table.add_row("Endpoints", str(result.get("endpoints", 0)))
    table.add_row("Payloads Fired", str(result.get("payloads_fired", 0)))
    table.add_row("Reflected", str(result.get("reflected", 0)))
    table.add_row("Confirmed XSS", f"[bold red]{result.get('confirmed', 0)}[/bold red]")
    console.print(table)

    # Contexts
    contexts = result.get("contexts") or {}
    if contexts:
        ctx_table = Table(title="Context Breakdown", border_style="magenta")
        ctx_table.add_column("Context")
        ctx_table.add_column("Count", justify="right")
        for k, v in contexts.items():
            ctx_table.add_row(k, str(v))
        console.print(ctx_table)

    # Findings
    findings = result.get("findings") or []
    if findings:
        console.print(f"\n[bold red]⚠ {len(findings)} Confirmed XSS Findings[/bold red]\n")
        for i, f in enumerate(findings[:20], 1):
            console.print(Panel(
                f"[bold]URL[/bold]    : {f.get('url')}\n"
                f"[bold]Param[/bold]  : {f.get('param')}\n"
                f"[bold]Payload[/bold]: {f.get('payload')}\n"
                f"[bold]Evidence[/bold]: {f.get('evidence', '')[:200]}",
                title=f"[red]#{i}[/red]",
                border_style="red",
            ))
        if len(findings) > 20:
            console.print(f"[dim]... and {len(findings) - 20} more (see report)[/dim]")
    else:
        console.print("\n[yellow]No confirmed XSS found.[/yellow]")

    # Save output
    if output:
        Path(output).write_text(json.dumps(result, indent=2))
        console.print(f"\n[green]✓ Report saved: {output}[/green]")


# =========================================================
# Command: crawl
# =========================================================
@app.command()
def crawl(
    url: str = typer.Option(..., "-u", "--url", help="Target URL"),
    depth: int = typer.Option(2, "-d", "--depth"),
    max_pages: int = typer.Option(100, "--max-pages"),
    go_core: str = typer.Option(GO_CORE_DEFAULT, "--go-core"),
    quiet: bool = typer.Option(False, "-q", "--quiet"),
):
    """Crawl a target and list discovered endpoints."""
    _banner(quiet)

    async def _run():
        import httpx
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(
                f"{go_core.rstrip('/')}/crawl",
                json={"url": url, "depth": depth, "js_crawl": True, "max_pages": max_pages},
            )
            return r.json()

    data = asyncio.run(_run())

    if not data.get("success"):
        console.print(f"[red]✗ Crawl failed:[/red] {data.get('error')}")
        sys.exit(1)

    endpoints = data.get("endpoints", [])
    console.print(f"[green]✓ Found {len(endpoints)} endpoints in {data.get('duration')}[/green]\n")

    table = Table(title="Endpoints", border_style="cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Method", style="bold")
    table.add_column("URL")
    table.add_column("Source", style="magenta")
    table.add_column("Params", style="yellow")

    for i, ep in enumerate(endpoints, 1):
        params = ", ".join((ep.get("params") or {}).keys())
        table.add_row(
            str(i),
            ep.get("method", "GET"),
            ep.get("url", ""),
            ep.get("source", ""),
            params or "-",
        )
    console.print(table)


# =========================================================
# Command: fire
# =========================================================
@app.command()
def fire(
    url: str = typer.Option(..., "-u", "--url", help="Target URL"),
    param: str = typer.Option("q", "-p", "--param", help="Param to inject into"),
    payload: Optional[str] = typer.Option(None, "--payload", help="Single payload"),
    context: str = typer.Option("html", "-c", "--context",
                                help="Context: html, attr_double, js_string_single, ..."),
    waf_bypass: bool = typer.Option(False, "--waf-bypass"),
    go_core: str = typer.Option(GO_CORE_DEFAULT, "--go-core"),
    quiet: bool = typer.Option(False, "-q", "--quiet"),
):
    """Quick-fire payloads against a single URL (no crawl)."""
    _banner(quiet)

    engine = PayloadEngine(PAYLOAD_FILE)

    if payload:
        payloads = [{"id": "custom", "raw": payload, "context": context}]
    else:
        payloads = engine.select_for_context(context=context, waf_bypass=waf_bypass)

    console.print(f"[cyan]Firing {len(payloads)} payloads → {url}?{param}=...[/cyan]\n")

    async def _run():
        import httpx
        endpoint = {
            "url": url,
            "method": "GET",
            "params": {param: "test"},
            "source": "cli",
        }
        async with httpx.AsyncClient(timeout=300) as c:
            r = await c.post(
                f"{go_core.rstrip('/')}/fire",
                json={
                    "endpoints": [endpoint],
                    "payloads": payloads,
                    "workers": 20,
                    "timeout_ms": 10000,
                },
            )
            return r.json()

    data = asyncio.run(_run())

    if not data.get("success"):
        console.print(f"[red]✗ Fire failed:[/red] {data.get('error')}")
        sys.exit(1)

    results = data.get("results", [])
    hits = [r for r in results if r.get("reflected")]
    console.print(f"[green]✓ {len(results)} requests, {len(hits)} reflected[/green]\n")

    if hits:
        for h in hits[:10]:
            console.print(Panel(
                f"[bold]Payload[/bold]: {h.get('payload')}\n"
                f"[bold]Status[/bold] : {h.get('status_code')}\n"
                f"[bold]Evidence[/bold]: {(h.get('evidence') or '')[:200]}",
                border_style="red",
            ))


# =========================================================
# Command: payloads
# =========================================================
@app.command()
def payloads(
    list_cats: bool = typer.Option(False, "--list", help="List all categories"),
    context: Optional[str] = typer.Option(None, "-c", "--context",
                                          help="Show payloads for a context"),
    search: Optional[str] = typer.Option(None, "-s", "--search",
                                         help="Search payloads by substring"),
):
    """Inspect the payload database."""
    engine = PayloadEngine(PAYLOAD_FILE)

    if list_cats:
        table = Table(title="Payload Categories", border_style="cyan")
        table.add_column("Category", style="bold")
        table.add_column("Count", justify="right")
        stats = engine.stats()
        for cat, count in stats.items():
            table.add_row(cat, str(count))
        table.add_row("[bold]TOTAL[/bold]", f"[bold]{sum(stats.values())}[/bold]")
        console.print(table)
        return

    if context:
        items = engine.select_for_context(context=context, waf_bypass=False)
        console.print(f"[cyan]{len(items)} payloads for context '{context}':[/cyan]\n")
        for p in items[:50]:
            console.print(f"  [dim]{p['id']}[/dim]  {p['raw']}")
        return

    if search:
        found = engine.search(search)
        console.print(f"[cyan]{len(found)} payloads matching '{search}':[/cyan]\n")
        for p in found[:50]:
            console.print(f"  [dim]{p['id']}[/dim]  {p['raw']}")
        return

    console.print("[yellow]Use --list, --context, or --search[/yellow]")


# =========================================================
# Command: callback
# =========================================================
@app.command()
def callback(
    action: str = typer.Argument("list", help="list | clear | watch"),
    callback_url: str = typer.Option(CALLBACK_DEFAULT, "--callback"),
    interval: int = typer.Option(3, "--interval", help="Watch poll interval (sec)"),
):
    """Manage blind XSS callbacks."""
    base = callback_url.rstrip("/")

    async def _list():
        import httpx
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{base}/hits")
            return r.json()

    async def _clear():
        import httpx
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(f"{base}/clear")
            return r.json()

    if action == "clear":
        try:
            d = asyncio.run(_clear())
            console.print(f"[green]✓ {d.get('status')}[/green]")
        except Exception as e:
            console.print(f"[red]✗ {e}[/red]")
        return

    if action == "watch":
        console.print(f"[cyan]Watching {base}/hits every {interval}s (Ctrl+C to stop)...[/cyan]\n")
        seen = 0
        try:
            while True:
                try:
                    d = asyncio.run(_list())
                    hits = d.get("hits", [])
                    if len(hits) > seen:
                        for h in hits[seen:]:
                            console.print(Panel(
                                f"[bold]Token[/bold] : {h.get('token')}\n"
                                f"[bold]IP[/bold]    : {h.get('remote_addr')}\n"
                                f"[bold]UA[/bold]    : {(h.get('user_agent') or '')[:80]}\n"
                                f"[bold]URL[/bold]   : {h.get('url', '-')}\n"
                                f"[bold]Cookie[/bold]: {(h.get('cookies') or '')[:100]}",
                                title="[red]🔥 XSS HIT[/red]",
                                border_style="red",
                            ))
                        seen = len(hits)
                except Exception:
                    pass
                import time
                time.sleep(interval)
        except KeyboardInterrupt:
            console.print("\n[dim]Stopped.[/dim]")
        return

    # default: list
    try:
        d = asyncio.run(_list())
    except Exception as e:
        console.print(f"[red]✗ Callback server unreachable: {e}[/red]")
        sys.exit(1)

    hits = d.get("hits", [])
    console.print(f"[cyan]{len(hits)} callbacks captured[/cyan]\n")
    if not hits:
        return

    table = Table(title="Blind XSS Callbacks", border_style="red")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Token", style="bold")
    table.add_column("IP")
    table.add_column("URL")
    table.add_column("Cookie", style="yellow")

    for i, h in enumerate(hits, 1):
        table.add_row(
            str(i),
            h.get("token", ""),
            h.get("remote_addr", ""),
            (h.get("url") or "-")[:60],
            (h.get("cookies") or "-")[:50],
        )
    console.print(table)


# =========================================================
# Command: version
# =========================================================
@app.command()
def version():
    """Show version."""
    console.print(f"[bold]{DEVELOPER_INFO['name']}[/bold] v{DEVELOPER_INFO['version']}")
    console.print(f"Author : {DEVELOPER_INFO['author']}")
    console.print(f"License: {DEVELOPER_INFO['license']}")


# =========================================================
# Entrypoint
# =========================================================
def main():
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()