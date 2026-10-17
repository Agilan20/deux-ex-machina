"""
verify_connection.py
--------------------
Phase 1 - FalkorDB Connectivity Verification

Runs a series of checks:
  1. TCP connection to FalkorDB (localhost:6379)
  2. PING/PONG handshake via the FalkorDB client
  3. Graph creation and simple Cypher round-trip query
  4. Cleanup of the test graph

Usage:
  python verify_connection.py
"""

import sys
import io
import time

# Force UTF-8 output on Windows to handle Unicode characters
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from db.connection import get_client

console = Console(force_terminal=True, highlight=False)


# ─────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────

def _status(label: str, ok: bool, detail: str = ""):
    icon = "[bold green][ OK ][/]" if ok else "[bold red][FAIL][/]"
    msg = f"{icon}  {label}"
    if detail:
        msg += f"  [dim]{detail}[/]"
    console.print(msg)


def _header():
    banner = Text("FalkorDB -- Connectivity Verification", style="bold cyan")
    console.print(Panel(banner, subtitle="Phase 1", border_style="cyan", padding=(1, 4)))
    console.print()


# ─────────────────────────────────────────────────────────────
# Check 1 — TCP reachability (raw socket)
# ─────────────────────────────────────────────────────────────

def check_tcp(host: str, port: int) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
        _status("TCP connection", True, f"{host}:{port}")
        return True
    except (ConnectionRefusedError, OSError) as exc:
        _status("TCP connection", False, str(exc))
        return False


# ─────────────────────────────────────────────────────────────
# Check 2 — FalkorDB PING
# ─────────────────────────────────────────────────────────────

def check_ping(client) -> bool:
    try:
        # FalkorDB wraps redis-py; connection.ping() is accessible via the
        # underlying redis connection.
        pong = client.connection.ping()
        _status("PING / PONG handshake", bool(pong), f"response → {pong}")
        return bool(pong)
    except Exception as exc:
        _status("PING / PONG handshake", False, str(exc))
        return False


# ─────────────────────────────────────────────────────────────
# Check 3 — Graph round-trip (create → query → verify)
# ─────────────────────────────────────────────────────────────

DEMO_GRAPH = "_falkordb_verify_"

def check_graph_roundtrip(client) -> bool:
    try:
        g = client.select_graph(DEMO_GRAPH)

        # Create a simple node
        g.query("CREATE (:_Probe {ping: 'hello'})")

        # Read it back
        result = g.query("MATCH (p:_Probe) RETURN p.ping LIMIT 1")
        rows = result.result_set

        ok = len(rows) == 1 and rows[0][0] == "hello"
        _status("Graph round-trip (CREATE → MATCH)", ok, f"returned: {rows[0][0] if rows else 'nothing'}")
        return ok
    except Exception as exc:
        _status("Graph round-trip (CREATE → MATCH)", False, str(exc))
        return False


# ─────────────────────────────────────────────────────────────
# Cleanup — remove the probe graph
# ─────────────────────────────────────────────────────────────

def cleanup(client):
    try:
        g = client.select_graph(DEMO_GRAPH)
        g.delete()
        _status("Cleanup (test graph deleted)", True)
    except Exception as exc:
        _status("Cleanup", False, str(exc))


# ─────────────────────────────────────────────────────────────
# Check 4 — Server info
# ─────────────────────────────────────────────────────────────

def print_server_info(client):
    try:
        info = client.connection.info("server")
        table = Table(title="Server Info", box=box.ROUNDED, border_style="cyan", show_header=True)
        table.add_column("Key", style="bold yellow", no_wrap=True)
        table.add_column("Value", style="white")

        interesting = [
            "redis_version", "redis_mode", "os",
            "arch_bits", "tcp_port", "uptime_in_seconds",
            "executable", "config_file",
        ]
        for key in interesting:
            if key in info:
                table.add_row(key, str(info[key]))

        console.print()
        console.print(table)
    except Exception as exc:
        console.print(f"[dim]Server info unavailable: {exc}[/]")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    _header()

    import os
    from dotenv import load_dotenv
    load_dotenv()

    host     = os.getenv("FALKORDB_HOST", "localhost")
    port     = int(os.getenv("FALKORDB_PORT", 6379))
    username = os.getenv("FALKORDB_USERNAME", "")

    target = f"{host}:{port}"
    if username:
        target = f"{username}@{target}"

    console.print(f"[bold]Target:[/] [cyan]{target}[/]\n")
    console.print("[bold]Running checks...[/]\n")

    results = {}

    # --- Check 1: TCP ---
    results["tcp"] = check_tcp(host, port)
    if not results["tcp"]:
        console.print("\n[bold red]Cannot reach FalkorDB. Is the server running?[/]")
        console.print(
            "  Start it with Docker:\n"
            "  [dim]docker run --rm -p 6379:6379 falkordb/falkordb[/]\n"
        )
        sys.exit(1)

    # --- Connect ---
    t0 = time.perf_counter()
    client = get_client()
    elapsed = (time.perf_counter() - t0) * 1000

    # --- Check 2: PING ---
    results["ping"] = check_ping(client)

    # --- Check 3: Graph round-trip ---
    results["graph"] = check_graph_roundtrip(client)

    # --- Cleanup ---
    if results["graph"]:
        cleanup(client)

    # --- Server info ---
    print_server_info(client)

    # --- Summary ---
    console.print()
    passed = sum(results.values())
    total  = len(results)
    all_ok = passed == total

    summary_color = "green" if all_ok else "red"
    summary_label = "ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED"

    console.print(
        Panel(
            f"[bold {summary_color}]{summary_label}  [{passed}/{total}][/]  "
            f"[dim](connected in {elapsed:.1f} ms)[/]",
            border_style=summary_color,
            padding=(0, 4),
        )
    )

    if not all_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
