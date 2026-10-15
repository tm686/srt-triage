#!/usr/bin/env python3
"""
srt-triage: Host Triage & Ranking Tool

Two-tier scanning architecture with curses TUI for host lead-scoring
and triage from nmap XML output with full NSE script preservation.
"""

import argparse
import curses
import json
import logging
import os
import sys
import threading
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.scope import ScopeEnforcer
from lib.tool_check import check_tools, check_required
from lib.scanner import run_tier1
from lib.tui import TriageTUI
from lib import db as db_mod

logger = logging.getLogger("srt_triage")


def _load_targets(target_args: list[str]) -> list[str]:
    """Parse target arguments — IPs, CIDRs, or files containing them."""
    targets = []
    for t in target_args:
        p = Path(t)
        if p.is_file():
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        else:
            targets.append(t)
    return targets


def _load_scope(scope_path: str | None, targets: list[str]) -> ScopeEnforcer:
    """Load scope from file or auto-generate from targets."""
    if scope_path and Path(scope_path).exists():
        with open(scope_path) as f:
            entries = json.load(f)
    else:
        # Auto-generate scope from targets
        entries = ScopeEnforcer.parse_targets(targets)
    return ScopeEnforcer(entries)


def main():
    parser = argparse.ArgumentParser(
        description="srt-triage: Host Triage & Ranking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 10.0.0.0/24
  %(prog)s 10.0.0.1 10.0.0.2 10.0.0.3
  %(prog)s targets.txt --scope scope.json
  %(prog)s 10.0.0.0/24 --skip-scan --db previous.db
        """
    )
    parser.add_argument("targets", nargs="+",
                        help="IP, CIDR, or file containing targets")
    parser.add_argument("--scope", default=None,
                        help="Scope file (JSON list of scope entry dicts)")
    parser.add_argument("--db", default="srt_triage.db",
                        help="SQLite database path (default: srt_triage.db)")
    parser.add_argument("--config-dir", default=None,
                        help="Config directory (default: config/ next to script)")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Load existing DB only, skip Tier 1 scanning")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    # Logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        filename="srt_triage.log",
        level=log_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # Config dir
    script_dir = Path(__file__).resolve().parent
    config_dir = args.config_dir or str(script_dir / "config")

    # Check tools
    ok, tools = check_required(config_dir)
    if not ok and not args.skip_scan:
        print("ERROR: Required tools not found:")
        for name, info in tools.items():
            status = "OK" if info["available"] else "MISSING"
            print(f"  {name}: {status}")
        sys.exit(1)

    # Load targets
    raw_targets = _load_targets(args.targets)
    if not raw_targets:
        print("ERROR: No targets specified")
        sys.exit(1)

    # Scope enforcement
    scope = _load_scope(args.scope, raw_targets)
    scope_entries = ScopeEnforcer.parse_targets(raw_targets)
    all_ips = ScopeEnforcer.expand_cidrs(scope_entries)
    targets = scope.filter_targets(all_ips)

    if not targets:
        print("ERROR: No in-scope targets after filtering")
        sys.exit(1)

    print(f"[*] {len(targets)} target(s) in scope")

    # Init database
    conn = db_mod.init_db(args.db)

    config = {
        "config_dir": config_dir,
        "tiers": {},
    }
    # Load tiers config
    tiers_path = Path(config_dir) / "tiers.json"
    if tiers_path.exists():
        with open(tiers_path) as f:
            config["tiers"] = json.load(f)

    if not args.skip_scan:
        print(f"[*] Starting Tier 1 scan on {len(targets)} target(s)...")
        print("[*] This will run rustscan then nmap -sC -sV -oX on open ports")

        # Run Tier 1 before launching TUI
        def status_print(msg):
            print(f"  [+] {msg}")

        run_tier1(targets, conn, config, status_cb=status_print)
        print("[*] Tier 1 scan complete. Launching TUI...")
    else:
        print("[*] Skipping scan, loading existing data...")

    # Launch curses TUI
    def run_tui(stdscr):
        tui = TriageTUI(stdscr, conn, config)
        tui.run()

    try:
        curses.wrapper(run_tui)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[!] TUI crashed: {e}")
    finally:
        conn.close()

    print("[*] srt-triage finished.")


if __name__ == "__main__":
    main()
