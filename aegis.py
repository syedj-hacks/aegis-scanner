#!/usr/bin/env python3
"""
aegis.py
Aegis Scanner CLI entry point (Cyber404 Academy 2026).

Validates the target, initialises the database, dispatches to the selected
modules/profiles/ orchestrator, then prints a final summary. Every module
underneath this already degrades gracefully (run_tool()/safe_call() never
raise), so the try/except around dispatch is a last-resort safety net, not
the primary error handling path.
"""

import argparse
import ipaddress
import re
import sys
import time

from modules.utils.config import PROFILES, get_profile
from modules.utils.display import (
    print_banner, print_panel, print_info, print_success,
    print_warning, print_error, print_summary,
)
from database.db import init_db
from modules.reporting.summary import build_summary, summary_stats

from modules.profiles.quickscan import run_quickscan
from modules.profiles.stealth import run_stealthscan
from modules.profiles.webaudit import run_webaudit
from modules.profiles.deepscan import run_deepscan
from modules.profiles.compliance import run_compliance

__version__ = "1.0.0"

# One-line description per profile, shown in --help. Kept here rather than
# in config.py's PROFILES dict, which this phase does not own.
PROFILE_DESCRIPTIONS = {
    "quickscan": "Fast overview — DNS, top-port nmap scan, service detection.",
    "stealthscan": "Slow-timing, full-port sweep — minimal footprint, no service probing.",
    "webaudit": "Web-focused audit — headers, Nikto, gobuster + CVE enrichment on web ports.",
    "deepscan": "Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports.",
    "compliance": "TLS cipher + HTTP header nmap scripts for a compliance-oriented baseline.",
}

PROFILE_DISPATCH = {
    "quickscan": run_quickscan,
    "stealthscan": run_stealthscan,
    "webaudit": run_webaudit,
    "deepscan": run_deepscan,
    "compliance": run_compliance,
}

# RFC 1123 hostname: 1-63 char labels, alnum/hyphen, no leading/trailing
# hyphen, no empty labels (rules out "invalid..hostname").
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_target(target: str) -> bool:
    """True if `target` is a syntactically plausible hostname or IP address."""
    if not target or len(target) > 253:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(target))


def _build_epilog() -> str:
    lines = ["available profiles:"]
    for name in PROFILES:
        lines.append(f"  {name:<12} {PROFILE_DESCRIPTIONS.get(name, '')}")
    lines += [
        "",
        "example:",
        "  python3 aegis.py 192.168.56.101 --profile deepscan",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis.py",
        description="Aegis Scanner — modular vulnerability assessment framework",
        epilog=_build_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="target hostname or IP address to scan")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default="quickscan",
        help="scan profile to run (default: quickscan)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print extra pre-flight and timing detail",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Aegis Scanner {__version__}",
    )
    return parser


def _normalize_result(result):
    """
    Profile functions return (scan_id, report_path) or, for deepscan,
    (scan_id, txt_path, pdf_path). Flatten either shape to
    (scan_id, [report_path, ...]) with None paths dropped.
    """
    if not isinstance(result, tuple) or not result:
        return None, []
    scan_id, *paths = result
    return scan_id, [p for p in paths if p]


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    print_banner(f"AEGIS SCANNER v{__version__}")

    if not is_valid_target(args.target):
        print_error(
            f"'{args.target}' is not a valid hostname or IP address — "
            "check for typos (e.g. double dots, invalid characters)."
        )
        return 1

    print_panel(
        f"[bold]Target:[/bold]  {args.target}\n"
        f"[bold]Profile:[/bold] {args.profile}",
        title="Scan Configuration",
        style="cyan",
    )

    if args.verbose:
        profile_cfg = get_profile(args.profile)
        print_info(
            f"[verbose] profile '{args.profile}' -> "
            f"tools={profile_cfg.get('tools')} nmap_args={profile_cfg.get('nmap_args')}"
        )

    try:
        init_db()
    except Exception as exc:
        print_error(f"Failed to initialize the database: {exc}")
        return 1

    dispatch = PROFILE_DISPATCH[args.profile]
    start = time.time()

    try:
        result = dispatch(args.target)
    except KeyboardInterrupt:
        print_warning("Scan interrupted by user.")
        return 130
    except Exception as exc:
        print_error(f"Unexpected error during '{args.profile}' scan: {exc}")
        return 1

    elapsed = time.time() - start
    scan_id, report_paths = _normalize_result(result)

    if scan_id is None:
        print_error("Scan did not complete — no scan record was created.")
        return 1

    summary = build_summary(scan_id)
    stats = summary_stats(summary)

    completion_lines = [
        f"[bold]Scan ID:[/bold]  {scan_id}",
        f"[bold]Profile:[/bold] {args.profile}",
        f"[bold]Elapsed:[/bold] {elapsed:.1f}s",
    ]
    if report_paths:
        for path in report_paths:
            completion_lines.append(f"[bold]Report:[/bold]   {path}")
    else:
        completion_lines.append("[bold]Report:[/bold]   none generated")
    print_panel("\n".join(completion_lines), title="SCAN COMPLETE", style="green")

    print_summary(args.target, stats)
    print_success(f"Done — scan {scan_id} finished in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
