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

from rich.prompt import Prompt

from modules.utils.config import PROFILES, get_profile, SKIP_KEY
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
    "quickscan": "Fast overview — DNS, top-port nmap scan, service detection, quick whatweb + high-severity nuclei check.",
    "stealthscan": "Quiet -T2 scan of common ports — minimal footprint, no service probing.",
    "webaudit": "Web-focused audit — headers, Nikto, gobuster/dirb, whatweb, sslyze + CVE enrichment on web ports.",
    "deepscan": "Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports.",
    "compliance": "TLS cipher + HTTP header nmap scripts, sslyze and whatweb on TLS ports for a compliance-oriented baseline.",
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
    parser.add_argument(
        "target", nargs="?", default=None,
        help="target hostname or IP address to scan (omit to be prompted)",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default=None,
        help="scan profile to run (default: quickscan; omit to be prompted "
             "when target is also omitted)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print extra pre-flight and timing detail",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="never prompt; when the stored-report cap is reached, delete "
             "the oldest report automatically instead of asking. Implied "
             "when stdin/stdout is not a terminal.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Aegis Scanner {__version__}",
    )
    return parser


def _normalize_result(result):
    """
    Profile functions return (scan_id, report_path, stats) or, for deepscan,
    (scan_id, txt_path, pdf_path, stats) — every profile now appends a
    tools_run/tools_failed/tools_skipped dict as the last tuple element so
    the final summary panel can report what actually happened instead of
    always showing zero (build_summary()/summary_stats() only know severity
    counts from the database, not which tools ran). Flattens either shape to
    (scan_id, [report_path, ...], stats) with None paths dropped.
    """
    if not isinstance(result, tuple) or not result:
        return None, [], {}
    *head, maybe_stats = result
    if isinstance(maybe_stats, dict):
        scan_id, *paths = head
        stats = maybe_stats
    else:
        scan_id, *paths = result
        stats = {}
    return scan_id, [p for p in paths if p], stats


def _prompt_target() -> str:
    """
    Interactively prompt for a target, re-prompting on invalid input instead
    of exiting. Only called when no target was supplied on the command line.
    """
    while True:
        try:
            candidate = Prompt.ask("[bold]Enter target (hostname/IP)[/bold]").strip()
        except (EOFError, KeyboardInterrupt):
            print_warning("No target provided — exiting.")
            sys.exit(130)

        if is_valid_target(candidate):
            return candidate

        print_error(
            f"'{candidate}' is not a valid hostname or IP address — "
            "check for typos (e.g. double dots, invalid characters)."
        )


def _prompt_profile() -> str:
    """
    Show a numbered menu of every profile in config.PROFILES and prompt for
    a selection (by number or name), defaulting to quickscan. Only called
    when no --profile was supplied on the command line.
    """
    names = sorted(PROFILES.keys())
    default_name = "quickscan" if "quickscan" in names else names[0]

    menu_lines = [
        f"  [bold]{i}[/bold]. {name:<12} {PROFILE_DESCRIPTIONS.get(name, '')}"
        for i, name in enumerate(names, start=1)
    ]
    print_panel("\n".join(menu_lines), title="Select a Scan Profile", style="cyan")

    while True:
        try:
            choice = Prompt.ask(
                "[bold]Profile[/bold] (number or name)", default=default_name
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print_warning(f"No selection made — defaulting to '{default_name}'.")
            return default_name

        if choice in PROFILES:
            return choice
        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(names):
                return names[index]

        print_error(f"'{choice}' is not a valid profile — enter a number 1-{len(names)} or a profile name.")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    print_banner(f"AEGIS SCANNER v{__version__}")

    # Interactive mode is gated on the target being absent from argv — a
    # bare `python3 aegis.py` invocation. `python3 aegis.py <target>` (no
    # --profile) must keep defaulting to quickscan silently, exactly as
    # before, so the profile menu is never shown unless the target was also
    # missing (full backward compatibility for every other invocation shape).
    interactive = args.target is None

    if interactive:
        args.target = _prompt_target()

    if not is_valid_target(args.target):
        print_error(
            f"'{args.target}' is not a valid hostname or IP address — "
            "check for typos (e.g. double dots, invalid characters)."
        )
        return 1

    if args.profile is None:
        args.profile = _prompt_profile() if interactive else "quickscan"

    print_panel(
        f"[bold]Target:[/bold]  {args.target}\n"
        f"[bold]Profile:[/bold] {args.profile}\n\n"
        "[dim]Ctrl+C skips the tool currently running; press it twice quickly "
        "to abort the whole scan.\n"
        f"\\[{SKIP_KEY}] skips the current tool and moves to the next one "
        "(ignored for compulsory tools like nmap/DNS resolution).[/dim]",
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
        result = dispatch(args.target, non_interactive=args.non_interactive)
    except KeyboardInterrupt:
        print_warning("Scan interrupted by user.")
        return 130
    except Exception as exc:
        print_error(f"Unexpected error during '{args.profile}' scan: {exc}")
        return 1

    elapsed = time.time() - start
    scan_id, report_paths, profile_stats = _normalize_result(result)

    if scan_id is None:
        print_error("Scan did not complete — no scan record was created.")
        return 1

    summary = build_summary(scan_id)
    stats = summary_stats(summary)
    # summary_stats() only knows severity counts from the database — it
    # can't know which tools ran (that's not persisted). The profile
    # orchestrator already counted that in real time, so its stats
    # override the always-zero tools_run/tools_failed placeholders.
    stats.update(profile_stats)

    # Report paths, severity breakdown and notable finding types are all
    # covered by the REPORT GENERATED panel the profile prints (see
    # modules/reporting/completion.py), so they are not repeated here —
    # this panel is now just the run-level facts that panel does not carry.
    completion_lines = [
        f"[bold]Scan ID:[/bold]  {scan_id}",
        f"[bold]Profile:[/bold] {args.profile}",
        f"[bold]Elapsed:[/bold] {elapsed:.1f}s",
    ]
    if not report_paths:
        completion_lines.append("[bold]Report:[/bold]   none generated")
    print_panel("\n".join(completion_lines), title="SCAN COMPLETE", style="green")

    print_summary(args.target, stats)
    print_success(f"Done — scan {scan_id} finished in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
