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
import os
import re
import sys
import time
import urllib.parse

from rich.prompt import Prompt, Confirm
from rich.table import Table

from modules.utils.config import (
    PROFILES, get_profile, SKIP_KEY, get_rate_limits,
    MAX_CONCURRENT_NMAP_CHUNKS, MAX_CONCURRENT_TARGETS, MAX_THREADS,
)
from modules.utils.auth import load_auth
from modules.profiles._common import web_tool_concurrency
from modules.profiles.multi_target import parse_targets
from modules.utils.display import (
    console, print_banner, print_panel, print_info, print_success,
    print_warning, print_error, print_summary,
)
from database.db import init_db
from modules.reporting.summary import build_summary, summary_stats

from modules.profiles.quickscan import run_quickscan
from modules.profiles.stealth import run_stealthscan
from modules.profiles.webaudit import run_webaudit
from modules.profiles.deepscan import run_deepscan
from modules.profiles.compliance import run_compliance
from modules.profiles.recon import run_recon

__version__ = "1.0.0"

# One-line description per profile, shown in --help. Kept here rather than
# in config.py's PROFILES dict, which this phase does not own.
PROFILE_DESCRIPTIONS = {
    "quickscan": "Fast overview — DNS, top-port nmap scan, service detection, quick whatweb + high-severity nuclei check.",
    "stealthscan": "Quiet -T2 scan of common ports — minimal footprint, no service probing.",
    "webaudit": "Web-focused audit — headers, Nikto, gobuster/dirb, whatweb, sslyze + CVE enrichment on web ports.",
    "deepscan": "Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports.",
    "compliance": "TLS cipher + HTTP header nmap scripts, sslyze and whatweb on TLS ports for a compliance-oriented baseline.",
    "recon": "Passive attack-surface map — certificate transparency, subdomains, OSINT, cloud buckets, breach check. Never touches the target.",
}

PROFILE_DISPATCH = {
    "quickscan": run_quickscan,
    "stealthscan": run_stealthscan,
    "webaudit": run_webaudit,
    "deepscan": run_deepscan,
    "compliance": run_compliance,
    "recon": run_recon,
}

# RFC 1123 hostname: 1-63 char labels, alnum/hyphen, no leading/trailing
# hyphen, no empty labels (rules out "invalid..hostname").
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# "10.0.0.0/24", "2001:db8::/32" — a prefix length, not a URL path.
_CIDR_RE = re.compile(r"^[^/]+/\d{1,3}$")


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


def normalize_target(raw: str) -> str:
    """
    Reduce whatever the user typed to the bare host the scanner works with.

    A scan is host-centric, not URL-centric: nmap needs a hostname or IP,
    and the web wrappers rebuild their own URLs from the host plus whichever
    ports actually turned out to be open. So a pasted URL — the single most
    natural thing to paste — has to lose its scheme, credentials, port, path
    and fragment before it can be validated:

        Https://www.example.com/login?next=/  ->  www.example.com
        http://user:pw@10.0.0.5:8080/admin    ->  10.0.0.5
        https://[2001:db8::1]/                ->  2001:db8::1

    Dropping the port is intentional and not a loss: ports come from the
    profile's scan range, so an explicit :8443 is still reached if it is
    open. The caller echoes the normalised host so the change is visible
    rather than silent.

    Anything that isn't URL-shaped is returned stripped and otherwise
    untouched, leaving is_valid_target() to reject it with the usual
    message — this function never turns bad input into good.
    """
    if not raw:
        return ""

    candidate = raw.strip().strip("\"'")
    if not candidate:
        return ""

    # A bare IPv6 literal must short-circuit: it is full of colons, so the
    # authority parse below would read "2001:db8::1" as host "2001" with a
    # port, silently scanning the wrong thing. Bracketed-but-bare form is
    # unwrapped here too, since urlsplit needs a scheme-or-"//" to do it.
    for form in (candidate, candidate.strip("[]")):
        try:
            ipaddress.ip_address(form)
            return form
        except ValueError:
            pass

    # A scheme-less "host/24" is a CIDR range, not a URL with a path, and
    # the scanner has never supported ranges. Left untouched so validation
    # rejects it: quietly scanning 10.0.0.0 when the user asked for
    # 10.0.0.0/24 would be worse than an error.
    if "//" not in candidate and _CIDR_RE.match(candidate):
        return candidate

    # urlsplit only fills in .hostname when it sees an authority, so give a
    # bare "example.com:8080" the "//" that marks one. Guarded on "//"
    # rather than on a scheme because "example.com:8080" would otherwise
    # parse as scheme "example.com".
    probe = candidate if "//" in candidate else "//" + candidate
    try:
        host = urllib.parse.urlsplit(probe).hostname or ""
    except ValueError:
        # Malformed authority (e.g. an unclosed IPv6 bracket). Hand the
        # original back and let validation produce the error.
        return candidate

    # A trailing dot is legal DNS (the root anchor) but breaks the hostname
    # regex and several tools' URL builders.
    return (host or candidate).rstrip(".")


# Short, plain-language gloss per profile for the --help table. Deliberately
# separate from PROFILE_DESCRIPTIONS above: that one names the tools each
# profile runs (the right answer for the interactive menu, where the user has
# already committed to scanning), whereas --help is often someone's first
# contact with the tool and needs "what is this for / how long will it take"
# before it needs a tool inventory.
_PROFILE_HELP_BLURB = {
    "quickscan":   "fast overview (default)",
    "stealthscan": "quiet, minimal footprint",
    "webaudit":    "web-focused",
    "deepscan":    "full assessment, slowest",
    "compliance":  "TLS + security headers",
    "recon":       "passive — maps what a name exposes, never touches it",
}

# Ordered so the help table reads shortest-scan-first rather than
# alphabetically — the order someone choosing a profile actually cares about.
# recon sits last because it is the odd one out: it is the only profile that
# sends nothing to the target, and the only one that accepts a company name.
_PROFILE_HELP_ORDER = ("quickscan", "stealthscan", "webaudit", "deepscan",
                       "compliance", "recon")


def _build_epilog() -> str:
    """
    The beginner-facing half of --help.

    Scope is deliberate: this covers the main scan command and nothing else.
    The test/audit, database and config commands stay in COMMANDS.txt — they
    are maintenance tooling, and listing them here would bury the one command
    a new user actually needs behind a wall of ones they don't.
    """
    ordered = [n for n in _PROFILE_HELP_ORDER if n in PROFILES]
    ordered += [n for n in sorted(PROFILES) if n not in _PROFILE_HELP_ORDER]

    lines = ["what each --profile does:"]
    for name in ordered:
        lines.append(f"  {name:<12}  {_PROFILE_HELP_BLURB.get(name, PROFILE_DESCRIPTIONS.get(name, ''))}")

    lines += [
        "",
        "examples:",
        "  python3 aegis.py                                     guided — asks you everything",
        "  python3 aegis.py scanme.nmap.org                      quickscan (the default)",
        "  python3 aegis.py scanme.nmap.org --profile deepscan   full scan",
        "  python3 aegis.py --targets a.com,b.com                scan several hosts",
        "  python3 aegis.py --diff 41 57                         compare two finished scans",
        "  python3 aegis.py example.com --recon                  passive recon, sends nothing",
        "  python3 aegis.py --recon \"Acme Corp\"                   recon from a company name",
        "  python3 aegis.py scanme.nmap.org --live               watch it in a browser",
        "",
        "every scan writes report.txt, report.pdf and a self-contained",
        "report.html, and prints a one-line delta against the previous scan",
        "of the same target.",
        "",
        "while a scan is running (interactive terminal only):",
        f"  {SKIP_KEY}             skip the tool running right now, move to the next one",
        "  Ctrl+C        skip the tool running right now; press twice quickly to",
        "                stop the whole scan (Ctrl+C between tools stops the scan)",
        "",
        "reports land in output/<target>/ . Maintenance, database and config",
        "commands are documented in COMMANDS.txt.",
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
        metavar="target",
        help="hostname, IP or URL to scan (a URL is reduced to its host) — "
             "leave it out and you'll be asked for one",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default=None,
        metavar="PROFILE",
        help="how thorough a scan to run (default: quickscan) — see the list below",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="show which tools and settings this profile will use, before it starts",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="never stop to ask a question (picks the sensible default) — "
             "for scripts and cron. Turns itself on when output isn't a terminal.",
    )
    parser.add_argument(
        "--targets",
        default=None,
        metavar="FILE|a.com,b.com",
        help="scan several hosts: a file with one per line, or a "
             "comma-separated list. Each gets its own output/<target>/ "
             "directory and its own scan_errors.log.",
    )
    parser.add_argument(
        "--max-concurrent-targets",
        type=int, default=None, metavar="N",
        help=f"how many of --targets to scan at once "
             f"(default {MAX_CONCURRENT_TARGETS}). Combines with the "
             "per-scan tool concurrency, so raise it carefully.",
    )
    # --- Authenticated scanning (opt-in) ---------------------------------
    # These take a credential on the command line, which puts it in shell
    # history. The .env route (AEGIS_AUTH_COOKIE / AEGIS_AUTH_HEADER /
    # AEGIS_AUTH_BASIC_USER+PASS) exists for exactly that reason and is
    # named in the help text so the safer option is the discoverable one.
    parser.add_argument(
        "--auth-cookie",
        default=None, metavar="COOKIE",
        help="session cookie for an authenticated scan, e.g. "
             "'PHPSESSID=abc; security=low'. Prefer AEGIS_AUTH_COOKIE in "
             ".env — a flag lands in your shell history.",
    )
    parser.add_argument(
        "--auth-header",
        default=None, metavar="'Name: value'",
        help="extra request header for an authenticated scan, e.g. "
             "'Authorization: Bearer <token>'. Prefer AEGIS_AUTH_HEADER "
             "in .env.",
    )
    parser.add_argument(
        "--recon",
        action="store_true",
        help="passive recon mapper: map what a domain OR a company name "
             "exposes (subdomains, cloud buckets, breached addresses) "
             "without sending anything to the target. Same as "
             "--profile recon, but also accepts a company name.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="open a live dashboard in the browser that fills in as the scan "
             "runs. Served from 127.0.0.1 on a random port. You are asked "
             "about this anyway when running interactively.",
    )
    parser.add_argument(
        "--no-live",
        action="store_true",
        help="never ask about (or open) the live dashboard. For scripts.",
    )
    parser.add_argument(
        "--diff",
        nargs=2, default=None, metavar=("SCAN_A", "SCAN_B"),
        help="compare two finished scans and print what is new, fixed and "
             "unchanged, then exit. Runs no scan.",
    )
    parser.add_argument(
        "--diff-verbose",
        action="store_true",
        help="with --diff, also list the unchanged findings (they are "
             "counted but not listed by default — on a real target they "
             "are most of them).",
    )
    # --- Plugin engine (opt-in; Phase 2) ---------------------------------
    # The legacy profile orchestrators remain the default. --engine switches
    # to the concurrent, plugin-driven engine with a declarative YAML scan
    # profile. Everything downstream (database, reports, diff) is shared, so
    # an --engine scan is reported identically to a legacy one.
    parser.add_argument(
        "--engine",
        action="store_true",
        help="run the concurrent plugin engine instead of the built-in "
             "profile orchestrators. Uses a YAML scan profile (--scan-profile) "
             "and honours --threads and the profile's safety throttle.",
    )
    parser.add_argument(
        "--scan-profile",
        default="full", metavar="NAME|FILE",
        help="engine YAML profile (default: full). A shipped name "
             "(quick/full/stealth/recon) or a path to a .yaml file. "
             "Only consulted with --engine.",
    )
    parser.add_argument(
        "--threads",
        type=int, default=None, metavar="N",
        help="max plugins to run at once within one engine scan "
             f"(default {MAX_THREADS}, capped at {MAX_THREADS}). Composes "
             "with the profile's per-target rate limit. Only with --engine.",
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="list every discovered scanner plugin (name, context, "
             "availability) and exit. Does not scan.",
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
            candidate = Prompt.ask(
                "[bold]Enter target (hostname, IP or URL)[/bold]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print_warning("No target provided — exiting.")
            sys.exit(130)

        host = normalize_target(candidate)
        if is_valid_target(host):
            if host != candidate:
                print_info(f"Scanning host '{host}' (from '{candidate}').")
            return host

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


_MODE_VULN, _MODE_RECON, _MODE_DIFF = "1", "2", "3"


def _prompt_mode() -> str:
    """
    The top-level "what do you want to do" menu, shown only for a bare
    `python3 aegis.py` with no arguments at all.

    Every other invocation shape — a target, a --profile, --targets,
    --recon, --diff — skips this entirely and behaves exactly as it did
    before the menu existed. That is the whole compatibility contract: the
    menu is what you get when you have told the tool nothing, not a new step
    inserted in front of people who have.
    """
    print_panel(
        "  [bold]1[/bold]. Vulnerability scan\n"
        "     [dim]pick a profile and scan a host — quickscan, deepscan, …[/dim]\n\n"
        "  [bold]2[/bold]. Recon mapper\n"
        "     [dim]map what a domain or company name exposes. Passive: it\n"
        "     sends nothing to the target.[/dim]\n\n"
        "  [bold]3[/bold]. Scan diff\n"
        "     [dim]compare two finished scans — what is new, fixed or worse[/dim]",
        title="Select a Mode",
        style="cyan",
    )

    try:
        return Prompt.ask(
            "[bold]Mode[/bold]", choices=[_MODE_VULN, _MODE_RECON, _MODE_DIFF],
            default=_MODE_VULN,
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print_warning("No selection made — exiting.")
        sys.exit(130)


def _prompt_recon_target() -> tuple:
    """
    Prompt for the recon mapper's target, which — unlike every other mode —
    may be free text.

    Returns (target, is_company). No hostname validation is applied and none
    should be: "Acme Corp" is a legitimate, supported input here, and
    rejecting it would remove the one thing that makes this mode different.
    is_company is decided by whether the input parses as a hostname, so the
    profile knows which steps are even applicable.
    """
    while True:
        try:
            raw = Prompt.ask(
                "[bold]Enter a domain (example.com) or a company name "
                "(Acme Corp)[/bold]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print_warning("No target provided — exiting.")
            sys.exit(130)

        if not raw:
            print_error("Enter a domain or a company name.")
            continue

        host = normalize_target(raw)
        if is_valid_target(host):
            if host != raw:
                print_info(f"Mapping domain '{host}' (from '{raw}').")
            return host, False

        print_info(
            f"'{raw}' is not a hostname — treating it as a company name. "
            "Cloud storage and OSINT will run; DNS, certificate transparency "
            "and subdomain enumeration need a domain and will be skipped."
        )
        return raw, True


def _prompt_scan_pair() -> tuple:
    """
    Interactive scan picker for diff mode: show the most recent scans and
    ask for two of them by number. Returns (scan_a, scan_b) or (None, None).

    Presented newest-first (get_scan_history's own order) but the pair is
    normalised to (older, newer) before being returned, because a diff reads
    as a change over time and "3 new since scan #216" would be backwards if
    the user happened to pick them the other way round.
    """
    from database.db import get_scan_history

    try:
        history = (get_scan_history() or [])[:10]
    except Exception as exc:
        print_error(f"Could not read scan history: {exc}")
        return None, None

    if len(history) < 2:
        print_error(
            f"Only {len(history)} scan(s) on record — a diff needs two. "
            "Run a scan first."
        )
        return None, None

    table = Table(title="Recent scans", header_style="bold magenta")
    table.add_column("#", justify="right")
    table.add_column("Scan ID", justify="right")
    table.add_column("Target")
    table.add_column("Profile")
    table.add_column("When")
    for index, scan in enumerate(history, start=1):
        table.add_row(
            str(index), str(scan.get("id")), str(scan.get("target") or "?"),
            str(scan.get("profile") or "?"),
            str(scan.get("timestamp") or "?")[:19].replace("T", " "),
        )
    console.print(table)

    def _pick(label: str):
        while True:
            try:
                choice = Prompt.ask(f"[bold]{label}[/bold] (row number or scan id)").strip()
            except (EOFError, KeyboardInterrupt):
                return None
            if not choice.isdigit():
                print_error("Enter a number.")
                continue
            value = int(choice)
            if 1 <= value <= len(history):
                return history[value - 1].get("id")
            # Not a row number — accept a raw scan id, including one older
            # than the ten listed, so the table is a convenience and not a
            # restriction.
            if any(s.get("id") == value for s in history) or value > 0:
                return value
            print_error(f"Enter a row number 1-{len(history)} or a scan id.")

    scan_a = _pick("Baseline scan (the earlier one)")
    if scan_a is None:
        return None, None
    scan_b = _pick("Current scan (the later one)")
    if scan_b is None:
        return None, None

    if scan_a == scan_b:
        print_error("Both selections are the same scan — nothing to compare.")
        return None, None

    if scan_a > scan_b:
        print_info(
            f"Comparing #{scan_b} → #{scan_a} (the lower id is the baseline)."
        )
        scan_a, scan_b = scan_b, scan_a
    return scan_a, scan_b


def _run_interactive_diff() -> int:
    """Mode 3: pick two scans, print the diff, offer to save it."""
    from modules.reporting.diff import diff_scans, print_diff, generate_diff_report

    scan_a, scan_b = _prompt_scan_pair()
    if scan_a is None:
        return 1

    result = diff_scans(scan_a, scan_b)
    print_diff(result)

    try:
        if Confirm.ask("\n[cyan]Save this diff as a report?[/cyan]", default=False):
            generate_diff_report(result)
    except (EOFError, KeyboardInterrupt):
        pass
    return 0


def _run_diff(args) -> int:
    """
    --diff: compare two finished scans and print the delta. Runs no scan.

    Kept in aegis.py rather than a separate script because it is the same
    question the scanner exists to answer ("what is the state of this
    target"), asked across two runs — and one entry point is one thing for
    a user to remember.
    """
    from modules.reporting.diff import diff_scans, render_diff

    try:
        scan_a, scan_b = (int(v) for v in args.diff)
    except (TypeError, ValueError):
        print_error(
            f"--diff needs two numeric scan ids, got {args.diff!r}. "
            "List them with: python3 -c \"from database.db import "
            "get_scan_history; print(get_scan_history())\""
        )
        return 1

    result = diff_scans(scan_a, scan_b)
    print(render_diff(result, verbose=args.diff_verbose))
    return 0


def _maybe_start_live_dashboard(args) -> bool:
    """
    Ask about (or, with --live, just start) the live dashboard.

    Returns True if a dashboard is running. The profiles do not need to be
    told: update_live_data() is keyed on the target and no-ops for a target
    with no dashboard, so the scan code path is identical either way and
    there is no use_live flag to thread through six orchestrators.

    Never blocks a scan. A dashboard that fails to start is a warning and
    the scan proceeds — it is a view onto the scan, not part of it.
    """
    if args.no_live:
        return False

    use_live = args.live
    if not use_live and not args.non_interactive:
        try:
            use_live = Confirm.ask(
                "[cyan]Open a live dashboard in your browser?[/cyan] "
                "[dim](fills in as the scan runs)[/dim]",
                default=False,
            )
        except (EOFError, KeyboardInterrupt):
            use_live = False

    if not use_live:
        return False

    from modules.reporting.dashboard_live import init_live_dashboard

    url = init_live_dashboard(args.target)
    if not url:
        print_warning("Live dashboard could not be started — the scan continues without it.")
        return False

    print_success(f"Live dashboard: {url}")
    _open_in_browser(url)
    return True


def _open_in_browser(location: str) -> None:
    """
    Best-effort "show this to the user". Never raises and never blocks: a
    headless box has no browser, and failing to open one must not affect a
    scan that has already run or is about to.
    """
    import subprocess

    try:
        subprocess.Popen(
            ["xdg-open", location],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        print_info(f"Open this in a browser: {location}")


def _print_attack_surface_delta(target: str, scan_id) -> None:
    """
    The one-line "what changed since last time" note printed after a scan.

    Compares against the previous scan OF THE SAME TARGET, and only ever
    prints the summary line — never the full table, which is what --diff is
    for. Silent when this is the target's first scan, because "nothing to
    compare" is not news.

    Never raises: this runs after a completed, fully persisted scan, and a
    problem building a courtesy line must not change the exit code of a
    scan that worked.
    """
    try:
        from database.db import get_scan_history
        from modules.reporting.diff import diff_scans

        history = get_scan_history(target) or []
        previous = next(
            (s for s in history if s.get("id") and s["id"] != scan_id), None
        )
        if not previous:
            return

        delta = diff_scans(previous["id"], scan_id)
        if not delta.get("comparable", True):
            return

        console.print(
            f"\n[bold]Attack surface delta:[/bold] {delta.get('delta_summary')}"
        )
        console.print(
            f"[dim]Full comparison: python3 aegis.py --diff "
            f"{previous['id']} {scan_id}[/dim]"
        )
    except Exception:
        return


def _hold_dashboard_open(live: bool, args, report_paths) -> None:
    """
    Keep the process (and so the dashboard server) alive after the scan.

    The server runs on a daemon thread, which means it stops the moment
    this process exits — so without this, the dashboard someone has been
    watching goes to a connection error at the exact moment it would show
    the completion banner and the link to the full report. The live view
    would be live right up until the only part anyone wants to read.

    Interactive runs therefore wait for a keypress. Scripted ones cannot,
    so they get told plainly that the live view has ended and where the
    static report is — which is the honest version of the same information.
    """
    if not live:
        return

    html_path = next((p for p in report_paths if str(p).endswith(".html")), None)

    if args.non_interactive:
        print_info(
            "The live dashboard stops with this process. The finished report "
            + (f"is at {html_path}" if html_path else "is in this target's output directory")
        )
        return

    try:
        console.print(
            "\n[cyan]The live dashboard is still open.[/cyan] "
            "[dim]It stops when this command exits.[/dim]"
        )
        Prompt.ask(
            "[dim]Press Enter to close it"
            + (f" (report also saved to {html_path})" if html_path else "")
            + "[/dim]",
            default="",
            show_default=False,
        )
    except (EOFError, KeyboardInterrupt):
        return


def _offer_html_report(report_paths, args) -> None:
    """Offer to open the static HTML report when no live view was used."""
    html_path = next(
        (p for p in report_paths if str(p).endswith(".html")), None
    )
    if not html_path or args.non_interactive:
        return
    try:
        if Confirm.ask("[cyan]Open the HTML report in your browser?[/cyan]", default=False):
            _open_in_browser(os.path.abspath(html_path))
    except (EOFError, KeyboardInterrupt):
        return


def _run_recon_mode(args, is_company: bool) -> int:
    """
    Mode 2 / --recon: run the passive recon mapper and report.

    Kept separate from main()'s scan path because the two genuinely differ
    at the start — no hostname validation, no auth, no rate-limit or
    concurrency reporting, and a target that may not be a host at all — but
    it shares the whole tail (delta line, summary panel, HTML offer) through
    the same helpers.
    """
    print_panel(
        f"[bold]Target:[/bold]  {args.target}\n"
        f"[bold]Mode:[/bold]    recon mapper "
        f"({'company name' if is_company else 'domain'})\n\n"
        "[dim]Passive only — public certificate logs, DNS aggregators, cloud\n"
        "namespaces and a breach database. Nothing is sent to the target.[/dim]",
        title="Recon Configuration",
        style="cyan",
    )

    try:
        init_db()
    except Exception as exc:
        print_error(f"Failed to initialize the database: {exc}")
        return 1

    live = _maybe_start_live_dashboard(args)

    start = time.time()
    try:
        result = run_recon(
            args.target,
            non_interactive=args.non_interactive,
            is_company=is_company,
        )
    except KeyboardInterrupt:
        print_warning("Recon interrupted by user.")
        return 130
    except Exception as exc:
        print_error(f"Unexpected error during recon: {exc}")
        return 1

    elapsed = time.time() - start
    scan_id, report_paths, profile_stats = _normalize_result(result)
    if scan_id is None:
        print_error("Recon did not complete — no scan record was created.")
        return 1

    summary = build_summary(scan_id, quiet=True)
    stats = summary_stats(summary)
    stats.update(profile_stats)

    print_panel(
        f"[bold]Scan ID:[/bold]  {scan_id}\n"
        f"[bold]Mode:[/bold]     recon\n"
        f"[bold]Elapsed:[/bold]  {elapsed:.1f}s",
        title="RECON COMPLETE", style="green",
    )
    print_summary(args.target, stats)
    _print_attack_surface_delta(args.target, scan_id)
    if not live:
        _offer_html_report(report_paths, args)
    else:
        _hold_dashboard_open(live, args, report_paths)
    print_success(f"Done — recon scan {scan_id} finished in {elapsed:.1f}s")
    return 0


def _run_multi_target(args, targets) -> int:
    """--targets: run the chosen profile against several hosts."""
    from modules.profiles.multi_target import run_targets, print_multi_summary

    if args.profile is None:
        args.profile = "quickscan"

    # Normalise first, then validate, so a target list pasted out of a
    # browser or a spreadsheet full of URLs is usable as-is. Normalising can
    # collapse two entries onto one host (http:// and https:// of the same
    # site), so de-duplicate again afterwards — parse_targets already did it
    # once, on the raw strings.
    normalized, seen = [], set()
    for target in targets:
        host = normalize_target(target)
        if not is_valid_target(host):
            print_error(
                f"'{target}' in --targets is not a valid hostname or IP address "
                "— fix or remove it and re-run. Nothing has been scanned."
            )
            return 1
        if host not in seen:
            seen.add(host)
            normalized.append(host)

    if normalized != targets:
        print_info(f"Scanning {len(normalized)} host(s): {', '.join(normalized)}")
    targets = normalized

    try:
        init_db()
    except Exception as exc:
        print_error(f"Failed to initialize the database: {exc}")
        return 1

    auth = load_auth(cli_cookie=args.auth_cookie, cli_header=args.auth_header)

    # --engine composes with --targets: each host is scanned by the plugin
    # engine (with its own per-target rate limiter, so one throttled host
    # never starves another), still bounded by --max-concurrent-targets.
    if args.engine:
        dispatch = _build_engine_dispatch(args)
        if dispatch is None:
            return 1
        dispatch_label = args.scan_profile
    else:
        dispatch = PROFILE_DISPATCH[args.profile]
        dispatch_label = args.profile

    start = time.time()
    try:
        results = run_targets(
            targets,
            dispatch,
            profile=dispatch_label,
            non_interactive=args.non_interactive,
            auth=auth,
            max_concurrent=args.max_concurrent_targets,
        )
    except KeyboardInterrupt:
        print_warning("Multi-target scan interrupted by user.")
        return 130

    print_multi_summary(results)
    elapsed = time.time() - start
    succeeded = sum(1 for r in results if r.get("ok"))
    print_success(
        f"Done — {succeeded}/{len(results)} target(s) scanned in {elapsed:.1f}s"
    )
    # Non-zero when nothing at all succeeded, so a cron job notices. A
    # partial success is still a success: the reports that were produced
    # are real, and failing the whole run would hide them.
    return 0 if succeeded else 1


def _run_list_plugins() -> int:
    """Print the discovered plugin registry and exit. Used by --list-plugins."""
    from plugins import describe, load_errors

    rows = describe()
    table = Table(title="Aegis Scanner — discovered plugins", show_lines=False)
    table.add_column("Plugin", style="cyan", no_wrap=True)
    table.add_column("Context")
    table.add_column("Baseline")
    table.add_column("Available")
    table.add_column("Description")
    for name, types, baseline, desc, avail in rows:
        avail_render = "[green]yes[/green]" if avail == "yes" else f"[yellow]{avail}[/yellow]"
        table.add_row(name, types, baseline, avail_render, desc)
    console.print(table)
    console.print(f"[dim]{len(rows)} plugin(s) discovered from plugins/.[/dim]")

    if load_errors:
        console.print("[red]Plugins that failed to load:[/red]")
        for modname, err in load_errors:
            console.print(f"  [red]{modname}[/red]: {err}")
    return 0


def _build_engine_dispatch(args):
    """
    Build a dispatch callable for --engine from the requested YAML profile.

    Returns a callable with the same (target, non_interactive, auth)
    signature the profile orchestrators expose — so main()'s shared
    completion path handles its result unchanged — or None if the profile
    could not be loaded (message already printed).
    """
    from modules.engine import load_yaml_profile, run_engine_scan
    from modules.engine.profiles_yaml import ProfileError

    try:
        profile = load_yaml_profile(args.scan_profile)
    except ProfileError as exc:
        print_error(f"engine profile: {exc}")
        return None

    if args.verbose:
        safety = profile.get("safety") or {}
        print_info(
            f"[verbose] engine profile '{profile['name']}' -> "
            f"plugins={profile['plugins'] or 'all'} "
            f"threads={args.threads or MAX_THREADS} "
            f"safety={{rps:{safety.get('max_requests_per_second', 'none')}, "
            f"concurrent:{safety.get('max_concurrent_plugins', 'none')}}}"
        )

    def dispatch(target, non_interactive=False, auth=None):
        return run_engine_scan(target, profile, threads=args.threads,
                               non_interactive=non_interactive, auth=auth)

    return dispatch


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # --list-plugins is a query, not a scan: print the plugin registry and
    # exit before any banner or target handling.
    if args.list_plugins:
        return _run_list_plugins()

    # --diff produces no scan and no banner: it is a reporting query, and
    # its output is meant to be pipeable into a mail body or a log.
    if args.diff:
        return _run_diff(args)

    print_banner(f"AEGIS SCANNER v{__version__}")

    if args.targets:
        targets = parse_targets(args.targets)
        if not targets:
            print_error(
                f"--targets {args.targets!r} yielded no targets — expected a "
                "readable file with one host per line, or a comma-separated list."
            )
            return 1
        if args.target:
            print_warning(
                f"both a positional target ({args.target}) and --targets were "
                f"given; scanning the {len(targets)} --targets host(s) and "
                "ignoring the positional one."
            )
        return _run_multi_target(args, targets)

    # Interactive mode is gated on the target being absent from argv — a
    # bare `python3 aegis.py` invocation. `python3 aegis.py <target>` (no
    # --profile) must keep defaulting to quickscan silently, exactly as
    # before, so the profile menu is never shown unless the target was also
    # missing (full backward compatibility for every other invocation shape).
    interactive = args.target is None

    # The top-level mode menu appears for a bare `python3 aegis.py` and
    # nothing else. Any argument that already states an intent — a target, a
    # --profile, --recon — answers the menu's question, so asking it would
    # be asking something the user has already told us.
    if interactive and args.profile is None and not args.recon:
        mode = _prompt_mode()
        if mode == _MODE_DIFF:
            return _run_interactive_diff()
        if mode == _MODE_RECON:
            args.recon = True

    # --recon accepts free text, so it takes its target from its own prompt
    # and skips the hostname validation below entirely.
    if args.recon:
        args.profile = "recon"
        if args.target is None:
            args.target, recon_is_company = _prompt_recon_target()
        else:
            host = normalize_target(args.target)
            if is_valid_target(host):
                if host != args.target:
                    print_info(f"Mapping domain '{host}' (from '{args.target}').")
                args.target, recon_is_company = host, False
            else:
                # A company name on the command line: quoted free text that
                # is not a hostname. Accepted rather than rejected — it is
                # the documented second input shape for this mode.
                print_info(
                    f"'{args.target}' is not a hostname — treating it as a "
                    "company name (cloud storage and OSINT only)."
                )
                recon_is_company = True
        return _run_recon_mode(args, recon_is_company)

    if interactive:
        args.target = _prompt_target()
    else:
        # A URL pasted on the command line is normalised to its host, and
        # the substitution is announced so the report header ("Target: ...")
        # is never a surprise. The interactive path does its own echo.
        host = normalize_target(args.target)
        if host and host != args.target:
            print_info(f"Scanning host '{host}' (from '{args.target}').")
        args.target = host

    if not is_valid_target(args.target):
        print_error(
            f"'{args.target}' is not a valid hostname or IP address — "
            "check for typos (e.g. double dots, invalid characters)."
        )
        return 1

    if args.profile is None:
        args.profile = _prompt_profile() if interactive else "quickscan"

    # Resolved once, here, and handed to the profile — so a run has exactly
    # one credential set, and the profile does not re-resolve it from the
    # environment behind the CLI flag's back. With nothing configured this
    # is a disabled AuthConfig whose *_args() all return [], so every tool
    # command is built byte-for-byte as it was before auth existed.
    auth = load_auth(cli_cookie=args.auth_cookie, cli_header=args.auth_header)

    # Ctrl+C's description here is deliberately hedged, and the hedge is the
    # whole point. run_tool()/safe_call() only intercept an interrupt while
    # they are actually running something — verified live: SIGINT during a
    # subprocess returns a normal skipped result and the scan continues, but
    # SIGINT in the gaps between tools (CVE enrichment, database writes,
    # report generation) has nothing to catch it and propagates to main(),
    # ending the scan. The panel used to promise "Ctrl+C skips the tool
    # currently running" flatly, so a user who hit the gap saw the scanner
    # exit on a keypress they had just been told was safe.
    #
    # The skip key has no such gap-dependence: it is only ever read while a
    # tool is running, so it means exactly one thing at all times. It is
    # therefore listed first, as the control to actually reach for.
    print_panel(
        f"[bold]Target:[/bold]  {args.target}\n"
        f"[bold]Profile:[/bold] {args.profile}\n\n"
        f"[dim]\\[{SKIP_KEY}] skips the tool running right now and moves to the "
        "next one — this is the reliable way to skip\n"
        "    (ignored for compulsory tools like nmap/DNS resolution).\n"
        "Ctrl+C also skips the running tool, but only while one is actually "
        "running: pressed\n"
        "    between tools it stops the whole scan. Twice quickly always stops "
        "the scan.[/dim]",
        title="Scan Configuration",
        style="cyan",
    )

    if args.verbose:
        profile_cfg = get_profile(args.profile)
        print_info(
            f"[verbose] profile '{args.profile}' -> "
            f"tools={profile_cfg.get('tools')} nmap_args={profile_cfg.get('nmap_args')}"
        )
        # The concurrency and rate-limit settings actually IN EFFECT for
        # this run, not the config file's values in the abstract: a profile
        # that opted out of the tool pool reports 1 here, and a '-v' line
        # that reported the config constant instead would be describing a
        # run that did not happen.
        print_info(
            f"[verbose] concurrency -> web tools: "
            f"{web_tool_concurrency(args.profile)}-way"
            + (f", nmap full-range chunks: {MAX_CONCURRENT_NMAP_CHUNKS} at a time"
               if "-p-" in (profile_cfg.get("nmap_args") or []) else "")
        )
        limits = get_rate_limits(args.profile)
        print_info(
            "[verbose] rate limits -> "
            f"gobuster -t {limits['gobuster_threads']}, "
            f"dirb -z {limits['dirb_delay_ms'] or 'off'}, "
            f"nikto -Pause {limits['nikto_pause_s'] or 'off'}, "
            f"nuclei -rate-limit {limits['nuclei_rate_limit'] or 'tool default'}"
        )
        print_info(f"[verbose] authentication -> {auth.describe()}")

    try:
        init_db()
    except Exception as exc:
        print_error(f"Failed to initialize the database: {exc}")
        return 1

    live = _maybe_start_live_dashboard(args)

    # --engine swaps the legacy orchestrator for the concurrent plugin
    # engine, driven by a YAML scan profile. Everything after dispatch is
    # shared: run_engine_scan returns the same (scan_id, txt, pdf, html,
    # stats) tuple the profile functions do, so the completion panel,
    # summary and delta below are unchanged.
    if args.engine:
        dispatch = _build_engine_dispatch(args)
        if dispatch is None:
            return 1
    else:
        dispatch = PROFILE_DISPATCH[args.profile]
    start = time.time()

    try:
        result = dispatch(args.target, non_interactive=args.non_interactive, auth=auth)
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

    # What moved since the last scan of this same target — one line, printed
    # after every scan rather than only when someone remembers to ask for a
    # --diff. The full comparison stays behind the flag.
    _print_attack_surface_delta(args.target, scan_id)

    # Only offered when there was no live view: someone who has had the
    # dashboard open throughout the scan already has a browser tab on this
    # target, and it links to the report itself once the scan completes.
    if not live:
        _offer_html_report(report_paths, args)
    else:
        _hold_dashboard_open(live, args, report_paths)

    print_success(f"Done — scan {scan_id} finished in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
