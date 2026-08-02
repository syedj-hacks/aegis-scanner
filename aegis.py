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
import urllib.parse

from rich.prompt import Prompt

from modules.utils.config import (
    PROFILES, get_profile, SKIP_KEY, get_rate_limits,
    MAX_CONCURRENT_NMAP_CHUNKS, MAX_CONCURRENT_TARGETS,
)
from modules.utils.auth import load_auth
from modules.profiles._common import web_tool_concurrency
from modules.profiles.multi_target import parse_targets
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
}

# Ordered so the help table reads shortest-scan-first rather than
# alphabetically — the order someone choosing a profile actually cares about.
_PROFILE_HELP_ORDER = ("quickscan", "stealthscan", "webaudit", "deepscan", "compliance")


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

    start = time.time()
    try:
        results = run_targets(
            targets,
            PROFILE_DISPATCH[args.profile],
            profile=args.profile,
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


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
    print_success(f"Done — scan {scan_id} finished in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
