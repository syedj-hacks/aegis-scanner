"""
modules/profiles/multi_target.py
Run one profile against several targets concurrently (`--targets`).

Distinct from the within-scan parallelism in _common.run_web_tools(): that
one overlaps the tools inside a single scan, this one overlaps whole scans.
They compose, and the real outbound request rate is roughly their product —
which is why the default here (config.MAX_CONCURRENT_TARGETS = 2) is
deliberately small, and why config.PROFILE_RATE_LIMITS exists.

Threads, not processes
----------------------
Checked rather than assumed, against the two pieces of shared state that
actually matter:

  display.console   ONE module-level Rich Console. Two Progress contexts
                    repainting it at once corrupt each other's output and
                    leave the cursor wrong after the run. Solved by
                    display.set_multi_target_mode(), which swaps the live
                    bars for plain interleaved lines for the duration.

  logger._loggers   a target-keyed dict of loggers, each owning a
                    FileHandler on that target's own scan_errors.log. Two
                    threads creating the SAME target's logger at once could
                    both attach a handler and double every line; get_logger
                    is now lock-guarded. Different targets were always
                    isolated — separate loggers, separate files — which is
                    what makes per-target scan_errors.log correct here.

Everything else is already per-call: run_tool() spawns its own subprocess,
db.py opens/commits/closes per call (SQLite's busy timeout handles the
concurrent writers), and config.output_dir() creates a per-target directory
with exist_ok=True.

Processes would have given isolation for free, but at a cost that is worse
here: every worker would inherit the same TTY stdin, so each would start
its own skip-key listener and several processes would fight over termios on
one terminal — the exact corruption the threaded design avoids. The skip
listener is switched off entirely for multi-target runs instead (see
run_targets), because "skip the current tool" has no single referent when
six tools across three targets are running.
"""

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from modules.utils.display import (
    print_info, print_success, print_error, print_warning, print_panel,
    set_multi_target_mode,
)
from modules.utils.error_handler import set_skip_listener_enabled

try:
    from modules.utils.config import MAX_CONCURRENT_TARGETS
except ImportError:
    MAX_CONCURRENT_TARGETS = 2

# Serialises the per-target start/finish announcements so two threads
# finishing at once cannot interleave halfway through a line.
_print_lock = threading.Lock()

# A /-suffixed token is only expanded as CIDR when the part before the /
# is a bare IP address. "example.com/24" is a URL path, not a network, and
# must be left exactly as it is — reducing it to a host is aegis.py's job,
# not this parser's.
_MAX_CIDR_HOSTS = 1024


def _expand_cidr(token: str) -> list:
    """
    Expand an IPv4/IPv6 CIDR token to its host addresses.

    Returns [] if `token` is not a CIDR whose left side is a bare IP — the
    caller then keeps the token verbatim, so a hostname with a slash (a
    URL) is never silently turned into a bogus network.

    A /32 (or /128) is returned as the single host it names. Larger
    networks are capped at _MAX_CIDR_HOSTS: a stray /8 in a target file
    would otherwise enqueue 16 million scans, which is a footgun, not a
    feature. The cap is reported by the caller.
    """
    if "/" not in token:
        return []
    head = token.split("/", 1)[0]
    try:
        ipaddress.ip_address(head)          # left side must be a bare IP
    except ValueError:
        return []
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return []
    # .hosts() drops network/broadcast for a real subnet; for a /32 it is
    # empty, so fall back to the single address the prefix names.
    hosts = list(network.hosts()) or [network.network_address]
    return [str(h) for h in hosts[:_MAX_CIDR_HOSTS]]


def parse_targets(raw) -> list:
    """
    Parse --targets: either a path to a file with one target per line, or a
    comma-separated list.

    A file wins when the value names an existing readable file; otherwise
    the value is treated as a comma-separated list. Blank lines and
    #-comments are ignored so a target file can be annotated. Order is
    preserved and duplicates are dropped — scanning the same host twice in
    one run would race two scans onto one output directory for no benefit.

    Returns [] for empty/unreadable input; the caller reports that.
    """
    if not raw:
        return []

    text = str(raw).strip()
    candidates = []

    try:
        with open(text, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # A file may still list several per line.
                candidates.extend(p.strip() for p in line.split(","))
    except OSError:
        candidates = [p.strip() for p in text.split(",")]

    # Expand any CIDR tokens to their host addresses before de-duplicating,
    # so "10.0.0.0/30, 10.0.0.1" collapses the overlap rather than scanning
    # 10.0.0.1 twice.
    expanded = []
    for candidate in candidates:
        hosts = _expand_cidr(candidate)
        if hosts:
            expanded.extend(hosts)
        elif candidate:
            expanded.append(candidate)

    seen = set()
    targets = []
    for candidate in expanded:
        if candidate and candidate not in seen:
            seen.add(candidate)
            targets.append(candidate)
    return targets


def run_targets(targets: list, dispatch, profile: str,
                non_interactive: bool = False, auth=None,
                max_concurrent: int = None) -> list:
    """
    Run `dispatch` against every target, up to `max_concurrent` at a time.

    Parameters
    ----------
    dispatch : callable  the profile orchestrator, called as
                         dispatch(target, non_interactive=..., auth=...)

    Returns a list of per-target result dicts, in the SAME ORDER as
    `targets` regardless of completion order:
        {target, ok, scan_id, report_paths, stats, elapsed, error}

    Never raises. A target whose scan blows up is recorded with ok=False
    and the others still run — one unreachable host in a list of twenty
    must not cost the other nineteen.
    """
    if not targets:
        return []

    workers = max(1, min(int(max_concurrent or MAX_CONCURRENT_TARGETS), len(targets)))

    # The single-target Rich progress panel cannot multiplex; the skip key
    # has no single referent across concurrent targets. Both are switched
    # off for the duration and restored afterwards, so a later single-target
    # run in the same process is unaffected.
    set_multi_target_mode(True)
    set_skip_listener_enabled(False)

    print_panel(
        f"[bold]Targets:[/bold] {len(targets)}\n"
        f"[bold]Profile:[/bold] {profile}\n"
        f"[bold]Running:[/bold] {workers} at a time\n\n"
        "[dim]Live progress bars and the skip key are disabled while several "
        "targets run at once —\nthey cannot address one scan unambiguously. "
        "Ctrl+C still stops the run.\nEach target writes its own "
        "output/<target>/ directory and scan_errors.log.[/dim]",
        title="Multi-Target Scan",
        style="cyan",
    )

    def _run_one(index_target):
        index, target = index_target
        with _print_lock:
            print_info(f"[{index}/{len(targets)}] starting {target}")

        started = time.time()
        entry = {
            "target": target, "ok": False, "scan_id": None,
            "report_paths": [], "stats": {}, "elapsed": 0.0, "error": None,
        }

        try:
            result = dispatch(target, non_interactive=non_interactive, auth=auth)
        except KeyboardInterrupt:
            # Propagated, not swallowed: a Ctrl+C during a multi-target run
            # means stop the run, and the pool needs to see it to unwind.
            raise
        except Exception as exc:
            entry["error"] = str(exc)
            entry["elapsed"] = time.time() - started
            with _print_lock:
                print_error(f"[{index}/{len(targets)}] {target} FAILED — {exc}")
            return entry

        entry["elapsed"] = time.time() - started
        scan_id, paths, stats = _normalise(result)
        entry.update(scan_id=scan_id, report_paths=paths, stats=stats,
                     ok=scan_id is not None)

        with _print_lock:
            if entry["ok"]:
                print_success(
                    f"[{index}/{len(targets)}] {target} done — scan {scan_id} "
                    f"in {entry['elapsed']:.1f}s"
                )
            else:
                print_warning(
                    f"[{index}/{len(targets)}] {target} produced no scan record "
                    f"after {entry['elapsed']:.1f}s"
                )
        return entry

    indexed = list(enumerate(targets, start=1))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # map() preserves input order in its output, so the returned
            # list matches `targets` however the scans actually finished.
            results = list(pool.map(_run_one, indexed))
    finally:
        set_multi_target_mode(False)
        set_skip_listener_enabled(True)

    return results


def _normalise(result):
    """
    Flatten a profile's return tuple to (scan_id, [paths], stats).

    Profiles return either (scan_id, report, stats) or (scan_id, txt, pdf,
    stats) — the same two shapes aegis.py._normalize_result() handles.
    """
    if not isinstance(result, tuple) or not result:
        return None, [], {}
    *head, last = result
    if isinstance(last, dict):
        scan_id, *paths = head
        stats = last
    else:
        scan_id, *paths = result
        stats = {}
    return scan_id, [p for p in paths if p], stats


def print_multi_summary(results: list) -> None:
    """One table-ish block covering every target the run touched."""
    if not results:
        return

    ok = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]

    lines = [
        f"[bold]Targets scanned:[/bold] {len(ok)}/{len(results)}",
        "",
    ]
    for entry in results:
        target = entry.get("target")
        if entry.get("ok"):
            stats = entry.get("stats") or {}
            lines.append(
                f"  [green]OK[/green]    {target:<28} scan {entry.get('scan_id')}  "
                f"{entry.get('elapsed', 0):.1f}s  "
                f"tools run/failed: {stats.get('tools_run', 0)}/{stats.get('tools_failed', 0)}"
            )
        else:
            reason = entry.get("error") or "no scan record created"
            lines.append(f"  [red]FAIL[/red]  {target:<28} {reason}")

    if failed:
        lines += [
            "",
            "[dim]A failed target does not affect the others — each scan is "
            "independent and writes its own output directory.[/dim]",
        ]

    print_panel("\n".join(lines), title="MULTI-TARGET SUMMARY", style="green")
