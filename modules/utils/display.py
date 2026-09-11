"""
modules/utils/display.py
Centralized Rich-based terminal UI for Aegis Scanner.
No other module should call print() directly — import from here instead.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn
)
from contextlib import contextmanager

console = Console()

# --- Verbosity (Phase 5: -v / -vv) ---------------------------------------
# Console verbosity level, set once from the CLI (-v = 1, -vv = 2), default
# 1. This gates the two ends of the output spectrum without touching the
# middle:
#   level 0  (-q/quiet, if ever wired)  errors and warnings only
#   level 1  (default)                  the normal [*]/[+]/[!]/[-] stream
#   level 2  (-vv)                      the above plus print_debug() detail
# print_info/success/warning/error keep their existing always-on behaviour
# at the default level, so nothing that exists today changes; print_debug is
# new and silent unless -vv is given. Kept as a module global (not threaded
# through every call) because the console itself is a module global and the
# whole point is one process-wide verbosity the operator sets once.
_VERBOSITY = 1


def set_verbosity(level: int) -> None:
    """Set the process-wide console verbosity (0 quiet, 1 normal, 2 debug)."""
    global _VERBOSITY
    try:
        _VERBOSITY = max(0, int(level))
    except (TypeError, ValueError):
        _VERBOSITY = 1


def get_verbosity() -> int:
    return _VERBOSITY


def print_debug(message: str) -> None:
    """
    Fine-grained diagnostic line, shown only at -vv (verbosity >= 2).

    For the detail an operator wants when something looks wrong but that
    would be noise in a normal run — a resolved config value, a per-plugin
    timing, the exact command a wrapper built. It is NOT a replacement for
    the file log (logger.py), which records everything regardless of console
    verbosity; this only decides what reaches the terminal.
    """
    if _VERBOSITY >= 2:
        console.print(f"[dim][.][/dim] {message}")


# Severity color map used everywhere findings are displayed
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFO": "bold cyan",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def print_banner(text: str = "AEGIS SCANNER"):
    """ASCII-ish banner shown once at startup."""
    console.print(Panel.fit(
        f"[bold cyan]{text}[/bold cyan]\n[dim]Modular Vulnerability Assessment Framework[/dim]",
        border_style="cyan"
    ))


def print_panel(message: str, title: str = "", style: str = "cyan"):
    """
    Generic section panel used to separate phases:
    Recon / Scanning / Web Audit / CVE Correlation / Report
    """
    console.print(Panel(message, title=title, border_style=style, expand=True))


def print_phase(phase_name: str):
    """Shortcut for the big phase-separator panels."""
    print_panel(f"[bold]{phase_name}[/bold]", title="PHASE", style="blue")


def print_info(message: str):
    console.print(f"[bold blue][*][/bold blue] {message}")


def print_success(message: str):
    console.print(f"[bold green][+][/bold green] {message}")


def print_warning(message: str):
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def print_error(message: str):
    console.print(f"[bold red][-][/bold red] {message}")


def print_severity_badge(severity: str) -> str:
    """
    Returns a Rich-markup-formatted severity badge string.
    Use this wherever a severity label is rendered (tables, panels, logs).
    """
    sev = severity.upper()
    color = SEVERITY_COLORS.get(sev, "white")
    return f"[{color}]{sev}[/{color}]"


_DESCRIPTION_MAX = 70


def _truncate(text: str, limit: int = _DESCRIPTION_MAX) -> str:
    text = str(text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def print_table(findings: list, title: str = "Vulnerability Findings"):
    """
    findings: list of dicts, each with keys:
    port, service, version, cve_id, cvss, severity, description (optional),
    remediation (optional)

    Port/Service/Version/CVE/CVSS are blank ("-") for the non-CVE finding
    types (a gobuster path, a missing header, a nikto line, ...) that make
    up most findings outside deepscan's service-enrichment pass — without a
    Description column those rows render as almost nothing but a severity
    badge. Description is included whenever the caller supplied one (every
    finding read back through reporting/summary.py has one — see
    summary._describe()) precisely so those rows are still legible here.
    """
    table = Table(title=title, show_lines=True, header_style="bold magenta")
    table.add_column("Port", justify="center")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("CVE")
    table.add_column("CVSS", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Description")

    # Sort worst-first so Critical/High surface at the top
    def sort_key(f):
        sev = f.get("severity", "INFO").upper()
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)

    for f in sorted(findings, key=sort_key):
        table.add_row(
            str(f.get("port", "-")),
            f.get("service", "-"),
            f.get("version", "-"),
            f.get("cve_id", "-"),
            str(f.get("cvss", "-")),
            print_severity_badge(f.get("severity", "INFO")),
            _truncate(f.get("description", "-")),
        )
    console.print(table)


def print_tree(target: str, subdomains: list = None, ports: list = None):
    """
    Visual tree of discovered subdomains and open ports for a target.
    subdomains: list[str]
    ports: list of dicts {port, service}
    """
    tree = Tree(f"[bold cyan]{target}[/bold cyan]")

    if subdomains:
        sub_branch = tree.add("[bold]Subdomains[/bold]")
        for s in subdomains:
            sub_branch.add(f"[green]{s}[/green]")

    if ports:
        port_branch = tree.add("[bold]Open Ports[/bold]")
        for p in ports:
            port_branch.add(f"[yellow]{p.get('port')}[/yellow] — {p.get('service', 'unknown')}")

    console.print(tree)


@contextmanager
def show_spinner(description: str):
    """
    Usage:
        with show_spinner("Running Nmap scan..."):
            run_nmap(target)
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description=description, total=None)
        yield


# --- Multi-target output mode --------------------------------------------
# Rich's Progress is a live-updating display that owns a region of the
# terminal and repaints it. There is exactly one module-level `console`
# above, so two Progress contexts running at once on different threads both
# try to own and repaint the same region: the bars overwrite each other,
# the cursor ends up in the wrong place, and the output is unreadable — and
# it stays broken after the run, because whichever context exits last
# restores a cursor state the other has already moved.
#
# --targets runs several scans concurrently in one process, so this is not
# hypothetical. Rather than attempt to multiplex a single-scan UI it was
# never designed for, multi-target runs switch the bars off and fall back
# to one plain line per event. Less pretty, and it is actually readable
# when three targets are interleaving.
#
# Single-target runs never touch this and keep the Rich progress bar
# exactly as before.
_multi_target_mode = False


def set_multi_target_mode(enabled: bool) -> None:
    """Switch the live progress bars off (see the note above)."""
    global _multi_target_mode
    _multi_target_mode = bool(enabled)


def multi_target_mode() -> bool:
    return _multi_target_mode


@contextmanager
def _plain_progress(total_steps: int, description: str):
    """
    The no-Rich fallback used in multi-target mode: same `advance` contract
    as scan_progress_bar, printed as ordinary lines that interleave safely.
    """
    state = {"done": 0}

    def advance(step_label: str = ""):
        state["done"] += 1
        if step_label:
            console.print(
                f"[dim]({state['done']}/{total_steps})[/dim] {description}: {step_label}"
            )

    yield advance


@contextmanager
def scan_progress_bar(total_steps: int, description: str = "Scanning"):
    """
    Determinate progress bar for multi-tool scan sequences.
    Usage:
        with scan_progress_bar(5, "Running full scan") as advance:
            run_tool_1(); advance("Nmap done")
            run_tool_2(); advance("Nikto done")

    Falls back to plain interleaved lines when several targets are being
    scanned at once — see set_multi_target_mode().
    """
    if _multi_target_mode:
        with _plain_progress(total_steps, description) as advance:
            yield advance
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(description, total=total_steps)

        def advance(step_label: str = ""):
            if step_label:
                progress.update(task, description=f"{description}: {step_label}")
            progress.advance(task)

        yield advance


def print_summary(target: str, stats: dict, show_tool_counts: bool = True):
    """
    End-of-scan summary panel.
    stats: {critical, high, medium, low, tools_run, tools_failed, tools_skipped}

    show_tool_counts=False drops the "Tools run/failed/skipped" line —
    used by report_txt.py's mid-run preview panel, which renders before the
    profile orchestrator's real tool-stats dict exists yet (summary_stats()
    only has DB-derived severity counts at that point). Showing a
    permanently-zero tool-count line there was more misleading than useful;
    the final SCAN SUMMARY panel that follows immediately after already
    shows the real counts.
    """
    body = (
        f"[bold]Target:[/bold] {target}\n\n"
        f"{print_severity_badge('CRITICAL')}: {stats.get('critical', 0)}   "
        f"{print_severity_badge('HIGH')}: {stats.get('high', 0)}   "
        f"{print_severity_badge('MEDIUM')}: {stats.get('medium', 0)}   "
        f"{print_severity_badge('LOW')}: {stats.get('low', 0)}"
    )
    if show_tool_counts:
        body += (
            f"\n\n[dim]Tools run: {stats.get('tools_run', 0)} | "
            f"Tools failed: {stats.get('tools_failed', 0)} | "
            f"Tools skipped by user: {stats.get('tools_skipped', 0)}[/dim]"
        )
    console.print(Panel(body, title="SCAN SUMMARY", border_style="bold cyan"))