"""
modules/reporting/report_txt.py
Plain-text report writer for Aegis Scanner (reporting layer).

Consumes summary.build_summary() — it never queries database/db.py itself,
so the grouping and worst-first ordering rule lives in exactly one module.

Two separate concerns, two separate functions
---------------------------------------------
render_report()  builds the report *text*. Pure: no I/O, no console.
preview_report() renders the same scan to the *terminal*, through
                 display.print_table() / display.print_summary(), so the
                 operator sees severity-coloured output rather than a wall
                 of the plaintext that is about to be written.
generate_txt_report() orchestrates the two and owns the file write.

The no-raw-print() rule applies to the terminal, not to the file: the text
written into report.txt is deliberately unstyled ASCII, because a Rich
markup tag baked into a file is noise to whoever opens it later. Nothing in
this module calls print() — the console path goes through display.py.
"""

import os
import textwrap
from datetime import datetime

from modules.utils.config import output_dir
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
    print_panel, print_table, print_summary,
)
from modules.utils.logger import get_logger
from modules.enrichment.severity import SEVERITY_LEVELS
from modules.reporting.summary import build_summary, summary_stats

# Report width. 78 keeps the whole report inside an 80-column terminal when
# it is later cat'ed, which is the usual way a .txt report gets read.
_WIDTH = 78

# Label column width in the detail blocks, so the values line up.
_LABEL_WIDTH = 14

# Target used to route log lines when the scan has no target to name.
_FALLBACK_TARGET = "reporting"

_DEFAULT_FILENAME = "report.txt"


def _rule(char: str = "-") -> str:
    return char * _WIDTH


def _centre(text: str) -> str:
    return text.center(_WIDTH).rstrip()


def _format_timestamp(value) -> str:
    """
    Render db.py's ISO timestamp readably, falling back to the raw string.

    An unparseable value is shown verbatim rather than dropped — a report
    that says "2026-07-23T21:50:17.617773" is still useful, one that says
    nothing is not.
    """
    if not value:
        return "unknown"
    try:
        return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def _wrap(text: str, indent: int) -> list:
    """
    Wrap `text` to the report width at a given indent.

    textwrap is used rather than a manual split so long remediation
    sentences (which routinely carry a URL) break on whitespace only —
    a chopped URL is worse than a short line.
    """
    pad = " " * indent
    return textwrap.wrap(
        str(text), width=_WIDTH - indent,
        initial_indent=pad, subsequent_indent=pad,
        break_long_words=False, break_on_hyphens=False,
    ) or [pad.rstrip()]


def _field(label: str, value) -> str:
    return f"    {label:<{_LABEL_WIDTH}}: {value}"


def _service_label(finding: dict) -> str:
    """'http 2.4.7' / 'http' / 'unknown' — service and version as one cell."""
    parts = [
        str(finding.get("service") or "").strip(),
        str(finding.get("version") or "").strip(),
    ]
    return " ".join(p for p in parts if p) or "unknown"


def _display_rows(findings: list) -> list:
    """
    Adapt findings for display.print_table().

    print_table reads each column with .get(key, "-"), which only supplies
    the "-" placeholder when the key is *absent*. Rows read back from
    SQLite always carry every column, so a NULL cve_id arrives as a present
    key holding None and renders as an empty cell (and a NULL cvss renders
    as the string "None"). Substituting the placeholder here keeps that
    tidy without modifying display.py, which this phase does not own.
    """
    rows = []
    for finding in findings or []:
        row = dict(finding)
        for column in ("port", "service", "version", "cve_id", "cvss"):
            if row.get(column) is None:
                row[column] = "-"
        rows.append(row)
    return rows


def _header_block(summary: dict) -> list:
    metadata = summary.get("scan_metadata") or {}
    return [
        _rule("="),
        _centre("AEGIS SCANNER"),
        _centre("Vulnerability Assessment Report"),
        _rule("="),
        "",
        _field("Target", metadata.get("target") or "unknown"),
        _field("Scan ID", metadata.get("id", summary.get("scan_id"))),
        _field("Profile", metadata.get("profile") or "unknown"),
        _field("Scan run", _format_timestamp(metadata.get("timestamp"))),
        _field("Report built", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "",
    ]


def _summary_block(summary: dict) -> list:
    counts = summary.get("by_severity") or {}
    lines = [
        _rule(),
        "  SEVERITY SUMMARY",
        _rule(),
        "",
    ]
    for level in SEVERITY_LEVELS:
        lines.append(f"    {level:<{_LABEL_WIDTH}}: {counts.get(level, 0)}")
    lines += [
        f"    {'-' * (_LABEL_WIDTH + 6)}",
        f"    {'TOTAL':<{_LABEL_WIDTH}}: {summary.get('total_findings', 0)}",
        "",
    ]
    return lines


def _top_findings_block(summary: dict) -> list:
    """One line per top finding — the at-a-glance list, worst-first."""
    top = summary.get("top_findings") or []
    if not top:
        return []

    lines = [
        _rule(),
        f"  TOP {len(top)} FINDING(S)",
        _rule(),
        "",
    ]
    for index, finding in enumerate(top, start=1):
        identifier = finding.get("cve_id") or _service_label(finding)
        lines.append(
            f"    {index:>2}. [{finding.get('severity', 'LOW'):<8}] "
            f"port {finding.get('port', '-')} — {identifier}"
        )
    lines.append("")
    return lines


def _detail_block(summary: dict) -> list:
    """Full findings list, worst-first, one block per finding."""
    findings = summary.get("findings") or []
    lines = [
        _rule(),
        "  DETAILED FINDINGS",
        _rule(),
        "",
    ]

    if not findings:
        lines += [
            "    No findings were recorded for this scan.",
            "",
            "    This means the scan completed without recording an issue — not",
            "    that the target is known to be secure. Confirm the scan actually",
            "    reached the target before treating this as a clean result.",
            "",
        ]
        return lines

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "LOW")
        cvss = finding.get("cvss")
        cvss_cell = (
            "not scored" if cvss is None
            else f"{cvss} (source: {finding.get('severity_source', 'heuristic')})"
        )

        lines += [
            f"  [{index}] {severity} — {finding.get('cve_id') or _service_label(finding)}",
            "  " + "-" * (_WIDTH - 2),
            _field("Port", finding.get("port", "-")),
            _field("Service", _service_label(finding)),
            _field("CVE", finding.get("cve_id") or "none"),
            _field("CVSS", cvss_cell),
            _field("Severity", severity),
            "",
            f"    {'Description':<{_LABEL_WIDTH}}:",
        ]
        lines += _wrap(finding.get("description") or "No description available.", 6)
        lines += [
            "",
            f"    {'Remediation':<{_LABEL_WIDTH}}:",
        ]
        lines += _wrap(finding.get("remediation") or "No remediation guidance available.", 6)
        lines.append("")

    return lines


def render_report(summary: dict) -> str:
    """
    Build the full plain-text report body for a summary.

    Pure: takes the dict build_summary() returned and gives back a string.
    Writing it anywhere is the caller's job, which keeps this testable
    without touching the filesystem.
    """
    lines = []
    lines += _header_block(summary)
    lines += _summary_block(summary)
    lines += _top_findings_block(summary)
    lines += _detail_block(summary)
    lines += [
        _rule("="),
        _centre("End of report — generated by Aegis Scanner"),
        _rule("="),
        "",
    ]
    return "\n".join(lines)


def preview_report(summary: dict):
    """
    Render the same scan to the terminal, through display.py only.

    This is the live preview, not the file: display.print_table() already
    sorts worst-first and colours each severity badge, and
    display.print_summary() draws the counts panel, so the console view
    matches the rest of the framework rather than echoing raw report text.

    Never raises — a console rendering problem must not stop the report
    from being written.
    """
    metadata = summary.get("scan_metadata") or {}
    target = metadata.get("target") or _FALLBACK_TARGET

    try:
        print_panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Scan ID:[/bold] {metadata.get('id', summary.get('scan_id'))}    "
            f"[bold]Profile:[/bold] {metadata.get('profile') or 'unknown'}\n"
            f"[bold]Scan run:[/bold] {_format_timestamp(metadata.get('timestamp'))}",
            title="TEXT REPORT PREVIEW",
            style="cyan",
        )

        findings = summary.get("findings") or []
        if findings:
            print_table(_display_rows(findings), title=f"Findings — {target}")
        else:
            print_warning(f"[Report] no findings recorded for {target}")

        print_summary(target, summary_stats(summary))
    except Exception as exc:
        # Console-only failure: log it and carry on to the file write.
        get_logger(target).warning(f"[Report] terminal preview failed: {exc}")
        print_warning(f"[Report] could not render the terminal preview: {exc}")


def _resolve_output_path(target: str, output_path: str = None) -> str:
    """
    Decide where the report goes.

    Default is config.output_dir(target)/report.txt — output_dir() creates
    the per-target directory, which is the convention every other module
    writes under. An explicit output_path is honoured verbatim; if it names
    a directory that does not exist yet, it is created so the caller does
    not have to.
    """
    if not output_path:
        return os.path.join(output_dir(target), _DEFAULT_FILENAME)

    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    return output_path


def generate_txt_report(scan_id, output_path: str = None):
    """
    Generate the plain-text report for a persisted scan.

    Parameters
    ----------
    scan_id     : int   id of a row in the scans table
    output_path : str   optional explicit destination; defaults to
                        output/<target>/report.txt

    Returns
    -------
    str | None — the path written, or None if the report could not be
    produced. Never raises: an unknown scan_id, an unwritable destination
    or a full disk are logged and reported through display.py, and None
    comes back so the caller can carry on.
    """
    summary = build_summary(scan_id)
    metadata = summary.get("scan_metadata") or {}
    target = metadata.get("target") or _FALLBACK_TARGET
    logger = get_logger(target)

    if summary.get("error"):
        # build_summary already logged and displayed the reason; without a
        # scan there is nothing to report on, so stop here.
        logger.error(f"[Report] txt report aborted for scan_id={scan_id}: {summary['error']}")
        print_error(f"[Report] cannot generate a text report: {summary['error']}")
        return None

    # Terminal preview first, so the operator sees the result even if the
    # write below fails.
    preview_report(summary)

    try:
        body = render_report(summary)
    except Exception as exc:
        logger.error(f"[Report] failed to render txt report for scan {scan_id}: {exc}")
        print_error(f"[Report] failed to render the text report: {exc}")
        return None

    try:
        path = _resolve_output_path(target, output_path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
    except OSError as exc:
        # Unwritable directory, read-only filesystem, bad path, disk full.
        logger.error(f"[Report] could not write txt report for scan {scan_id}: {exc}")
        print_error(f"[Report] could not write the text report: {exc}")
        return None
    except Exception as exc:
        logger.error(f"[Report] unexpected error writing txt report for scan {scan_id}: {exc}")
        print_error(f"[Report] unexpected error writing the text report: {exc}")
        return None

    logger.info(
        f"[Report] txt report written to {path} "
        f"({summary['total_findings']} finding(s))"
    )
    print_success(f"[Report] text report written to {path}")
    return path


if __name__ == "__main__":
    import sys

    from database.db import get_scan_history

    if len(sys.argv) > 1:
        requested = sys.argv[1]
    else:
        history = get_scan_history()
        if not history:
            print_error("No scans in the database — run a scan first.")
            sys.exit(1)
        requested = history[0]["id"]

    print_info(f"Generating text report for scan {requested}")
    written = generate_txt_report(requested, sys.argv[2] if len(sys.argv) > 2 else None)
    if written:
        print_info(f"Report path: {written}")
    else:
        print_warning("No report was written.")
        sys.exit(1)
