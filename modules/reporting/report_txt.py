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
from modules.reporting.retention import report_filename
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
    print_panel, print_table, print_summary,
)
from modules.utils.logger import get_logger
from modules.enrichment.severity import SEVERITY_LEVELS
from modules.reporting.summary import (
    build_summary, summary_stats, injection_findings, INJECTION_FINDING_TYPES,
    field_display, service_display, cvss_display, distinct_identifiers,
    profile_scope_note,
)
from modules.enrichment.compliance_map import group_by_framework, FRAMEWORKS

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


# 4 spaces of indent + the label column + ": " — what _field() spends before
# the value starts, and therefore how much of the 78-column width is left.
_FIELD_VALUE_WIDTH = _WIDTH - (4 + _LABEL_WIDTH + 2)


def _fit(value) -> str:
    """One-line field value that cannot overflow the report width.

    Endpoint and Reference carry URLs, which are long, and ZAP's reference is
    several URLs at once. Wrapping them onto continuation lines would break
    the aligned label/value layout of the finding card, so they are elided in
    the middle: the host and the tail of the path both survive, which is what
    makes a truncated URL still recognisable.
    """
    text = " ".join(str(value or "").split())
    if len(text) <= _FIELD_VALUE_WIDTH:
        return text
    keep = _FIELD_VALUE_WIDTH - 3
    head = keep // 2
    return f"{text[:head]}...{text[len(text) - (keep - head):]}"


# Terminal table cells are narrow, so the console gets an abbreviated form
# of summary.field_display()'s wording: the distinction between "cannot
# apply" and "not determined" is preserved, the explanatory tail is not.
# The file report and the PDF carry the full phrasing.
_TERMINAL_NOT_APPLICABLE = "N/A"
_TERMINAL_UNKNOWN = "not determined"


def _terminal_cell(finding: dict, column: str) -> str:
    """Short form of field_display() that fits a terminal column."""
    rendered = field_display(finding, column)
    if rendered.startswith("N/A"):
        return _TERMINAL_NOT_APPLICABLE
    if rendered.startswith("not determined"):
        return _TERMINAL_UNKNOWN
    return rendered


def _display_rows(findings: list) -> list:
    """
    Adapt findings for display.print_table().

    print_table reads each column with .get(key, "-"), which only supplies
    the "-" placeholder when the key is *absent*. Rows read back from
    SQLite always carry every column, so a NULL cve_id arrives as a present
    key holding None and renders as an empty cell (and a NULL cvss renders
    as the string "None").

    Substituting a bare "-" here (the previous behaviour) was tidy but
    uninformative: it made "this finding type has no CVE by nature" and
    "a CVE should have been determined and wasn't" look identical. The
    cells now say which one it is, in the abbreviated form a terminal
    column has room for.
    """
    rows = []
    for finding in findings or []:
        row = dict(finding)
        for column in ("port", "service", "version", "cve_id", "cvss"):
            if row.get(column) is None:
                row[column] = _terminal_cell(finding, column)
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
    ] + _scope_note_block(metadata.get("profile"))


def _scope_note_block(profile) -> list:
    """The profile's scope statement, if it has one.

    Placed directly under the header rather than at the end: a reader who
    stops after the severity summary is exactly the reader who most needs to
    know what the profile did not look at.
    """
    note = profile_scope_note(profile, labelled=True)
    if not note:
        return []
    return _wrap(note, 2) + [""]


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
    # Labelled as a set rather than one at a time, so two findings that
    # would otherwise render the same truncated text are pulled apart —
    # see summary.distinct_identifiers().
    identifiers = distinct_identifiers(top)
    for index, (finding, identifier) in enumerate(zip(top, identifiers), start=1):
        lines.append(
            f"    {index:>2}. [{finding.get('severity', 'LOW'):<8}] "
            f"port {field_display(finding, 'port')} — {identifier}"
        )
    lines.append("")
    return lines


# Safe display cap for a payload / evidence snippet in the injection
# section. The XSS evidence is already truncated by xss_wrap; this bounds
# the sqlmap payloads/metadata (a UNION payload or a long database list) so
# one finding can't run to dozens of wrapped lines.
_INJECTION_FIELD_MAXLEN = 300


def _truncate(value, limit: int = _INJECTION_FIELD_MAXLEN) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _injection_block(summary: dict) -> list:
    """
    Dedicated "Injection & Scripting Vulnerabilities" section: every
    confirmed SQL injection and reflected-XSS finding, shown with the exact
    payload, the parameter/endpoint it was sent against, and a response
    snippet proving exploitation.

    Rendered separately from (and ahead of) the general DETAILED FINDINGS
    list, and only when at least one such finding exists — it does not
    restructure the rest of the report. Scoped to exactly these two
    vulnerability classes (see summary.INJECTION_FINDING_TYPES).
    """
    injections = injection_findings(summary)
    if not injections:
        return []

    lines = [
        _rule(),
        "  INJECTION & SCRIPTING VULNERABILITIES",
        _rule(),
        "",
        "    Confirmed SQL injection and cross-site scripting findings, each",
        "    shown with the exact payload used, the parameter/endpoint it was",
        "    sent against, and a response snippet proving exploitation.",
        "",
    ]

    for index, finding in enumerate(injections, start=1):
        kind = str(finding.get("finding_type") or "").lower()
        label = INJECTION_FINDING_TYPES.get(kind, "Injection")
        severity = finding.get("severity", "LOW")

        lines += [
            f"  [{index}] {severity} — {label}",
            "  " + "-" * (_WIDTH - 2),
            _field("Class", label),
            _field("Endpoint", _truncate(finding.get("endpoint")) or "-"),
            _field("Parameter", finding.get("parameter") or "-"),
            "",
            f"    {'Payload':<{_LABEL_WIDTH}}:",
        ]
        lines += _wrap(_truncate(finding.get("payload")) or "(not recorded)", 6)
        lines += [
            "",
            f"    {'Evidence':<{_LABEL_WIDTH}}:",
        ]
        lines += _wrap(
            _truncate(finding.get("evidence")) or "(no response snippet recorded)", 6
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

    identifiers = distinct_identifiers(findings)
    for index, (finding, identifier) in enumerate(zip(findings, identifiers), start=1):
        severity = finding.get("severity", "LOW")

        lines += [
            f"  [{index}] {severity} — {identifier}",
            "  " + "-" * (_WIDTH - 2),
            _field("Port", field_display(finding, "port")),
            _field("Service", service_display(finding)),
            _field("CVE", field_display(finding, "cve_id")),
            _field("CVSS", cvss_display(finding)),
            _field("Severity", severity),
            # Endpoint and Reference are populated at the source by the web
            # wrappers (gobuster/dirb URL, nikto URI + "See:" citation, ZAP
            # url + reference). They go through field_display() like every
            # other cell, so a host-level finding says "N/A (host-level
            # finding)" rather than showing a blank where a URL would be.
            _field("Endpoint", _fit(field_display(finding, "endpoint"))),
            _field("Reference", _fit(field_display(finding, "reference"))),
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


def _compliance_block(summary: dict) -> list:
    """
    Findings grouped by the framework control each maps to — PCI-DSS,
    ISO 27001, NIST 800-53.

    Rendered ONLY for the compliance profile, and empty for every other, so
    no other profile's report changes by a single byte. That gate is
    deliberate rather than incidental: a control reference asserts a finding
    is evidence about a named requirement, and stamping that on every CVE a
    deepscan turns up would make the assertion meaningless. See
    modules/enrichment/compliance_map.py.

    A framework with no findings is omitted rather than printed empty: a
    heading with nothing under it reads as "assessed and clean", which is a
    stronger claim than "nothing mapped here".
    """
    profile = (summary.get("scan_metadata") or {}).get("profile")
    if str(profile or "").strip().lower() != "compliance":
        return []

    findings = summary.get("findings") or []
    grouped = group_by_framework(findings)

    lines = [
        _rule(),
        "  COMPLIANCE CONTROL MAPPING",
        _rule(),
        "",
    ]

    if not grouped:
        lines += [
            "    No finding in this scan mapped to a tracked control.",
            "",
            "    This is not a pass: it means the findings recorded here are of",
            "    types this project has no defensible mapping for, so they were",
            "    left unmapped rather than assigned a loosely-related control.",
            "",
        ]
        return lines

    lines += [
        "    Each finding below is evidence bearing on the listed control. A",
        "    mapping is not a compliance verdict — it identifies which",
        "    requirement this evidence belongs under when assessed.",
        "",
    ]

    # Fixed framework order, not dict order, so successive reports of the
    # same target are diffable against each other.
    for _prefix, label in FRAMEWORKS:
        entries = grouped.get(label)
        if not entries:
            continue

        lines += [f"    {label}", "    " + "-" * (_WIDTH - 6)]

        # One heading per control, with the findings under it: an auditor
        # reads a requirement at a time, not a finding at a time.
        by_control = {}
        for reference, finding in entries:
            by_control.setdefault(reference, []).append(finding)

        for reference in sorted(by_control):
            lines += _wrap(reference, 6)
            for finding in by_control[reference]:
                severity = finding.get("severity", "LOW")
                description = finding.get("description") or "No description available."
                lines += _wrap(f"[{severity}] {description}", 10)
            lines.append("")
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
    lines += _injection_block(summary)
    lines += _compliance_block(summary)
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

        # No real {tools_run, tools_failed, tools_skipped} exists yet at
        # this point in the profile run — see print_summary()'s
        # show_tool_counts docstring note.
        print_summary(target, summary_stats(summary), show_tool_counts=False)
    except Exception as exc:
        # Console-only failure: log it and carry on to the file write.
        get_logger(target).warning(f"[Report] terminal preview failed: {exc}")
        print_warning(f"[Report] could not render the terminal preview: {exc}")


def _resolve_output_path(target: str, output_path: str = None,
                         profile: str = None, scan_id=None) -> str:
    """
    Decide where the report goes.

    Default is
    config.output_dir(target)/report_<profile>_<target>_<scan_id>.txt —
    one file per scan, so a new scan can no longer overwrite the previous
    scan's report (see modules/reporting/retention.py for why that
    mattered). output_dir() creates the per-target directory, which is the
    convention every other module writes under.

    Falls back to the historical fixed report.txt name only when the
    profile or scan_id is unknown, which keeps a direct
    generate_txt_report() call with neither argument working as it always
    did. An explicit output_path is honoured verbatim; if it names a
    directory that does not exist yet, it is created so the caller does not
    have to.
    """
    if not output_path:
        directory = output_dir(target)
        if profile and scan_id is not None:
            return os.path.join(directory, report_filename(profile, target, scan_id, "txt"))
        return os.path.join(directory, _DEFAULT_FILENAME)

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
        path = _resolve_output_path(
            target, output_path,
            profile=metadata.get("profile"), scan_id=metadata.get("id", scan_id),
        )
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
