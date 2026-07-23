"""
modules/reporting/report_pdf.py
PDF report writer for Aegis Scanner (reporting layer).

Consumes summary.build_summary(), exactly like report_txt.py, so both
reports describe the same scan in the same worst-first order without
either of them touching database/db.py.

PDF engine
----------
WeasyPrint, because requirements.txt already lists it — no new dependency
was added for this phase. It renders HTML + CSS to PDF, so the report is
built as an HTML string here and handed over once. The import is
deliberately lazy (inside _render_pdf) rather than at module scope:
WeasyPrint binds to native Pango/Cairo libraries and can fail at *import*
time with ImportError or OSError on a machine where those are missing.
Importing at module scope would make that failure break
`from modules.reporting.report_pdf import generate_pdf_report` for every
caller, including ones that only wanted the txt report. Lazily, the same
failure is just a None return from this one function.

This is a statically generated file, not a web page: no server, no
JavaScript, nothing is served. WeasyPrint is used purely as an HTML-to-PDF
typesetter.

Terminal output still goes through display.py only. The HTML/CSS below is
document markup written into a file, not console output.
"""

import html
import os
from datetime import datetime

from modules.utils.config import output_dir
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)
from modules.utils.logger import get_logger
from modules.enrichment.severity import SEVERITY_LEVELS
from modules.reporting.summary import build_summary

# Print-legible equivalents of display.SEVERITY_COLORS.
#
# display.py names terminal colours ("bold red", "bold orange3", "bold
# yellow", "bold green"), which cannot be used verbatim on white paper:
# terminal yellow and green are chosen for contrast against a dark
# background and wash out when printed. These are the same four hues
# darkened enough to stay legible as a filled badge with white text, so the
# PDF reads as the same severity scheme as the terminal table.
#   CRITICAL red | HIGH orange | MEDIUM yellow/amber | LOW green
_SEVERITY_HEX = {
    "CRITICAL": "#b02418",
    "HIGH": "#d78700",   # Rich's orange3, unchanged — it already prints well
    "MEDIUM": "#a8860b",
    "LOW": "#2e7d32",
}
_DEFAULT_HEX = "#5a5a5a"

# Target used to route log lines when the scan has no target to name.
_FALLBACK_TARGET = "reporting"

_DEFAULT_FILENAME = "report.pdf"


def _esc(value) -> str:
    """
    HTML-escape any value for interpolation into the document.

    Every field in a finding — service name, version string, banner — comes
    from a remote host the framework does not control. A version string
    containing '<' would otherwise corrupt the document structure, so
    nothing reaches the HTML without passing through here.
    """
    if value is None:
        return "-"
    return html.escape(str(value), quote=True)


def _format_timestamp(value) -> str:
    """Render db.py's ISO timestamp readably, falling back to the raw string."""
    if not value:
        return "unknown"
    try:
        return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def _service_label(finding: dict) -> str:
    """'http 2.4.7' / 'http' / 'unknown' — service and version as one cell."""
    parts = [
        str(finding.get("service") or "").strip(),
        str(finding.get("version") or "").strip(),
    ]
    return " ".join(p for p in parts if p) or "unknown"


def _severity_hex(severity) -> str:
    return _SEVERITY_HEX.get(str(severity or "").upper(), _DEFAULT_HEX)


def _badge(severity) -> str:
    """A filled severity pill, coloured to match the terminal scheme."""
    label = str(severity or "LOW").upper()
    return (
        f'<span class="badge" style="background:{_severity_hex(label)}">'
        f'{_esc(label)}</span>'
    )


def _stylesheet() -> str:
    """
    Document CSS.

    @page gives the printed margins and the running page number; the rest
    is deliberately plain so the PDF stays readable in black and white
    apart from the severity badges, where colour is the point.
    """
    return """
    @page {
        size: A4;
        margin: 18mm 16mm 20mm 16mm;
        @bottom-center {
            content: "Aegis Scanner — page " counter(page) " of " counter(pages);
            font-family: "DejaVu Sans", sans-serif;
            font-size: 8pt;
            color: #777;
        }
    }
    body {
        font-family: "DejaVu Sans", sans-serif;
        font-size: 9.5pt;
        color: #1c1c1c;
        line-height: 1.45;
    }
    h1, h2, h3 { margin: 0; font-weight: bold; }

    .cover {
        border-top: 5px solid #12557f;
        border-bottom: 1px solid #cfcfcf;
        padding: 14px 0 16px 0;
        margin-bottom: 20px;
    }
    .cover h1 { font-size: 24pt; letter-spacing: 3px; color: #12557f; }
    .cover .subtitle { font-size: 11pt; color: #555; margin-top: 4px; }

    table.meta { width: 100%; margin-top: 14px; border-collapse: collapse; }
    table.meta td { padding: 2px 0; vertical-align: top; }
    table.meta td.key { width: 32%; color: #555; }
    table.meta td.value { font-weight: bold; }

    h2.section {
        font-size: 12pt;
        color: #12557f;
        border-bottom: 2px solid #12557f;
        padding-bottom: 4px;
        margin: 24px 0 12px 0;
    }

    table.data { width: 100%; border-collapse: collapse; font-size: 9pt; }
    table.data th {
        background: #12557f;
        color: #fff;
        text-align: left;
        padding: 6px 8px;
        font-size: 8.5pt;
        letter-spacing: 0.5px;
    }
    table.data td {
        padding: 5px 8px;
        border-bottom: 1px solid #e3e3e3;
        vertical-align: middle;
    }
    table.data tr:nth-child(even) td { background: #f7f8f9; }
    td.num, th.num { text-align: center; }

    .badge {
        display: inline-block;
        color: #fff;
        font-size: 7.5pt;
        font-weight: bold;
        letter-spacing: 0.5px;
        padding: 2px 8px;
        border-radius: 8px;
    }

    .bar-track {
        display: inline-block;
        width: 55%;
        height: 9px;
        background: #eceff1;
        border-radius: 5px;
        vertical-align: middle;
    }
    .bar-fill { display: block; height: 9px; border-radius: 5px; }

    .finding {
        border: 1px solid #dcdcdc;
        border-left-width: 5px;
        border-radius: 3px;
        padding: 10px 12px;
        margin-bottom: 12px;
        page-break-inside: avoid;
    }
    .finding .head {
        font-size: 10.5pt;
        font-weight: bold;
        margin-bottom: 2px;
    }
    .finding .facts { color: #555; font-size: 8.5pt; margin-bottom: 7px; }
    .finding .label {
        font-size: 8pt;
        font-weight: bold;
        color: #12557f;
        letter-spacing: 0.6px;
        margin-top: 6px;
    }
    .finding p { margin: 2px 0 0 0; }

    .empty {
        border: 1px dashed #bbb;
        padding: 14px;
        color: #555;
        text-align: center;
    }
    .footer {
        margin-top: 22px;
        border-top: 1px solid #cfcfcf;
        padding-top: 7px;
        font-size: 8pt;
        color: #777;
        text-align: center;
    }
    """


def _cover_html(summary: dict) -> str:
    metadata = summary.get("scan_metadata") or {}
    rows = [
        ("Target", metadata.get("target") or "unknown"),
        ("Scan ID", metadata.get("id", summary.get("scan_id"))),
        ("Scan profile", metadata.get("profile") or "unknown"),
        ("Scan run", _format_timestamp(metadata.get("timestamp"))),
        ("Report built", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]
    cells = "".join(
        f'<tr><td class="key">{_esc(key)}</td>'
        f'<td class="value">{_esc(value)}</td></tr>'
        for key, value in rows
    )
    return (
        '<div class="cover">'
        "<h1>AEGIS SCANNER</h1>"
        '<div class="subtitle">Vulnerability Assessment Report</div>'
        "</div>"
        f'<table class="meta">{cells}</table>'
    )


def _summary_html(summary: dict) -> str:
    """
    Severity summary table: count, share of total, and a proportional bar
    in the tier's own colour, so the profile of the scan is readable at a
    glance before any individual finding is.
    """
    counts = summary.get("by_severity") or {}
    total = summary.get("total_findings", 0) or 0

    rows = []
    for level in SEVERITY_LEVELS:
        count = counts.get(level, 0)
        share = (count / total * 100) if total else 0
        # A zero-count tier gets an empty track, not a 0%-wide fill: a
        # rounded zero-width block still paints its corner radius and shows
        # up as a coloured sliver, which reads as "a few" rather than none.
        fill = (
            f'<span class="bar-fill" style="width:{share:.1f}%;'
            f'background:{_severity_hex(level)}"></span>'
            if count else ""
        )
        rows.append(
            "<tr>"
            f"<td>{_badge(level)}</td>"
            f'<td class="num">{count}</td>'
            f'<td><span class="bar-track">{fill}</span></td>'
            f'<td class="num">{share:.0f}%</td>'
            "</tr>"
        )

    rows.append(
        "<tr>"
        "<td><b>TOTAL</b></td>"
        f'<td class="num"><b>{total}</b></td>'
        "<td></td>"
        '<td class="num"></td>'
        "</tr>"
    )

    return (
        '<h2 class="section">Severity Summary</h2>'
        '<table class="data">'
        "<thead><tr>"
        '<th>Severity</th><th class="num">Count</th>'
        '<th>Share</th><th class="num">%</th>'
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _top_findings_html(summary: dict) -> str:
    """
    At-a-glance table, worst-first — the PDF counterpart of
    display.print_table(), with the same columns in the same order.
    """
    top = summary.get("top_findings") or []
    if not top:
        return ""

    rows = "".join(
        "<tr>"
        f'<td class="num">{_esc(finding.get("port"))}</td>'
        f'<td>{_esc(finding.get("service"))}</td>'
        f'<td>{_esc(finding.get("version"))}</td>'
        f'<td>{_esc(finding.get("cve_id"))}</td>'
        f'<td class="num">{_esc(finding.get("cvss"))}</td>'
        f'<td class="num">{_badge(finding.get("severity"))}</td>'
        "</tr>"
        for finding in top
    )

    return (
        f'<h2 class="section">Top {len(top)} Finding(s)</h2>'
        '<table class="data">'
        "<thead><tr>"
        '<th class="num">Port</th><th>Service</th><th>Version</th>'
        '<th>CVE</th><th class="num">CVSS</th><th class="num">Severity</th>'
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _details_html(summary: dict) -> str:
    """One card per finding, worst-first, carrying description + remediation."""
    findings = summary.get("findings") or []
    header = '<h2 class="section">Detailed Findings</h2>'

    if not findings:
        return (
            header
            + '<div class="empty"><b>No findings were recorded for this scan.</b>'
            "<br/>This means the scan completed without recording an issue — not "
            "that the target is known to be secure. Confirm the scan actually "
            "reached the target before treating this as a clean result.</div>"
        )

    cards = []
    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity") or "LOW").upper()
        cvss = finding.get("cvss")
        cvss_cell = (
            "not scored" if cvss is None
            else f"{cvss} (source: {finding.get('severity_source', 'heuristic')})"
        )
        title = finding.get("cve_id") or _service_label(finding)

        cards.append(
            f'<div class="finding" style="border-left-color:{_severity_hex(severity)}">'
            f'<div class="head">{index}. {_esc(title)} &nbsp;{_badge(severity)}</div>'
            f'<div class="facts">'
            f'Port {_esc(finding.get("port"))} &nbsp;|&nbsp; '
            f'Service {_esc(_service_label(finding))} &nbsp;|&nbsp; '
            f'CVE {_esc(finding.get("cve_id") or "none")} &nbsp;|&nbsp; '
            f'CVSS {_esc(cvss_cell)}'
            f"</div>"
            f'<div class="label">DESCRIPTION</div>'
            f'<p>{_esc(finding.get("description") or "No description available.")}</p>'
            f'<div class="label">REMEDIATION</div>'
            f'<p>{_esc(finding.get("remediation") or "No remediation guidance available.")}</p>'
            f"</div>"
        )

    return header + "".join(cards)


def render_html(summary: dict) -> str:
    """
    Build the complete HTML document WeasyPrint typesets into the PDF.

    Pure: no I/O and no console output, so the markup can be inspected or
    tested without producing a file.
    """
    metadata = summary.get("scan_metadata") or {}
    title = f"Aegis Scanner Report — {metadata.get('target') or 'unknown'}"

    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'/>"
        f"<title>{_esc(title)}</title>"
        f"<style>{_stylesheet()}</style>"
        "</head><body>"
        + _cover_html(summary)
        + _summary_html(summary)
        + _top_findings_html(summary)
        + _details_html(summary)
        + '<div class="footer">Generated by Aegis Scanner — '
          "modular vulnerability assessment framework</div>"
        "</body></html>"
    )


def _resolve_output_path(target: str, output_path: str = None) -> str:
    """
    Decide where the PDF goes.

    Mirrors report_txt._resolve_output_path: default is
    config.output_dir(target)/report.pdf, and an explicit path has its
    parent directory created so the caller does not have to.
    """
    if not output_path:
        return os.path.join(output_dir(target), _DEFAULT_FILENAME)

    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    return output_path


def _render_pdf(document_html: str, path: str):
    """
    Typeset `document_html` to `path` with WeasyPrint.

    May raise — ImportError/OSError if the native libraries are missing,
    OSError if the destination is unwritable, or any WeasyPrint-internal
    error. generate_pdf_report() is what turns those into a logged None.

    base_url is set to the output directory so relative URLs (there are
    none today) resolve predictably rather than against the process CWD.
    """
    from weasyprint import HTML  # lazy: see the module docstring

    HTML(string=document_html, base_url=os.path.dirname(os.path.abspath(path))).write_pdf(path)


def generate_pdf_report(scan_id, output_path: str = None):
    """
    Generate the PDF report for a persisted scan.

    Parameters
    ----------
    scan_id     : int   id of a row in the scans table
    output_path : str   optional explicit destination; defaults to
                        output/<target>/report.pdf

    Returns
    -------
    str | None — the path written, or None if the PDF could not be
    produced. Never raises: an unknown scan_id, an unwritable destination,
    a missing WeasyPrint installation and any WeasyPrint-internal failure
    are all logged, reported through display.py, and returned as None.
    """
    summary = build_summary(scan_id)
    metadata = summary.get("scan_metadata") or {}
    target = metadata.get("target") or _FALLBACK_TARGET
    logger = get_logger(target)

    if summary.get("error"):
        # build_summary already logged and displayed the reason.
        logger.error(f"[Report] pdf report aborted for scan_id={scan_id}: {summary['error']}")
        print_error(f"[Report] cannot generate a PDF report: {summary['error']}")
        return None

    try:
        document_html = render_html(summary)
    except Exception as exc:
        logger.error(f"[Report] failed to render pdf markup for scan {scan_id}: {exc}")
        print_error(f"[Report] failed to build the PDF document: {exc}")
        return None

    try:
        path = _resolve_output_path(target, output_path)
    except OSError as exc:
        logger.error(f"[Report] could not prepare pdf output path for scan {scan_id}: {exc}")
        print_error(f"[Report] could not prepare the PDF output path: {exc}")
        return None

    print_info(f"[Report] typesetting PDF for {target} ({summary['total_findings']} finding(s))")

    try:
        _render_pdf(document_html, path)
    except ImportError as exc:
        # weasyprint is in requirements.txt, so this means the venv is not
        # installed rather than that the dependency was never chosen.
        message = f"WeasyPrint is not available ({exc}) — run: pip install -r requirements.txt"
        logger.error(f"[Report] pdf report failed for scan {scan_id}: {message}")
        print_error(f"[Report] {message}")
        return None
    except OSError as exc:
        # Unwritable destination, or WeasyPrint's native Pango/Cairo
        # libraries missing on this host.
        logger.error(f"[Report] could not write pdf report for scan {scan_id}: {exc}")
        print_error(f"[Report] could not write the PDF report: {exc}")
        return None
    except Exception as exc:
        # Catch-all for WeasyPrint-internal errors — the framework must
        # never crash because a PDF could not be typeset.
        logger.error(f"[Report] unexpected error building pdf for scan {scan_id}: {exc}")
        print_error(f"[Report] unexpected error building the PDF report: {exc}")
        return None

    logger.info(
        f"[Report] pdf report written to {path} "
        f"({summary['total_findings']} finding(s))"
    )
    print_success(f"[Report] PDF report written to {path}")
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

    print_info(f"Generating PDF report for scan {requested}")
    written = generate_pdf_report(requested, sys.argv[2] if len(sys.argv) > 2 else None)
    if written:
        print_info(f"Report path: {written}")
    else:
        print_warning("No report was written.")
        sys.exit(1)
