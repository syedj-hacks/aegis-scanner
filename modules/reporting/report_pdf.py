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
import math
import os
from datetime import datetime

from modules.utils.config import output_dir
from modules.reporting.retention import report_filename
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)
from modules.utils.logger import get_logger
from modules.enrichment.severity import SEVERITY_LEVELS
from modules.reporting.summary import (
    build_summary, injection_findings, INJECTION_FINDING_TYPES,
    field_display, service_display, cvss_display, distinct_identifiers,
    profile_scope_note,
)
from modules.enrichment.compliance_map import group_by_framework, FRAMEWORKS
from modules.reporting.risk_report import risk_posture, top_risks

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

    table.cover-band { width: 100%; margin-top: 14px; border-collapse: collapse; }
    table.cover-band td { vertical-align: middle; }
    table.cover-band td.cb-meta { width: 62%; }
    table.cover-band td.cb-chart { width: 38%; text-align: center; }

    table.meta { width: 100%; border-collapse: collapse; }
    table.meta td { padding: 2px 0; vertical-align: top; }
    table.meta td.key { width: 40%; color: #555; }
    table.meta td.value { font-weight: bold; }

    .chart-box { display: inline-block; text-align: center; }
    svg.donut { display: block; margin: 0 auto; }
    table.legend { margin: 6px auto 0 auto; border-collapse: collapse; font-size: 8.5pt; }
    table.legend td { padding: 1px 5px; }
    table.legend td.lg-label { color: #444; text-align: left; }
    table.legend td.lg-count { font-weight: bold; text-align: right; }
    .swatch {
        display: inline-block; width: 9px; height: 9px;
        border-radius: 2px; vertical-align: middle;
    }

    .scope-note {
        margin-top: 12px;
        padding: 8px 10px;
        border-left: 3px solid #9aa7b1;
        background: #f4f6f8;
        color: #3d4750;
        font-size: 8.5pt;
        line-height: 1.4;
    }

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

    .inj-intro { color: #444; font-size: 9pt; margin: 0 0 10px 0; }
    .injection {
        border: 1px solid #d9c2c0;
        border-left: 5px solid #b02418;
        border-radius: 3px;
        padding: 10px 12px;
        margin-bottom: 12px;
        page-break-inside: avoid;
    }
    .injection .head { font-size: 10.5pt; font-weight: bold; margin-bottom: 4px; }
    .injection .facts { color: #555; font-size: 8.5pt; margin-bottom: 7px; }
    .injection .label {
        font-size: 8pt; font-weight: bold; color: #12557f;
        letter-spacing: 0.6px; margin-top: 6px;
    }
    .injection pre {
        margin: 3px 0 0 0;
        background: #f4f2f0;
        border: 1px solid #e0dcd9;
        border-radius: 3px;
        padding: 6px 8px;
        font-family: "DejaVu Sans Mono", monospace;
        font-size: 8pt;
        color: #333;
        white-space: pre-wrap;
        word-break: break-all;
    }
    .footer {
        margin-top: 22px;
        border-top: 1px solid #cfcfcf;
        padding-top: 7px;
        font-size: 8pt;
        color: #777;
        text-align: center;
    }

    /* --- Phase 4: part headers, risk banner, top risks, enrichment --- */
    h1.part {
        font-size: 15pt;
        margin: 26px 0 12px 0;
        padding-bottom: 5px;
        border-bottom: 2px solid #2b3a55;
        color: #2b3a55;
        page-break-before: auto;
    }
    p.lead { color: #444; font-size: 9.5pt; margin: 4px 0 12px 0; }
    .risk-banner {
        display: flex;
        align-items: center;
        border: 2px solid #4a5568;
        border-radius: 8px;
        padding: 14px 18px;
        margin: 8px 0 18px 0;
    }
    .risk-score { font-size: 40pt; font-weight: 700; line-height: 1; min-width: 165px; }
    .risk-max { font-size: 15pt; color: #888; font-weight: 400; }
    .risk-meta { padding-left: 18px; }
    .risk-band {
        display: inline-block; color: #fff; font-weight: 700; font-size: 9pt;
        padding: 2px 10px; border-radius: 10px; letter-spacing: 0.4px;
    }
    .risk-note { font-size: 9pt; color: #444; margin-top: 6px; }
    .toprisk {
        border-left: 3px solid #cbd5e0; padding: 6px 10px; margin: 7px 0;
        background: #f7f9fc;
    }
    .toprisk-head { font-weight: 600; margin-bottom: 3px; }
    .risk-chip {
        display: inline-block; background: #2b3a55; color: #fff; font-size: 8pt;
        padding: 1px 7px; border-radius: 9px; margin-left: 6px;
    }
    .facts.enrich { margin-top: 3px; }
    .conf-confirmed { color: #2f7d32; font-weight: 700; }
    .conf-potential { color: #b8860b; font-weight: 700; }
    """


# Donut geometry. r/stroke chosen so the ring reads clearly at ~150px on
# the cover; the circumference is what each severity segment's arc length is
# measured against.
_DONUT_RADIUS = 52
_DONUT_CENTRE = 70
_DONUT_STROKE = 24
_DONUT_CIRCUMFERENCE = 2 * math.pi * _DONUT_RADIUS


def _severity_donut_svg(summary: dict) -> str:
    """
    Inline SVG donut of the severity distribution, generated from the very
    same by_severity counts the summary panel uses — no new data, just a
    second, at-a-glance view of it on the cover.

    Built as stacked stroked arcs (stroke-dasharray) in the four severity
    hues (_SEVERITY_HEX), matching the terminal/summary colour scheme.
    Static SVG, not script — WeasyPrint typesets it directly. A scan with no
    findings renders an empty grey ring with a "0" centre rather than
    nothing.
    """
    counts = summary.get("by_severity") or {}
    total = summary.get("total_findings", 0) or 0
    cx = cy = _DONUT_CENTRE
    circ = _DONUT_CIRCUMFERENCE

    # Grey base ring behind the coloured segments (also the whole ring when
    # there are no findings to colour it in).
    arcs = [
        f'<circle cx="{cx}" cy="{cy}" r="{_DONUT_RADIUS}" fill="none" '
        f'stroke="#eceff1" stroke-width="{_DONUT_STROKE}" />'
    ]

    offset = 0.0
    for level in SEVERITY_LEVELS:
        count = counts.get(level, 0)
        if not count or not total:
            continue
        seg = (count / total) * circ
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{_DONUT_RADIUS}" fill="none" '
            f'stroke="{_severity_hex(level)}" stroke-width="{_DONUT_STROKE}" '
            f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" />'
        )
        offset += seg

    # Centre label sits outside the rotated group so it stays upright.
    centre = (
        f'<text x="{cx}" y="{cy - 3}" text-anchor="middle" '
        f'font-size="21" font-weight="bold" fill="#1c1c1c">{total}</text>'
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" '
        f'font-size="9" fill="#666">findings</text>'
    )

    return (
        '<svg class="donut" viewBox="0 0 140 140" width="150" height="150">'
        f'<g transform="rotate(-90 {cx} {cy})">{"".join(arcs)}</g>'
        f"{centre}</svg>"
    )


def _severity_legend_html(summary: dict) -> str:
    """Colour-swatch legend + per-tier count, paired with the donut."""
    counts = summary.get("by_severity") or {}
    items = "".join(
        '<tr>'
        f'<td><span class="swatch" style="background:{_severity_hex(level)}"></span></td>'
        f'<td class="lg-label">{_esc(level.title())}</td>'
        f'<td class="lg-count">{counts.get(level, 0)}</td>'
        "</tr>"
        for level in SEVERITY_LEVELS
    )
    return f'<table class="legend">{items}</table>'


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
    # Two-column band under the title: scan metadata on the left, the
    # severity-distribution donut (+ legend) on the right, so the cover
    # leads with the shape of the result at a glance.
    chart = (
        '<div class="chart-box">'
        f"{_severity_donut_svg(summary)}"
        f"{_severity_legend_html(summary)}"
        "</div>"
    )
    return (
        '<div class="cover">'
        "<h1>AEGIS SCANNER</h1>"
        '<div class="subtitle">Vulnerability Assessment Report</div>'
        "</div>"
        '<table class="cover-band"><tr>'
        f'<td class="cb-meta"><table class="meta">{cells}</table></td>'
        f'<td class="cb-chart">{chart}</td>'
        "</tr></table>"
        + _scope_note_html(metadata.get("profile"))
    )


def _scope_note_html(profile) -> str:
    """The profile's scope statement, worded identically to the text report.

    Styled as a quiet note rather than a warning banner — it states what the
    profile's scope is, which is not the same as saying something went wrong.
    """
    note = profile_scope_note(profile, labelled=True)
    if not note:
        return ""
    return f'<div class="scope-note">{_esc(note)}</div>'


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
        f'<td class="num">{_esc(field_display(finding, "port"))}</td>'
        f'<td>{_esc(field_display(finding, "service"))}</td>'
        f'<td>{_esc(field_display(finding, "version"))}</td>'
        f'<td>{_esc(field_display(finding, "cve_id"))}</td>'
        f'<td class="num">{_esc(field_display(finding, "cvss"))}</td>'
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


# Safe display cap for a payload / evidence snippet in the injection
# section (see report_txt._INJECTION_FIELD_MAXLEN — same rationale).
_INJECTION_FIELD_MAXLEN = 300


def _truncate(value, limit: int = _INJECTION_FIELD_MAXLEN) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _injection_html(summary: dict) -> str:
    """
    Dedicated "Injection & Scripting Vulnerabilities" section: one card per
    confirmed SQL injection / reflected-XSS finding, each showing the exact
    payload, the parameter/endpoint it was sent against, and a response
    snippet proving exploitation.

    Rendered separately from the general Detailed Findings list and only
    when at least one such finding exists, so it does not restructure the
    rest of the report. Scoped to exactly the two vulnerability classes in
    summary.INJECTION_FINDING_TYPES.
    """
    injections = injection_findings(summary)
    if not injections:
        return ""

    cards = []
    for index, finding in enumerate(injections, start=1):
        kind = str(finding.get("finding_type") or "").lower()
        label = INJECTION_FINDING_TYPES.get(kind, "Injection")
        severity = str(finding.get("severity") or "LOW").upper()

        cards.append(
            '<div class="injection">'
            f'<div class="head">{index}. {_esc(label)} &nbsp;{_badge(severity)}</div>'
            '<div class="facts">'
            f'Endpoint {_esc(_truncate(finding.get("endpoint")) or "-")} '
            f'&nbsp;|&nbsp; Parameter {_esc(finding.get("parameter") or "-")}'
            "</div>"
            '<div class="label">PAYLOAD</div>'
            f'<pre>{_esc(_truncate(finding.get("payload")) or "(not recorded)")}</pre>'
            '<div class="label">RESPONSE EVIDENCE</div>'
            f'<pre>{_esc(_truncate(finding.get("evidence")) or "(no response snippet recorded)")}</pre>'
            "</div>"
        )

    return (
        '<h2 class="section">Injection &amp; Scripting Vulnerabilities</h2>'
        '<p class="inj-intro">Confirmed SQL injection and cross-site scripting '
        "findings, each shown with the exact payload used, the parameter/endpoint "
        "it was sent against, and a response snippet proving exploitation.</p>"
        + "".join(cards)
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
    identifiers = distinct_identifiers(findings)
    for index, (finding, title) in enumerate(zip(findings, identifiers), start=1):
        severity = str(finding.get("severity") or "LOW").upper()
        # Shared with the text report so the same finding cannot be titled
        # two different things depending on which file the reader opens.

        # Phase 4 enrichment line: confidence (Confirmed/Potential — the
        # false-positive distinction), EPSS exploit probability, and the
        # combined risk score. Only rendered when present so a legacy-scan
        # finding (all NULL) shows the same card it always did.
        confidence = finding.get("confidence")
        epss = finding.get("epss_score")
        risk = finding.get("risk_score")
        enrich_bits = []
        if confidence:
            css = "conf-confirmed" if confidence == "Confirmed" else "conf-potential"
            enrich_bits.append(f'<span class="{css}">{_esc(confidence)}</span>')
        if epss is not None:
            enrich_bits.append(f"EPSS {epss * 100:.0f}%")
        if risk is not None:
            enrich_bits.append(f"Risk {risk}/10")
        enrich_html = (
            f'<div class="facts enrich">{" &nbsp;|&nbsp; ".join(enrich_bits)}</div>'
            if enrich_bits else ""
        )

        cards.append(
            f'<div class="finding" style="border-left-color:{_severity_hex(severity)}">'
            f'<div class="head">{index}. {_esc(title)} &nbsp;{_badge(severity)}</div>'
            f'<div class="facts">'
            f'Port {_esc(field_display(finding, "port"))} &nbsp;|&nbsp; '
            f'Service {_esc(service_display(finding))} &nbsp;|&nbsp; '
            f'CVE {_esc(field_display(finding, "cve_id"))} &nbsp;|&nbsp; '
            f'CVSS {_esc(cvss_display(finding))}'
            f"</div>"
            + enrich_html
            # Same two cells the text report's detail card gained, through
            # the same field_display(), so the two files cannot disagree
            # about what a finding's endpoint or citation was.
            + f'<div class="facts">'
            f'Endpoint {_esc(_truncate(field_display(finding, "endpoint")))} '
            f'&nbsp;|&nbsp; '
            f'Reference {_esc(_truncate(field_display(finding, "reference")))}'
            f"</div>"
            f'<div class="label">DESCRIPTION</div>'
            f'<p>{_esc(finding.get("description") or "No description available.")}</p>'
            f'<div class="label">REMEDIATION</div>'
            f'<p>{_esc(finding.get("remediation") or "No remediation guidance available.")}</p>'
            f"</div>"
        )

    return header + "".join(cards)


def _compliance_html(summary: dict) -> str:
    """
    "Compliance Control Mapping" section: findings grouped by framework and
    then by control.

    Returns "" for every profile other than compliance, so no other
    profile's PDF changes at all — the same gate report_txt._compliance_block
    applies, for the same reason (see
    modules/enrichment/compliance_map.py).
    """
    profile = (summary.get("scan_metadata") or {}).get("profile")
    if str(profile or "").strip().lower() != "compliance":
        return ""

    grouped = group_by_framework(summary.get("findings") or [])
    if not grouped:
        return (
            '<h2>Compliance Control Mapping</h2>'
            "<p>No finding in this scan mapped to a tracked control. This is "
            "not a pass — it means the findings recorded are of types this "
            "project has no defensible mapping for, and were left unmapped "
            "rather than assigned a loosely-related control.</p>"
        )

    parts = [
        '<h2>Compliance Control Mapping</h2>',
        "<p>Each finding below is evidence bearing on the listed control. A "
        "mapping is not a compliance verdict &mdash; it identifies which "
        "requirement this evidence belongs under when assessed.</p>",
    ]

    # Fixed framework order so two reports of the same target are diffable.
    for _prefix, label in FRAMEWORKS:
        entries = grouped.get(label)
        if not entries:
            continue

        by_control = {}
        for reference, finding in entries:
            by_control.setdefault(reference, []).append(finding)

        parts.append(f"<h3>{_esc(label)}</h3>")
        for reference in sorted(by_control):
            rows = "".join(
                "<tr>"
                f"<td>{_badge(str(f.get('severity') or 'LOW').upper())}</td>"
                f"<td>{_esc(f.get('description') or 'No description available.')}</td>"
                "</tr>"
                for f in by_control[reference]
            )
            parts.append(
                f'<p class="control">{_esc(reference)}</p>'
                f'<table class="findings"><tbody>{rows}</tbody></table>'
            )

    return "".join(parts)


def _risk_band_hex(band: str) -> str:
    """Colour for the environment risk band."""
    return {
        "Critical": "#b3123a", "High": "#c74a1b",
        "Medium": "#b8860b", "Low": "#2f7d32", "None": "#4a5568",
    }.get(band, "#4a5568")


def _risk_banner_html(summary: dict) -> str:
    """
    The environment Risk Score banner — one number for the whole scanned
    asset, the first thing the executive summary shows. Aggregated from
    every finding's combined CVSS+EPSS risk weighted by asset criticality
    (Phase 4); the method is stated so the number is not a black box.
    """
    posture = risk_posture(summary)
    env = posture["environment_risk"]
    score = env["score"]
    band = env["band"]
    colour = _risk_band_hex(band)
    crit = posture["criticality"]

    return (
        '<div class="risk-banner" style="border-color:{c}">'
        '<div class="risk-score" style="color:{c}">{s}<span class="risk-max">/100</span></div>'
        '<div class="risk-meta">'
        '<div class="risk-band" style="background:{c}">{b} RISK</div>'
        '<div class="risk-note">Environment Risk Score — aggregated from every '
        "finding's combined CVSS&times;EPSS risk, weighted by an asset "
        'criticality of <b>{crit}</b>. Higher means a more urgent, more '
        "exploitable posture; it is driven by the worst findings, not the "
        "count of them.</div>"
        "</div></div>"
    ).format(c=colour, s=score, b=band.upper(), crit=_esc(crit))


def _executive_top_risks_html(summary: dict) -> str:
    """
    Top 5 risks in plain language — the executive summary's actionable core.
    Each is a sentence a non-specialist can act on, ranked by combined risk
    (so a mass-exploited medium can outrank a theoretical critical).
    """
    risks = top_risks(summary.get("findings") or [], limit=5)
    if not risks:
        return ""

    items = []
    for r in risks:
        sev = str(r.get("severity") or "LOW").upper()
        risk_score = r.get("risk_score")
        risk_txt = f'<span class="risk-chip">risk {risk_score}</span>' if risk_score is not None else ""
        items.append(
            '<div class="toprisk">'
            f'<div class="toprisk-head">{r["rank"]}. {_badge(sev)} {risk_txt}</div>'
            f'<p>{_esc(r["plain_language"])}</p>'
            "</div>"
        )

    return (
        '<h2 class="section">Top Risks — Plain Language</h2>'
        '<p class="lead">The five findings that most deserve attention, in '
        "priority order. Priority blends severity with real-world exploit "
        "probability (EPSS), so the list reflects what to fix first, not "
        "merely what scores highest.</p>"
        + "".join(items)
    )


def render_html(summary: dict) -> str:
    """
    Build the complete HTML document WeasyPrint typesets into the PDF.

    Structured into two reader-facing parts (Phase 4):

      EXECUTIVE SUMMARY   the risk posture at a glance — the environment
                          Risk Score, the severity breakdown chart, and the
                          top 5 risks written in plain language. Everything a
                          decision-maker needs without reading a CVE.

      TECHNICAL FINDINGS  the full per-finding detail — CVE/CVSS/EPSS,
                          evidence, endpoint, and remediation steps — plus
                          the injection and compliance sections. For the
                          engineer who will do the remediation.

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
        # --- Executive Summary ---
        + '<h1 class="part">Executive Summary</h1>'
        + _risk_banner_html(summary)
        + _summary_html(summary)
        + _executive_top_risks_html(summary)
        # --- Technical Findings ---
        + '<h1 class="part">Technical Findings</h1>'
        + _top_findings_html(summary)
        + _injection_html(summary)
        + _compliance_html(summary)
        + _details_html(summary)
        + '<div class="footer">Generated by Aegis Scanner — '
          "modular vulnerability assessment framework</div>"
        "</body></html>"
    )


def _resolve_output_path(target: str, output_path: str = None,
                         profile: str = None, scan_id=None) -> str:
    """
    Decide where the PDF goes.

    Mirrors report_txt._resolve_output_path exactly, so the .txt and .pdf
    for one scan are always a matching pair that retention.py can list and
    prune as a unit: default is
    config.output_dir(target)/report_<profile>_<target>_<scan_id>.pdf,
    falling back to the historical fixed report.pdf when the profile or
    scan_id is unknown. An explicit path has its parent directory created
    so the caller does not have to.
    """
    if not output_path:
        directory = output_dir(target)
        if profile and scan_id is not None:
            return os.path.join(directory, report_filename(profile, target, scan_id, "pdf"))
        return os.path.join(directory, _DEFAULT_FILENAME)

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
        path = _resolve_output_path(
            target, output_path,
            profile=metadata.get("profile"), scan_id=metadata.get("id", scan_id),
        )
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
