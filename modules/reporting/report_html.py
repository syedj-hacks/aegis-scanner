"""
modules/reporting/report_html.py
Self-contained HTML report for a finished scan.

Self-contained, literally
-------------------------
One file, no network. Every byte of CSS and JavaScript is inline, the donut
chart is hand-written SVG rather than a charting library, and the sort/
filter logic is about sixty lines of vanilla JS. Nothing is fetched from a
CDN at render time.

That is a requirement, not a preference. These reports are produced on an
assessment machine and read later — attached to an email, opened on an
air-gapped review box, archived alongside the engagement. A report whose
styling silently disappears when a CDN is unreachable, or which phones out
to a third party every time an assessor opens it, is not a deliverable.

Every value is escaped
----------------------
Findings contain raw tool output: nikto descriptions, gobuster paths, ZAP
alert prose, whatweb banners. That text routinely contains <, > and & — a
discovered path is literally attacker-influenced content — so nothing is
interpolated into markup as a string. The findings are serialised with
json.dumps into a <script type="application/json"> block (with the three
characters that can break out of a script element escaped), and the table
is built with textContent from there. Header values that do go into markup
go through html.escape().

The report reads a scan back out of the database, so it is not tied to the
run that produced it: any scan_id, any time.
"""

import html
import json
import os
from datetime import datetime

from modules.utils.config import output_dir
from modules.utils.display import print_error, print_success
from modules.utils.logger import get_logger
from modules.reporting.summary import build_summary, FINDING_TYPE_TOOL
from database.db import get_recon_data

_FALLBACK_TARGET = "unknown"

# Kali-ish dark palette. Defined once here and referenced by both this
# module and dashboard_live.py's template so the live view and the final
# report are recognisably the same artefact.
THEME = {
    "bg": "#1a1a2e",
    "panel": "#16213e",
    "panel_alt": "#0f3460",
    "accent": "#e94560",
    "text": "#e8e8f0",
    "muted": "#8b8ba7",
    "border": "#2a2a4a",
    "critical": "#e94560",
    "high": "#f47b20",
    "medium": "#f5c518",
    "low": "#4ecca3",
}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Serialising JSON into an HTML <script> block: these three sequences are
# the ones that can terminate the element early or start a comment, and
# escaping them as unicode escapes keeps the JSON valid while making it
# inert as markup. Without this a finding whose description contained the
# literal text "</script>" — which a discovered path or a nikto line can —
# would break the page open.
def _json_for_script(data) -> str:
    return (
        json.dumps(data, default=str)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _severity_counts(summary: dict) -> dict:
    counts = summary.get("by_severity") or {}
    return {name: int(counts.get(name, 0) or 0) for name in _SEVERITY_ORDER}


def _donut_svg(counts: dict, size: int = 190, thickness: int = 26) -> str:
    """
    A severity donut as raw SVG arcs — no charting library.

    Drawn with stroke-dasharray on concentric circles rather than path
    arcs: each segment is one <circle> with a dash pattern sized to its
    share and an offset placing it after the previous one, which is both
    shorter than computing arc endpoints and immune to the large-arc-flag
    edge case that makes a hand-rolled 100%-of-one-colour pie disappear.

    Renders an explicit empty state when there are no findings — a donut
    with no segments is an invisible chart, which reads as a broken page
    rather than as good news.
    """
    total = sum(counts.values())
    radius = (size - thickness) / 2
    centre = size / 2
    circumference = 2 * 3.141592653589793 * radius

    if not total:
        return (
            f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'role="img" aria-label="No findings">'
            f'<circle cx="{centre}" cy="{centre}" r="{radius}" fill="none" '
            f'stroke="{THEME["border"]}" stroke-width="{thickness}"/>'
            f'<text x="{centre}" y="{centre - 4}" text-anchor="middle" '
            f'fill="{THEME["muted"]}" font-size="15" font-family="monospace">no</text>'
            f'<text x="{centre}" y="{centre + 14}" text-anchor="middle" '
            f'fill="{THEME["muted"]}" font-size="15" font-family="monospace">findings</text>'
            f"</svg>"
        )

    segments = []
    offset = 0.0
    for name in _SEVERITY_ORDER:
        value = counts.get(name, 0)
        if not value:
            continue
        length = circumference * value / total
        segments.append(
            f'<circle cx="{centre}" cy="{centre}" r="{radius:.2f}" fill="none" '
            f'stroke="{THEME[name.lower()]}" stroke-width="{thickness}" '
            f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {centre} {centre})">'
            f"<title>{html.escape(name)}: {value}</title></circle>"
        )
        offset += length

    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
        f'role="img" aria-label="Findings by severity">'
        f'<circle cx="{centre}" cy="{centre}" r="{radius:.2f}" fill="none" '
        f'stroke="{THEME["border"]}" stroke-width="{thickness}"/>'
        + "".join(segments)
        + f'<text x="{centre}" y="{centre - 2}" text-anchor="middle" '
        f'fill="{THEME["text"]}" font-size="30" font-family="monospace" '
        f'font-weight="bold">{total}</text>'
        f'<text x="{centre}" y="{centre + 18}" text-anchor="middle" '
        f'fill="{THEME["muted"]}" font-size="12" font-family="monospace">findings</text>'
        f"</svg>"
    )


def _table_rows(findings: list) -> list:
    """
    Flatten findings into the exact records the client-side table renders.

    Done here rather than in JS so the page ships one clean shape and the
    browser does no interpretation of database columns. `tool` comes from
    the same FINDING_TYPE_TOOL map the TXT and PDF reports use, so all
    three reports credit a finding to the same tool.
    """
    rows = []
    for finding in findings or []:
        finding_type = str(finding.get("finding_type") or "").strip()
        rows.append({
            "severity": str(finding.get("severity") or "LOW").upper(),
            "port": finding.get("port"),
            "service": finding.get("service") or "",
            "type": finding_type,
            "tool": FINDING_TYPE_TOOL.get(finding_type, ""),
            "cve": finding.get("cve_id") or "",
            "cvss": finding.get("cvss"),
            "description": " ".join(str(finding.get("description") or "").split()),
            "remediation": " ".join(str(finding.get("remediation") or "").split()),
            "reference": finding.get("reference") or "",
            "endpoint": finding.get("endpoint") or "",
            "evidence": " ".join(str(finding.get("evidence") or "").split()),
        })
    return rows


# A passive recon run against a popular domain legitimately returns tens of
# thousands of subdomains (23,330 for example.com, measured). Rendering all
# of them inline produces a multi-megabyte page that takes seconds to lay
# out and that nobody scrolls to the bottom of. The section shows the first
# _MAX_RECON_ROWS and states the true total, so the number is never
# understated even when the list is.
_MAX_RECON_ROWS = 250


def _recon_section(recon: dict) -> str:
    """
    The recon mapper's own section, rendered only when the scan has recon
    rows. Every other profile produces none, so this returns "" and the
    section does not appear at all rather than appearing empty.
    """
    subdomains = recon.get("subdomains") or []
    buckets = recon.get("buckets") or []
    leaks = recon.get("leaks") or []
    if not (subdomains or buckets or leaks):
        return ""

    def _cells(rows, columns):
        body = []
        for row in rows[:_MAX_RECON_ROWS]:
            body.append(
                "<tr>"
                + "".join(
                    f"<td>{html.escape(str(row.get(c) or '—'))}</td>" for c in columns
                )
                + "</tr>"
            )
        if len(rows) > _MAX_RECON_ROWS:
            body.append(
                f"<tr><td colspan='{len(columns)}' class='truncated'>"
                f"… and {len(rows) - _MAX_RECON_ROWS:,} more not shown here — "
                "the full list is in this scan's recon_subdomains table"
                "</td></tr>"
            )
        return "".join(body)

    blocks = []
    if subdomains:
        blocks.append(
            "<h3>Subdomains <span class='count'>%s</span></h3>"
            "<table class='mini'><thead><tr><th>Hostname</th><th>Source</th></tr></thead>"
            "<tbody>%s</tbody></table>"
            % (f"{len(subdomains):,}", _cells(subdomains, ("subdomain", "source")))
        )
    if buckets:
        blocks.append(
            "<h3>Cloud storage <span class='count'>%d</span></h3>"
            "<p class='note'>A keyword match is not proof of ownership — the cloud "
            "storage namespace is global. Confirm before acting.</p>"
            "<table class='mini'><thead><tr><th>URL</th><th>Provider</th>"
            "<th>Access</th></tr></thead><tbody>%s</tbody></table>"
            % (len(buckets), _cells(buckets, ("bucket_url", "provider", "access")))
        )
    if leaks:
        blocks.append(
            "<h3>Breached addresses <span class='count'>%d</span></h3>"
            "<table class='mini'><thead><tr><th>Email</th><th>Breach</th>"
            "<th>Date</th></tr></thead><tbody>%s</tbody></table>"
            % (len(leaks), _cells(leaks, ("email", "breach_name", "breach_date")))
        )

    return (
        "<section class='card'><h2>Recon — attack surface</h2>"
        + "".join(blocks)
        + "</section>"
    )


def _render_html(summary: dict, recon: dict, duration=None) -> str:
    metadata = summary.get("scan_metadata") or {}
    target = metadata.get("target") or _FALLBACK_TARGET
    profile = metadata.get("profile") or "unknown"
    timestamp = metadata.get("timestamp") or ""
    scan_id = metadata.get("id") or summary.get("scan_id")

    counts = _severity_counts(summary)
    rows = _table_rows(summary.get("findings"))

    duration_text = f"{duration:.1f}s" if isinstance(duration, (int, float)) else "—"

    tiles = "".join(
        f"<div class='tile {name.lower()}'>"
        f"<div class='tile-n'>{counts[name]}</div>"
        f"<div class='tile-l'>{name}</div></div>"
        for name in _SEVERITY_ORDER
    )

    legend = "".join(
        f"<li><span class='swatch' style='background:{THEME[name.lower()]}'></span>"
        f"{name} <b>{counts[name]}</b></li>"
        for name in _SEVERITY_ORDER
    )

    return _TEMPLATE.format(
        target=html.escape(str(target)),
        profile=html.escape(str(profile)),
        timestamp=html.escape(str(timestamp)),
        scan_id=html.escape(str(scan_id)),
        duration=html.escape(duration_text),
        total=summary.get("total_findings", 0),
        tiles=tiles,
        donut=_donut_svg(counts),
        legend=legend,
        recon_section=_recon_section(recon),
        findings_json=_json_for_script(rows),
        generated=html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        **{f"c_{k}": v for k, v in THEME.items()},
    )


def generate_html_report(scan_id, output_path: str = None, duration=None) -> str:
    """
    Generate the HTML report for a persisted scan.

    Parameters
    ----------
    scan_id     : int   id of a row in the scans table
    output_path : str   optional explicit destination; defaults to
                        output/<target>/report.html
    duration    : float optional wall-clock seconds, shown in the header.
                        The database does not record scan duration, so this
                        is passed in by a caller that measured it and shown
                        as "—" otherwise rather than being invented.

    Returns
    -------
    str | None — the path written, or None if it could not be produced.
    Never raises: same contract as generate_txt_report(), because a
    reporting failure must not turn a successful scan into a failed one.
    """
    summary = build_summary(scan_id, quiet=True)
    metadata = summary.get("scan_metadata") or {}
    target = metadata.get("target") or _FALLBACK_TARGET
    logger = get_logger(target)

    if summary.get("error"):
        logger.error(f"[Report] html report aborted for scan_id={scan_id}: {summary['error']}")
        print_error(f"[Report] cannot generate an HTML report: {summary['error']}")
        return None

    try:
        recon = get_recon_data(scan_id)
    except Exception:
        recon = {"subdomains": [], "buckets": [], "leaks": []}

    try:
        body = _render_html(summary, recon, duration=duration)
    except Exception as exc:
        logger.error(f"[Report] failed to render html report for scan {scan_id}: {exc}")
        print_error(f"[Report] failed to render the HTML report: {exc}")
        return None

    if output_path is None:
        try:
            output_path = os.path.join(output_dir(target), "report.html")
        except OSError as exc:
            logger.error(f"[Report] could not create the output directory: {exc}")
            print_error(f"[Report] could not create the output directory: {exc}")
            return None

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as exc:
        logger.error(f"[Report] could not write {output_path}: {exc}")
        print_error(f"[Report] could not write the HTML report: {exc}")
        return None

    print_success(f"[Report] HTML report written to {output_path}")
    return output_path


# --- The page ------------------------------------------------------------
# str.format is used to fill this, so every literal brace in the CSS and JS
# below is doubled. That is the one maintenance cost of keeping the whole
# page in one place; the alternative (a separate template file) would break
# the "one self-contained module" property this file exists for.
_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis Scanner — {target} ({profile})</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0 0 60px;
    background: {c_bg}; color: {c_text};
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.5;
  }}
  header {{
    background: linear-gradient(135deg, {c_panel} 0%, {c_panel_alt} 100%);
    border-bottom: 3px solid {c_accent};
    padding: 26px 32px;
  }}
  header h1 {{ margin: 0 0 4px; font-size: 22px; letter-spacing: .5px; }}
  header h1 .accent {{ color: {c_accent}; }}
  header .target {{ font-family: monospace; font-size: 28px; font-weight: 700; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 26px; margin-top: 12px;
           font-size: 13px; color: {c_muted}; }}
  .meta b {{ color: {c_text}; font-family: monospace; font-weight: 600; }}
  main {{ max-width: 1180px; margin: 0 auto; padding: 26px 20px; }}
  .card {{
    background: {c_panel}; border: 1px solid {c_border};
    border-radius: 10px; padding: 22px; margin-bottom: 22px;
  }}
  .card h2 {{ margin: 0 0 16px; font-size: 15px; text-transform: uppercase;
              letter-spacing: 1.4px; color: {c_muted}; font-weight: 600; }}
  .card h3 {{ margin: 22px 0 8px; font-size: 14px; color: {c_text}; }}
  .card h3:first-of-type {{ margin-top: 4px; }}
  .count {{ background: {c_panel_alt}; color: {c_muted}; border-radius: 10px;
            padding: 1px 9px; font-size: 12px; margin-left: 6px; }}
  .note {{ color: {c_muted}; font-size: 12px; margin: 0 0 8px; }}

  .overview {{ display: flex; gap: 26px; flex-wrap: wrap; align-items: center; }}
  .tiles {{ display: grid; grid-template-columns: repeat(4, 1fr);
            gap: 12px; flex: 1 1 420px; }}
  .tile {{ border-radius: 8px; padding: 16px 12px; text-align: center;
           background: {c_panel_alt}; border-left: 4px solid {c_border}; }}
  .tile-n {{ font-size: 32px; font-weight: 700; font-family: monospace;
             line-height: 1; }}
  .tile-l {{ font-size: 11px; letter-spacing: 1.2px; color: {c_muted};
             margin-top: 6px; }}
  .tile.critical {{ border-left-color: {c_critical}; }}
  .tile.critical .tile-n {{ color: {c_critical}; }}
  .tile.high {{ border-left-color: {c_high}; }}
  .tile.high .tile-n {{ color: {c_high}; }}
  .tile.medium {{ border-left-color: {c_medium}; }}
  .tile.medium .tile-n {{ color: {c_medium}; }}
  .tile.low {{ border-left-color: {c_low}; }}
  .tile.low .tile-n {{ color: {c_low}; }}
  .chart {{ display: flex; align-items: center; gap: 18px; }}
  .legend {{ list-style: none; margin: 0; padding: 0; font-size: 13px; }}
  .legend li {{ margin: 5px 0; color: {c_muted}; }}
  .legend b {{ color: {c_text}; font-family: monospace; margin-left: 4px; }}
  .swatch {{ display: inline-block; width: 11px; height: 11px;
             border-radius: 2px; margin-right: 7px; }}

  .controls {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }}
  .controls input, .controls select {{
    background: {c_bg}; color: {c_text}; border: 1px solid {c_border};
    border-radius: 6px; padding: 8px 11px; font-size: 13px; font-family: inherit;
  }}
  .controls input {{ flex: 1 1 260px; }}
  .controls input:focus, .controls select:focus {{
    outline: none; border-color: {c_accent};
  }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 9px 10px;
            border-bottom: 1px solid {c_border}; vertical-align: top; }}
  th {{ color: {c_muted}; font-size: 11px; text-transform: uppercase;
        letter-spacing: .9px; user-select: none; }}
  th.sortable {{ cursor: pointer; }}
  th.sortable:hover {{ color: {c_accent}; }}
  th .arrow {{ opacity: .45; font-size: 10px; }}
  tbody tr:hover {{ background: rgba(255,255,255,.03); }}
  td.mono {{ font-family: monospace; }}
  table.mini td {{ font-family: monospace; font-size: 12px; }}

  .sev {{ display: inline-block; min-width: 74px; text-align: center;
          padding: 2px 8px; border-radius: 4px; font-size: 11px;
          font-weight: 700; letter-spacing: .6px; font-family: monospace; }}
  .sev.CRITICAL {{ background: {c_critical}; color: #fff; }}
  .sev.HIGH {{ background: {c_high}; color: #1a1a2e; }}
  .sev.MEDIUM {{ background: {c_medium}; color: #1a1a2e; }}
  .sev.LOW {{ background: {c_low}; color: #1a1a2e; }}

  .desc {{ max-width: 520px; }}
  .rem {{ color: {c_muted}; font-size: 12px; margin-top: 5px;
          padding-left: 9px; border-left: 2px solid {c_border}; }}
  .rem b {{ color: {c_low}; font-weight: 600; }}
  .empty {{ text-align: center; color: {c_muted}; padding: 34px; }}
  td.truncated {{ color: {c_muted}; font-style: italic; text-align: center; }}
  footer {{ text-align: center; color: {c_muted}; font-size: 12px;
            padding: 26px 20px 0; }}
  footer .accent {{ color: {c_accent}; }}
</style>
</head>
<body>
<header>
  <h1><span class="accent">AEGIS</span> SCANNER — vulnerability report</h1>
  <div class="target">{target}</div>
  <div class="meta">
    <span>profile <b>{profile}</b></span>
    <span>scan <b>#{scan_id}</b></span>
    <span>started <b>{timestamp}</b></span>
    <span>duration <b>{duration}</b></span>
    <span>findings <b>{total}</b></span>
  </div>
</header>

<main>
  <section class="card">
    <h2>Severity overview</h2>
    <div class="overview">
      <div class="tiles">{tiles}</div>
      <div class="chart">
        {donut}
        <ul class="legend">{legend}</ul>
      </div>
    </div>
  </section>

  {recon_section}

  <section class="card">
    <h2>Findings</h2>
    <div class="controls">
      <input id="q" type="search" placeholder="Filter by description, CVE, service, port or tool…">
      <select id="sev">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <select id="type"><option value="">All types</option></select>
    </div>
    <table>
      <thead><tr>
        <th class="sortable" data-k="severity">Severity <span class="arrow">&#9650;</span></th>
        <th class="sortable" data-k="port">Port <span class="arrow"></span></th>
        <th class="sortable" data-k="service">Service <span class="arrow"></span></th>
        <th class="sortable" data-k="type">Type <span class="arrow"></span></th>
        <th class="sortable" data-k="cve">CVE <span class="arrow"></span></th>
        <th>Description</th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div id="empty" class="empty" hidden>No findings match this filter.</div>
  </section>
</main>

<footer>
  Generated by <span class="accent">Aegis Scanner</span> on {generated} —
  self-contained report, no external resources.
</footer>

<script type="application/json" id="data">{findings_json}</script>
<script>
(function () {{
  "use strict";
  var ALL = JSON.parse(document.getElementById("data").textContent || "[]");
  var RANK = {{ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }};
  var tbody = document.getElementById("rows");
  var empty = document.getElementById("empty");
  var q = document.getElementById("q");
  var sev = document.getElementById("sev");
  var typeSel = document.getElementById("type");
  var sortKey = "severity", sortAsc = true;

  // Populate the type filter from the data rather than hardcoding a list:
  // the finding types present depend on which profile ran.
  var types = ALL.map(function (r) {{ return r.type; }})
                 .filter(function (t, i, a) {{ return t && a.indexOf(t) === i; }})
                 .sort();
  types.forEach(function (t) {{
    var o = document.createElement("option");
    o.value = t; o.textContent = t;
    typeSel.appendChild(o);
  }});

  function haystack(r) {{
    return [r.description, r.cve, r.service, r.type, r.tool, r.endpoint, r.port]
      .join(" ").toLowerCase();
  }}

  function compare(a, b) {{
    var x, y;
    if (sortKey === "severity") {{
      x = RANK[a.severity]; y = RANK[b.severity];
      if (x === undefined) x = 9;
      if (y === undefined) y = 9;
    }} else if (sortKey === "port") {{
      x = a.port === null || a.port === undefined ? Infinity : Number(a.port);
      y = b.port === null || b.port === undefined ? Infinity : Number(b.port);
    }} else {{
      x = String(a[sortKey] || "").toLowerCase();
      y = String(b[sortKey] || "").toLowerCase();
    }}
    if (x < y) return sortAsc ? -1 : 1;
    if (x > y) return sortAsc ? 1 : -1;
    return 0;
  }}

  // textContent everywhere, never innerHTML: these strings are raw tool
  // output and must never be parsed as markup.
  function cell(row, text, cls) {{
    var td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = text;
    row.appendChild(td);
    return td;
  }}

  function render() {{
    var needle = q.value.trim().toLowerCase();
    var wantSev = sev.value, wantType = typeSel.value;

    var rows = ALL.filter(function (r) {{
      if (wantSev && r.severity !== wantSev) return false;
      if (wantType && r.type !== wantType) return false;
      if (needle && haystack(r).indexOf(needle) === -1) return false;
      return true;
    }}).sort(compare);

    tbody.textContent = "";
    rows.forEach(function (r) {{
      var tr = document.createElement("tr");

      var td = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "sev " + r.severity;
      badge.textContent = r.severity;
      td.appendChild(badge);
      tr.appendChild(td);

      cell(tr, r.port === null || r.port === undefined ? "—" : String(r.port), "mono");
      cell(tr, r.service || "—", "mono");
      cell(tr, r.type || "—", "mono");
      cell(tr, r.cve || "—", "mono");

      var desc = document.createElement("td");
      desc.className = "desc";
      var main = document.createElement("div");
      main.textContent = r.description || "—";
      desc.appendChild(main);
      if (r.remediation) {{
        var rem = document.createElement("div");
        rem.className = "rem";
        var lab = document.createElement("b");
        lab.textContent = "Fix: ";
        rem.appendChild(lab);
        rem.appendChild(document.createTextNode(r.remediation));
        desc.appendChild(rem);
      }}
      tr.appendChild(desc);
      tbody.appendChild(tr);
    }});

    empty.hidden = rows.length !== 0;
  }}

  document.querySelectorAll("th.sortable").forEach(function (th) {{
    th.addEventListener("click", function () {{
      var k = th.getAttribute("data-k");
      if (k === sortKey) {{ sortAsc = !sortAsc; }} else {{ sortKey = k; sortAsc = true; }}
      document.querySelectorAll("th.sortable .arrow").forEach(function (a) {{
        a.textContent = "";
      }});
      th.querySelector(".arrow").textContent = sortAsc ? "\\u25B2" : "\\u25BC";
      render();
    }});
  }});

  q.addEventListener("input", render);
  sev.addEventListener("change", render);
  typeSel.addEventListener("change", render);
  render();
}})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print_error("Usage: python -m modules.reporting.report_html <scan_id>")
        sys.exit(1)
    print(generate_html_report(int(sys.argv[1])))
