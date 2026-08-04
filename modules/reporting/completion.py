"""
modules/reporting/completion.py
End-of-scan report banner for Aegis Scanner (reporting layer).

Every profile finishes by writing a .txt and a .pdf and printing a summary
panel of severity counts. What it did *not* print was where those two files
went, or anything about what was actually in them beyond four numbers — so
the last thing an operator saw was "9 findings" and a scrollback they had
to hunt through to find the path.

This module renders one clearly separated block, after everything else, that
answers the three questions someone actually has at the end of a run:

    what was found, what kind of thing was it, and where do I read it

    +- REPORT GENERATED -----------------------------------------
    | Profile: deepscan   Target: scanme.nmap.org   Scan: 115
    | Findings: 41 total (1 HIGH, 10 MEDIUM, 30 LOW)
    | Notable: 2 CVEs, 7 ZAP alerts, 13 discovered paths
    | TXT: output/.../report_deepscan_scanme.nmap.org_115.txt
    | PDF: output/.../report_deepscan_scanme.nmap.org_115.pdf
    | HTML: output/.../report.html
    +------------------------------------------------------------

Paths are emitted as OSC 8 terminal hyperlinks over a file:// URI, so a
terminal that supports them (most modern ones do) opens the report on
click. Terminals that do not support OSC 8 ignore the escape and show the
plain path, so nothing is lost — which is why the path is always written
out in full rather than hidden behind link text.

All console output goes through display.py, per the project convention;
this module contains no print().
"""

import os
from urllib.parse import quote

from modules.utils.display import print_panel, print_warning
from modules.utils.logger import get_logger
from modules.enrichment.severity import SEVERITY_LEVELS
from modules.reporting.summary import profile_scope_note

_FALLBACK_TARGET = "reporting"

# Panel border colour by worst severity present, matching display.py's
# terminal severity scheme so the block reads the same way as the findings
# table above it.
_BORDER_STYLES = {
    "CRITICAL": "red",
    "HIGH": "orange3",
    "MEDIUM": "yellow",
    "LOW": "green",
}
_DEFAULT_BORDER = "cyan"


def _border_style(by_severity: dict) -> str:
    """Colour the panel by the worst tier that actually occurred."""
    for level in SEVERITY_LEVELS:
        if (by_severity or {}).get(level, 0):
            return _BORDER_STYLES.get(level, _DEFAULT_BORDER)
    return _DEFAULT_BORDER

# How many distinct finding types the "Notable" line names before it gives
# up and counts the rest. Four is about what fits on one terminal line.
_MAX_NOTABLE_TYPES = 4

# Human-readable singular/plural for the finding types the profiles
# produce. A type with no entry here falls back to its raw name with
# underscores replaced, which reads acceptably ("smb share") — the table
# exists to make the common cases read like English ("2 CVEs" rather than
# "2 cves"), not to be exhaustive.
_TYPE_LABELS = {
    "banner": ("service banner", "service banners"),
    "cve": ("CVE", "CVEs"),
    "discovered_path": ("discovered path", "discovered paths"),
    "fingerprint_header": ("fingerprint header", "fingerprint headers"),
    "missing_security_header": ("missing security header", "missing security headers"),
    "nikto_finding": ("nikto finding", "nikto findings"),
    "nmap_script": ("nmap script result", "nmap script results"),
    "nuclei_finding": ("nuclei match", "nuclei matches"),
    "open_port": ("open port", "open ports"),
    "service_version": ("service version", "service versions"),
    "smb_share": ("SMB share", "SMB shares"),
    "smb_user": ("SMB user", "SMB users"),
    "sqlmap_finding": ("SQL injection", "SQL injections"),
    "technology_fingerprint": ("technology fingerprint", "technology fingerprints"),
    "weak_credentials": ("weak credential", "weak credentials"),
    "wordpress_fingerprinted": ("WordPress fingerprint", "WordPress fingerprints"),
    "xss_finding": ("reflected XSS", "reflected XSS findings"),
    "zap_finding": ("ZAP alert", "ZAP alerts"),
}


# Rows written before the finding_type migration have a NULL finding_type.
# They are real findings (the service/version rows quickscan persists), so
# they are counted and named rather than called "unknown", which reads like
# something went wrong.
_UNTYPED_LABEL = ("unclassified finding", "unclassified findings")


def _label_for(finding_type: str, count: int) -> str:
    if finding_type in ("unknown", "None", ""):
        singular, plural = _UNTYPED_LABEL
    else:
        singular, plural = _TYPE_LABELS.get(
            finding_type,
            (str(finding_type).replace("_", " "), str(finding_type).replace("_", " ")),
        )
    return singular if count == 1 else plural


def notable_types(findings: list, limit: int = _MAX_NOTABLE_TYPES) -> str:
    """
    "2 CVEs, 7 ZAP alerts, 13 discovered paths" — what the scan actually
    turned up, as a phrase.

    Ordered by severity of the worst finding of each type first and count
    second, so a single CRITICAL Redis exposure is named ahead of forty
    LOW discovered paths. A bare total ("41 findings") tells an operator
    nothing about whether to care; this line is the one that does.
    """
    if not findings:
        return ""

    tiers = {}
    counts = {}
    for finding in findings:
        finding_type = str(finding.get("finding_type") or "unknown")
        counts[finding_type] = counts.get(finding_type, 0) + 1

        severity = str(finding.get("severity") or "LOW").upper()
        tier = SEVERITY_LEVELS.index(severity) if severity in SEVERITY_LEVELS else len(SEVERITY_LEVELS)
        tiers[finding_type] = min(tiers.get(finding_type, len(SEVERITY_LEVELS)), tier)

    ordered = sorted(counts.items(), key=lambda kv: (tiers[kv[0]], -kv[1], kv[0]))

    named = ordered[: max(1, limit)]
    parts = [f"{count} {_label_for(finding_type, count)}" for finding_type, count in named]

    remaining = len(ordered) - len(named)
    if remaining > 0:
        remaining_count = sum(count for _, count in ordered[len(named):])
        parts.append(f"{remaining_count} more across {remaining} other type(s)")

    return ", ".join(parts)


def severity_phrase(by_severity: dict) -> str:
    """
    "1 HIGH, 10 MEDIUM, 30 LOW" — only the tiers that actually occurred.

    Empty tiers are omitted rather than printed as zeroes: "0 CRITICAL" is
    noise on a line whose job is to be read at a glance. The full
    four-tier breakdown including zeroes is still in the summary panel
    immediately above and in the report itself.
    """
    present = [
        f"{(by_severity or {}).get(level, 0)} {level}"
        for level in SEVERITY_LEVELS
        if (by_severity or {}).get(level, 0)
    ]
    return ", ".join(present)


def file_link(path: str) -> str:
    """
    A path rendered as an OSC 8 hyperlink to its file:// URI.

    Rich understands the [link=...] markup and emits the escape sequence
    for terminals that support it; on terminals that do not, the visible
    text is the plain path, which is exactly what someone would want to
    copy anyway. Returns the bare path if the URI cannot be built, since a
    broken link is worse than no link.

    The *link target* is always absolute — a file:// URI has to be — but
    the *visible* text is relative to the working directory when the file
    is underneath it. A report path is long enough to wrap onto three
    terminal lines in absolute form, which defeats the point of putting it
    in a panel; "output/host/report_quickscan_host_117.txt" is both
    shorter and the form someone would actually type.
    """
    try:
        absolute = os.path.abspath(path)
        uri = "file://" + quote(absolute)

        shown = absolute
        try:
            relative = os.path.relpath(absolute, os.getcwd())
            # Only when it really is below the cwd — a "../../.." chain is
            # less readable than the absolute path it replaced.
            if not relative.startswith(os.pardir):
                shown = relative
        except (OSError, ValueError):
            pass

        return f"[link={uri}]{shown}[/link]"
    except Exception:
        return str(path)


def print_report_summary(target: str, profile: str, scan_id, summary: dict,
                         txt_path: str = None, pdf_path: str = None,
                         html_path: str = None) -> None:
    """
    Render the end-of-scan REPORT GENERATED block.

    Parameters
    ----------
    summary  : the dict build_summary() returned — read for the severity
               counts and the finding list, so this never re-queries the
               database and never disagrees with the report it points at.
    txt_path,
    pdf_path,
    html_path: what the writers returned. Any may be None if that writer
               failed; the block says so explicitly rather than omitting
               the line, because a missing report is exactly the thing an
               operator needs told.

               html_path is listed for the same reason it is generated: a
               report nobody is told about is a report nobody opens, and
               the HTML one is the only sortable, filterable view of the
               findings.

    Never raises. This is the last thing a scan does; a formatting problem
    here must not turn a completed scan into a failed one.
    """
    logger = get_logger(target or _FALLBACK_TARGET)

    try:
        by_severity = (summary or {}).get("by_severity") or {}
        findings = (summary or {}).get("findings") or []
        total = (summary or {}).get("total_findings", len(findings))

        lines = [
            f"[bold]Profile:[/bold] {profile}    "
            f"[bold]Target:[/bold] {target}    "
            f"[bold]Scan:[/bold] {scan_id}",
        ]

        breakdown = severity_phrase(by_severity)
        lines.append(
            f"[bold]Findings:[/bold] {total} total"
            + (f" ({breakdown})" if breakdown else "")
        )

        notable = notable_types(findings)
        if notable:
            lines.append(f"[bold]Notable:[/bold] {notable}")

        for label, path in (("TXT", txt_path), ("PDF", pdf_path),
                            ("HTML", html_path)):
            if path:
                lines.append(f"[bold]{label}:[/bold] {file_link(path)}")
            else:
                lines.append(f"[bold]{label}:[/bold] [red]not generated — see errors above[/red]")

        # The same scope statement the report itself carries, from the same
        # source. The operator reading this panel has usually not opened the
        # report yet, and this is the moment where "6 MEDIUM, 24 LOW" could
        # otherwise be read as the whole story for the host.
        scope_note = profile_scope_note(profile)
        if scope_note:
            lines.append(f"[bold]Scope:[/bold] {scope_note}")

        # A bordered panel rather than loose lines: this block has to be
        # findable in a scrollback holding hundreds of tool-output lines,
        # and the border is what makes it scannable. Severity drives the
        # colour, so a run that found something critical does not look
        # like a run that found nothing.
        print_panel(
            "\n".join(lines),
            title="REPORT GENERATED",
            style=_border_style(by_severity),
        )

        logger.info(
            f"[Report] scan {scan_id} ({profile}/{target}) complete: "
            f"{total} finding(s) [{breakdown or 'none'}]; "
            f"txt={txt_path or 'FAILED'} pdf={pdf_path or 'FAILED'} "
            f"html={html_path or 'FAILED'}"
        )
    except Exception as exc:
        logger.warning(f"[Report] could not render the completion summary: {exc}")
        print_warning(f"[Report] could not render the report summary: {exc}")
