"""
modules/reporting/summary.py
Report data layer for Aegis Scanner (reporting layer).

This is the single place that turns a persisted scan into the structure the
report writers render. report_txt.py and report_pdf.py both call
build_summary() rather than touching database/db.py themselves, so the
grouping, sorting and severity rules live in exactly one file.

    db.get_scan_history() / db.get_findings_for_scan()
        -> build_summary(scan_id)
            -> report_txt.generate_txt_report()
            -> report_pdf.generate_pdf_report()

Severity: stored, not re-derived
--------------------------------
database/db.py's findings table persists only
(port, service, version, cve_id, cvss, severity) — the shape-specific
context the enrichment layer graded on (a nikto description, a missing
header name, a gobuster path) is not stored. Re-running
severity.score_finding() over a row read back from SQLite would therefore
regrade it from the columns that survived, and a CRITICAL nikto backdoor
finding recorded on port 80 would come back MEDIUM — the grade the port
alone deserves. The stored severity is the authoritative record of what the
scan actually concluded, so it is trusted here and only passed through
severity.normalise_severity() to guarantee it sits on the four-tier scale
(a NULL or unexpected label from an older row becomes LOW rather than
breaking the grouping).

Remediation: re-derived, deliberately
-------------------------------------
Remediation text is not a column, so it is regenerated at report time via
remediation.remediation_text(). That is the right behaviour anyway — a
report generated today reflects today's guidance tables. The same lossiness
applies: guidance for a row is only as specific as the columns that
survived, so a stored missing-header finding is advised on by port rather
than by header name.

This module performs no I/O beyond the SQLite reads db.py owns, so there is
nothing here to wrap in run_tool()/safe_call().
"""

from modules.utils.display import print_info, print_warning, print_error
from modules.utils.logger import get_logger
from modules.enrichment.severity import SEVERITY_LEVELS, normalise_severity
from modules.enrichment.remediation import remediation_text
from database.db import get_scan_history, get_findings_for_scan

# How many findings top_findings carries by default. Enough to fill an
# executive summary block without reprinting the whole findings list, which
# the reports render in full immediately afterwards.
_DEFAULT_TOP_N = 10

# Target used to route log lines when the scan_id has no target to name
# (an unknown scan_id, or a scans row with a NULL target).
_FALLBACK_TARGET = "reporting"


def _sort_key(finding: dict):
    """
    Worst-first ordering: severity tier, then CVSS descending, then port.

    Mirrors display.print_table's severity-first ordering so the file
    reports and the terminal table list findings in the same sequence. CVSS
    is the tie-break within a tier because a 9.8 and a 7.1 are both HIGH-
    or-worse but are not equally urgent; unscored findings sort last within
    their tier rather than being treated as 0.0.
    """
    severity = normalise_severity(finding.get("severity"))
    tier = SEVERITY_LEVELS.index(severity) if severity in SEVERITY_LEVELS else len(SEVERITY_LEVELS)

    try:
        score = float(finding.get("cvss"))
    except (TypeError, ValueError):
        score = None

    try:
        port = int(finding.get("port"))
    except (TypeError, ValueError):
        port = 0

    return (tier, score is None, -(score or 0.0), port)


def _describe(finding: dict) -> str:
    """
    Build a one-line human description of a finding.

    db.py has no description column, so the sentence is composed from the
    columns that do exist. Kept in this module (rather than in each report
    writer) so the txt and PDF reports never drift apart in wording.
    """
    port = finding.get("port")
    service = (finding.get("service") or "").strip()
    version = (finding.get("version") or "").strip()
    cve_id = (finding.get("cve_id") or "").strip()

    where = f"port {port}" if port is not None else "an unspecified port"
    what = " ".join(part for part in (service, version) if part) or "an unidentified service"

    if cve_id:
        return f"{cve_id} affects {what} exposed on {where}."
    return f"{what[0].upper() + what[1:]} is exposed on {where}."


def _enrich(finding: dict) -> dict:
    """
    Turn one SQLite findings row into a render-ready finding.

    Returns a shallow copy — the row dict db.py handed over is never
    mutated. Severity is normalised (not regraded); description and
    remediation are derived. See the module docstring for why those two
    choices differ.
    """
    enriched = dict(finding)
    enriched["severity"] = normalise_severity(finding.get("severity"))
    enriched["severity_source"] = "cvss" if finding.get("cvss") is not None else "heuristic"
    enriched["description"] = _describe(finding)
    enriched["remediation"] = remediation_text(enriched)
    return enriched


def _empty_summary(scan_id, error: str) -> dict:
    """
    The summary returned when a scan cannot be summarised.

    Same keys as a successful summary with everything zeroed, so callers can
    render it (or check `error`) without special-casing the shape.
    """
    return {
        "scan_id": scan_id,
        "scan_metadata": {"id": scan_id, "target": None, "timestamp": None, "profile": None},
        "total_findings": 0,
        "by_severity": {level: 0 for level in SEVERITY_LEVELS},
        "findings": [],
        "top_findings": [],
        "error": error,
    }


def get_scan_metadata(scan_id) -> dict:
    """
    Look up one scans row by id.

    db.py exposes get_scan_history() (all scans) and get_latest_scan(target)
    but no get_scan(id), and this module must not modify db.py — so the
    lookup filters the history instead of issuing its own SQL. Scan history
    is a handful of rows, so scanning it is free.

    Returns the row dict, or None if no scan carries that id.
    """
    try:
        wanted = int(scan_id)
    except (TypeError, ValueError):
        return None

    for scan in get_scan_history() or []:
        if scan.get("id") == wanted:
            return scan
    return None


def count_by_severity(findings) -> dict:
    """
    Count findings per tier, as {CRITICAL, HIGH, MEDIUM, LOW}.

    Every tier is always present (0 when nothing matched) so report writers
    can render a fixed four-row table without checking for missing keys.
    """
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings or []:
        counts[normalise_severity(finding.get("severity"))] += 1
    return counts


def summary_stats(summary: dict) -> dict:
    """
    Adapt a summary to the dict display.print_summary() expects:
    {critical, high, medium, low, tools_run, tools_failed}.

    Lives here so report_txt.py and report_pdf.py share one adapter. The
    tool counters are reported as 0 — which tools ran is not persisted in
    the scans table, and inventing a number would misreport the scan.
    """
    by_severity = (summary or {}).get("by_severity") or {}
    return {
        "critical": by_severity.get("CRITICAL", 0),
        "high": by_severity.get("HIGH", 0),
        "medium": by_severity.get("MEDIUM", 0),
        "low": by_severity.get("LOW", 0),
        "tools_run": 0,
        "tools_failed": 0,
    }


def build_summary(scan_id, top_n: int = _DEFAULT_TOP_N) -> dict:
    """
    Assemble everything the report writers need for one persisted scan.

    Parameters
    ----------
    scan_id : int   id of a row in the scans table
    top_n   : int   how many findings top_findings carries (worst-first)

    Returns
    -------
    dict:
        scan_id        : int | any   the id as supplied
        scan_metadata  : dict        {id, target, timestamp, profile} from
                                     the scans table; values are None when
                                     the scan could not be found
        total_findings : int
        by_severity    : dict        {CRITICAL, HIGH, MEDIUM, LOW} counts,
                                     every key always present
        findings       : list[dict]  every finding, worst-first, each with
                                     severity, severity_source, description
                                     and remediation added
        top_findings   : list[dict]  the first `top_n` of findings
        error          : str | None  human-readable reason the summary is
                                     empty, if it is

    Never raises. An unknown scan_id, a missing database file or an
    unreadable row all come back as an empty summary with `error` set, and
    the reason is logged.
    """
    try:
        metadata = get_scan_metadata(scan_id)
    except Exception as exc:
        # A missing/corrupt aegis.db surfaces here as an sqlite3 error.
        # Reporting must degrade, not crash the framework.
        message = f"could not read scan history: {exc}"
        get_logger(_FALLBACK_TARGET).error(f"[Summary] scan_id={scan_id} — {message}")
        print_error(f"[Summary] {message}")
        return _empty_summary(scan_id, message)

    if not metadata:
        message = f"no scan found with id {scan_id}"
        get_logger(_FALLBACK_TARGET).error(f"[Summary] {message}")
        print_error(f"[Summary] {message}")
        return _empty_summary(scan_id, message)

    target = metadata.get("target") or _FALLBACK_TARGET
    logger = get_logger(target)

    try:
        rows = get_findings_for_scan(metadata["id"]) or []
    except Exception as exc:
        message = f"could not read findings: {exc}"
        logger.error(f"[Summary] scan_id={scan_id} — {message}")
        print_error(f"[Summary] {message}")
        summary = _empty_summary(scan_id, message)
        summary["scan_metadata"] = dict(metadata)
        return summary

    findings = sorted((_enrich(row) for row in rows), key=_sort_key)
    by_severity = count_by_severity(findings)

    try:
        limit = max(0, int(top_n))
    except (TypeError, ValueError):
        limit = _DEFAULT_TOP_N

    summary = {
        "scan_id": metadata["id"],
        "scan_metadata": dict(metadata),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "findings": findings,
        "top_findings": findings[:limit],
        "error": None,
    }

    if not findings:
        # Not an error: a scan that genuinely found nothing is a valid
        # result and still deserves a report saying so.
        logger.info(f"[Summary] scan {metadata['id']} ({target}) has no findings")
        print_warning(f"[Summary] scan {metadata['id']} ({target}) has no findings recorded")
        return summary

    logger.info(
        f"[Summary] scan {metadata['id']} ({target}): "
        f"{len(findings)} finding(s) {by_severity}"
    )
    print_info(
        f"[Summary] scan {metadata['id']} ({target}): {len(findings)} finding(s) — "
        + ", ".join(f"{level} {by_severity[level]}" for level in SEVERITY_LEVELS)
    )
    return summary


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        requested = sys.argv[1]
    else:
        history = get_scan_history()
        if not history:
            print_error("No scans in the database — run a scan first.")
            sys.exit(1)
        requested = history[0]["id"]

    result = build_summary(requested)
    print_info(f"Target:   {result['scan_metadata']['target']}")
    print_info(f"Profile:  {result['scan_metadata']['profile']}")
    print_info(f"Total:    {result['total_findings']}")
    print_info(f"Severity: {result['by_severity']}")
    print_info(f"Error:    {result['error'] or 'none'}")
    for entry in result["top_findings"]:
        print_info(f"  {entry['severity']:<8} {entry.get('cve_id') or '-':<16} {entry['description']}")
