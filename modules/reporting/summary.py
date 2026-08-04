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

# Finding types the report's dedicated "Injection & Scripting
# Vulnerabilities" section renders in full — with the exact payload, the
# parameter/endpoint it was sent against, and a response snippet proving
# exploitation. Deliberately just these two vulnerability classes (confirmed
# SQL injection via sqlmap, reflected XSS via nuclei DAST); the section does
# not restructure the rest of the report. The value is the human label the
# reports show for each class.
INJECTION_FINDING_TYPES = {
    "sqlmap_finding": "SQL Injection (sqlmap)",
    "xss_finding": "Reflected XSS (nuclei DAST)",
}


def injection_findings(summary: dict) -> list:
    """
    Return just the SQLi/XSS findings from a built summary, worst-first
    (summary['findings'] is already sorted).

    Reads the persisted `finding_type` column (db.py), so it works on a
    scan read back from SQLite exactly as it does on a fresh one. Both
    report writers call this so the two never disagree on what counts as an
    injection finding.
    """
    return [
        f for f in (summary.get("findings") or [])
        if str(f.get("finding_type") or "").lower() in INJECTION_FINDING_TYPES
    ]

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
    product = (finding.get("product") or "").strip()
    version = (finding.get("version") or "").strip()
    cve_id = (finding.get("cve_id") or "").strip()

    where = f"port {port}" if port is not None else "an unspecified port"
    # product (e.g. "nginx") is the most useful part of a quickscan/
    # stealthscan row — service alone is often just "http", which tells an
    # analyst nothing a port number didn't already. Shown ahead of the bare
    # service name, with service still included when it differs.
    label_parts = [p for p in (product, version) if p]
    if not label_parts:
        label_parts = [p for p in (service, version) if p]
    elif service and service.lower() != product.lower():
        label_parts.insert(0, service)
    what = " ".join(label_parts) or "an unidentified service"

    if cve_id:
        return f"{cve_id} affects {what} exposed on {where}."
    return f"{what[0].upper() + what[1:]} is exposed on {where}."


def _enrich(finding: dict) -> dict:
    """
    Turn one SQLite findings row into a render-ready finding.

    Returns a shallow copy — the row dict db.py handed over is never
    mutated. Severity is normalised (not regraded); description and
    remediation prefer the stored columns (populated at insert time since
    the description/remediation/finding_type migration) and fall back to
    the derived text below only for rows written before that migration,
    where those columns are NULL. See the module docstring for why
    severity is trusted rather than regraded.
    """
    enriched = dict(finding)
    enriched["severity"] = normalise_severity(finding.get("severity"))
    enriched["severity_source"] = "cvss" if finding.get("cvss") is not None else "heuristic"
    enriched["description"] = finding.get("description") or _describe(finding)
    enriched["remediation"] = finding.get("remediation") or remediation_text(enriched)
    return enriched


# --- Honest field labelling ----------------------------------------------
# Every report used to render an unpopulated Service / Version / CVE / CVSS
# cell as a bare "-", which collapses two completely different facts into
# one character:
#
#   "this field cannot apply to this kind of finding"  — a missing security
#       header has no CVE and never will; a dash there is not a gap.
#   "this field could apply but nothing determined it" — a nuclei match on
#       an unidentified service; a dash there IS a gap, and hides it.
#
# A reader cannot tell those apart, so the first makes the report look
# incomplete and the second makes an unknown look like a non-issue. Both are
# now labelled in words.
#
# Which tool produced each finding type. Used for the "not determined by X"
# wording, so the reader knows who to blame for the gap.
FINDING_TYPE_TOOL = {
    "banner": "banner grab",
    "cve": "NVD lookup",
    "discovered_path": "gobuster/dirb",
    "fingerprint_header": "header check",
    "missing_security_header": "header check",
    "nikto_finding": "nikto",
    "nmap_script": "nmap NSE",
    "nuclei_finding": "nuclei",
    "open_port": "nmap",
    # The recon mapper's three types. recon_subdomain names several tools
    # because it genuinely has several producers — crt.sh, subfinder/amass
    # and theHarvester all find subdomains and the profile merges them —
    # and the finding's own text names the specific source(s) that found
    # that particular name.
    "recon_bucket": "cloud_enum",
    "recon_leak": "HIBP",
    "recon_subdomain": "crt.sh/subfinder/amass",
    "service_version": "nmap -sV",
    "smb_share": "enum4linux",
    "smb_user": "enum4linux",
    "sqlmap_finding": "sqlmap",
    "sslyze_finding": "sslyze",
    "technology_fingerprint": "whatweb",
    "weak_credentials": "hydra",
    # gobuster, NOT wpscan. The finding is raised when gobuster's path sweep
    # hits a /wp-* marker (gobuster_wrap sets wordpress_fingerprinted, and
    # both deepscan and webaudit map that flag to this finding type) — it is
    # the *trigger* for wpscan under CONDITIONAL_TOOLS, not a wpscan result.
    # Naming wpscan here made webaudit — which never runs wpscan — render
    # "not determined by wpscan" on a finding gobuster produced. Same defect
    # class as smoke_test8 §4.2, found by the attribution sweep this pass
    # added (modules/reporting/attribution.py).
    "wordpress_fingerprinted": "gobuster",
    "wpscan_finding": "wpscan",
    "xss_finding": "nuclei DAST",
    "zap_finding": "zaproxy",
}

# Finding types for which a given field is not applicable *by nature*, with
# the short qualifier the report prints. Anything not listed here is treated
# as applicable-but-unpopulated and reported as a genuine gap.
#
# The judgement in each case is "could this tool, run correctly, ever fill
# this in?" — not "did it this time".
_NOT_APPLICABLE = {
    "cve_id": {
        "banner": "banner observation",
        "discovered_path": "path discovery",
        "fingerprint_header": "fingerprint",
        "missing_security_header": "config finding",
        "open_port": "port observation",
        "service_version": "service observation",
        "smb_share": "share enumeration",
        "smb_user": "user enumeration",
        "sqlmap_finding": "injection class, not a CVE",
        "sslyze_finding": "TLS configuration finding",
        "technology_fingerprint": "fingerprint",
        "weak_credentials": "credential finding",
        "wordpress_fingerprinted": "fingerprint",
        "xss_finding": "injection class, not a CVE",
    },
    "cvss": {
        # This table used to say CVSS was "a score of a CVE", so any non-CVE
        # finding type was declared CVSS-inapplicable. That premise no longer
        # holds: modules/enrichment/cvss.py computes a local CVSS v3.1 vector
        # for exactly these types (missing headers, weak TLS, exposed paths,
        # confirmed injection), so a populated `cvss` on one of them is now a
        # correct, intended value — not a field-signature violation. The
        # attribution audit (t_phase9 §H) flagged the contradiction the day
        # the scoring engine landed, which is the check doing its job.
        #
        # Only the types cvss.py leaves in UNSCORED_TYPES remain
        # CVSS-inapplicable, and for those the reason is no longer "no CVE"
        # but a deliberate scoping decision: scoring pure information
        # disclosure at its defensible 5.3 would promote thousands of LOW
        # rows to MEDIUM and bury the real findings (see cvss.py).
        "banner": "left unscored — informational disclosure (see cvss.UNSCORED_TYPES)",
        "fingerprint_header": "left unscored — informational disclosure",
        "technology_fingerprint": "left unscored — informational disclosure",
        "wordpress_fingerprinted": "left unscored — not a flaw in itself",
        "smb_share": "left unscored — enumeration evidence",
        "smb_user": "left unscored — enumeration evidence",
        "open_port": "left unscored — exposure, not an assessed weakness",
        "service_version": "left unscored — version evidence",
        # Deliberately ABSENT now, because cvss.py DOES score them:
        #   discovered_path (sensitive paths), missing_security_header,
        #   sslyze_finding (incl. testssl), weak_credentials, sqlmap_finding,
        #   xss_finding — a populated cvss on any of these is expected.
    },
    "service": {
        # enum4linux findings are about SMB accounts and shares rather than
        # a port-bound service, so there is no service cell to fill.
        "smb_share": "host-level finding",
        "smb_user": "host-level finding",
    },
    "version": {
        "discovered_path": "path discovery",
        "missing_security_header": "config finding",
        "open_port": "port observation",
        "smb_share": "host-level finding",
        "smb_user": "host-level finding",
        # sslyze reports the TLS configuration of a port, not a software
        # version — the protocol versions it names live in the description.
        "sslyze_finding": "TLS configuration finding",
    },
    # endpoint is the URL a finding concerns. Host- and port-level findings
    # are not about a URL at all, so an empty cell there is correct rather
    # than a gap in what the scan learned.
    "endpoint": {
        "banner": "port-level observation",
        "cve": "service-level finding",
        "nmap_script": "host/service finding",
        "open_port": "port observation",
        "service_version": "port-level observation",
        "smb_share": "host-level finding",
        "smb_user": "host-level finding",
        "sslyze_finding": "port-level observation",
        "weak_credentials": "credential finding",
    },
    # reference is a citation the tool itself supplied. Tools that report
    # observations rather than catalogued issues publish none, and never
    # would.
    "reference": {
        "banner": "banner observation",
        "discovered_path": "path discovery",
        "fingerprint_header": "fingerprint",
        "missing_security_header": "config finding",
        "nmap_script": "script output",
        "open_port": "port observation",
        "service_version": "service observation",
        "smb_share": "share enumeration",
        "smb_user": "user enumeration",
        "sslyze_finding": "TLS configuration finding",
        "technology_fingerprint": "fingerprint",
        "weak_credentials": "credential finding",
        "wordpress_fingerprinted": "fingerprint",
    },
}


def field_display(finding: dict, field: str) -> str:
    """
    Render one finding field as text that is always explicit about itself.

    Returns, in order of preference:
      - the value, when the field is populated
      - "N/A (<why>)"  when the field cannot apply to this finding type
      - "not determined by <tool>"  when it could have applied but nothing
        filled it in

    Never returns a bare "-". The point of this function is that no cell in
    any report is ever ambiguous about whether it represents a
    non-applicable field or a real gap in what the scan learned.
    """
    value = finding.get(field)
    if value is not None and str(value).strip() not in ("", "None"):
        return str(value).strip()

    finding_type = str(finding.get("finding_type") or "").strip().lower()

    reason = _NOT_APPLICABLE.get(field, {}).get(finding_type)
    if reason:
        return f"N/A ({reason})"

    tool = FINDING_TYPE_TOOL.get(finding_type)
    if tool:
        return f"not determined by {tool}"
    return "not determined"


def service_display(finding: dict) -> str:
    """
    Service and version as one cell — "http 1.31.3", or an honest label.

    Both populated is the common case and reads as one phrase. When only
    one is known the other is not silently dropped: "nginx (version not
    determined by nmap -sV)" says more than "nginx" does.
    """
    service = str(finding.get("service") or "").strip()
    version = str(finding.get("version") or "").strip()

    if service and version:
        return f"{service} {version}"
    if service:
        return f"{service} (version {field_display(finding, 'version')})"
    if version:
        return f"{field_display(finding, 'service')} (version {version})"
    return field_display(finding, "service")


# How much of a description may stand in as a finding's identifier. Long
# enough to be recognisable in a one-line list, short enough to fit beside
# a severity badge and a port.
FINDING_IDENTIFIER_MAXLEN = 60


def finding_identifier(finding: dict) -> str:
    """
    The short label that names a finding in a list or a card heading.

    Order: CVE id, then service/version, then a truncated description.

    Lives here rather than in either report writer because the two used to
    disagree — the PDF fell straight through to a service label and titled
    every nuclei match "unknown", while the text report had a description
    fallback. Same finding, two different names, depending on which file
    you opened.

    The description fallback is a last resort by design. A truncated
    description is a weak identifier: whole families of nuclei templates
    open with the same sentence, which is how four distinct Redis CVEs came
    to render as four identical-looking rows on scan 117. The fix for that
    is upstream — populating cve_id, and prefixing the template name onto
    the description — so that this fallback is reached with text that
    actually differs. It is kept because a finding with no better label
    still needs *a* label.
    """
    cve_id = str(finding.get("cve_id") or "").strip()
    if cve_id:
        return cve_id

    if str(finding.get("service") or "").strip():
        service = str(finding.get("service")).strip()
        version = str(finding.get("version") or "").strip()
        return f"{service} {version}".strip()

    description = str(finding.get("description") or "").strip()
    if description:
        if len(description) > FINDING_IDENTIFIER_MAXLEN:
            return description[: FINDING_IDENTIFIER_MAXLEN - 3].rstrip() + "..."
        return description

    finding_type = str(finding.get("finding_type") or "").strip()
    return finding_type or "unknown"


# How much of the *divergent* part of a description to show when several
# findings share a long opening. Enough to tell "integer overflow" from
# "use after free"; short enough to keep the line scannable.
_IDENTIFIER_DISTINGUISHER_MAXLEN = 45


def _longest_common_prefix(values) -> int:
    """Length of the longest prefix every string in `values` shares."""
    if not values:
        return 0
    shortest = min(len(v) for v in values)
    for index in range(shortest):
        column = {v[index] for v in values}
        if len(column) > 1:
            return index
    return shortest


def distinct_identifiers(findings: list) -> list:
    """
    finding_identifier() for a list, with collisions resolved.

    Returns one label per finding, positionally aligned with the input.

    Why this exists
    ---------------
    finding_identifier() falls back to a truncated description when a
    finding has no CVE id and no service. Truncation is not injective:
    nuclei ships whole families of templates whose descriptions share a
    long opening sentence, so several genuinely different findings can
    truncate to the same 60 characters. That is exactly what was reported
    against scan 117 — four distinct Redis RCE/DoS CVEs rendered as four
    identical-looking rows.

    The upstream fix (populating cve_id from the template id, and
    prefixing the template name onto the description) means new scans do
    not reach this path. It cannot help rows already in the database,
    though: their cve_id is NULL and their description is the bare
    upstream prose, so re-rendering an old scan still produced
    identical-looking rows.

    So collisions are also resolved here, at render time, in bounded steps
    that add information rather than removing any:

      1. append the part of each description where the group actually
         diverges. Simply showing *more* of the description does not work:
         the four Redis templates share their first ~160 characters, so a
         wider window is still four identical strings, just longer. What
         distinguishes them ("cause an integer overflow", "use after
         free") lives immediately past the common prefix, so that is what
         gets appended.
      2. if the descriptions are byte-identical, fall back to the columns
         that differ — port and finding type
      3. and if even those match, a positional marker, so the guarantee
         that no two labels are equal holds unconditionally

    Nothing is dropped, merged or invented. A reader always sees as many
    rows as there are findings, each with a label that distinguishes it
    from its neighbours.
    """
    findings = list(findings or [])
    labels = [finding_identifier(f) for f in findings]

    groups = {}
    for index, label in enumerate(labels):
        groups.setdefault(label, []).append(index)

    for label, indices in groups.items():
        if len(indices) < 2:
            continue

        # Only labels that came from the truncated-description fallback can
        # be repaired by showing more description. A group sharing a
        # service label ("http 1.31.3" on ports 80, 81 and 443) is a
        # different situation: those findings are already told apart by the
        # port the report prints beside the label, and appending the tail
        # of their description to each would add "…80." / "…81." — noise
        # restating the column next to it.
        if any(
            str(findings[i].get("cve_id") or "").strip()
            or str(findings[i].get("service") or "").strip()
            for i in indices
        ):
            continue

        descriptions = {
            index: str(findings[index].get("description") or "").strip()
            for index in indices
        }

        # Step 1: show where the descriptions actually diverge.
        split_at = _longest_common_prefix(list(descriptions.values()))
        if split_at < max(len(d) for d in descriptions.values()):
            for index, description in descriptions.items():
                tail = description[split_at:].strip()
                if len(tail) > _IDENTIFIER_DISTINGUISHER_MAXLEN:
                    tail = tail[: _IDENTIFIER_DISTINGUISHER_MAXLEN - 3].rstrip() + "..."
                labels[index] = f"{label} …{tail}" if tail else label

        # Step 2: identical text — distinguish by the columns that differ.
        if len({labels[i] for i in indices}) != len(indices):
            for index in indices:
                finding = findings[index]
                labels[index] = (
                    f"{labels[index]} "
                    f"[{finding.get('finding_type') or 'finding'} "
                    f"on port {finding.get('port')}]"
                )

        # Step 3: unconditional guarantee. Two findings can legitimately be
        # identical on every column the report shows (the same header
        # missing on the same port, recorded twice by different tools);
        # dedup only collapses rows that match on the full key, so a pair
        # like that survives to here and still must not render as one.
        if len({labels[i] for i in indices}) != len(indices):
            for ordinal, index in enumerate(indices, start=1):
                labels[index] = f"{labels[index]} ({ordinal} of {len(indices)})"

    return labels


def cvss_display(finding: dict) -> str:
    """
    CVSS cell: the score, where it came from, and — for a locally computed
    score — the vector it was computed from.

    An unscored finding is not a mystery — severity.py graded it
    heuristically — so the label says which of the two happened rather than
    leaving the reader to wonder whether scoring failed.

    The vector is shown because a locally computed score without one is
    just a differently-spelled severity bucket: "5.3" invites the reader to
    trust it, while "5.3 [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N]"
    lets them check it and disagree with a specific metric. NVD-sourced
    scores carry no vector here — they are attributable to the CVE record
    itself, which is the authority for them, and inventing a vector to
    display alongside one would misrepresent whose judgement it was.
    """
    cvss = finding.get("cvss")
    if cvss is None:
        # No score, from NVD or the local engine. That is not a gap to
        # apologise for and it is not "not determined by <some tool>" — no
        # tool was ever going to CVSS-score this row. It was graded on
        # severity.py's heuristic rules, which the Severity cell already
        # shows. Say exactly that rather than routing through
        # field_display(), whose tool-based fallback would misattribute the
        # absence to gobuster/nikto/etc.
        finding_type = str(finding.get("finding_type") or "").strip().lower()
        reason = _NOT_APPLICABLE.get("cvss", {}).get(finding_type)
        if reason:
            return f"N/A ({reason})"
        return "N/A (graded heuristically — see Severity)"

    source = finding.get("severity_source", "heuristic")
    vector = str(finding.get("cvss_vector") or "").strip()
    if vector:
        return f"{cvss} (source: {source}) [{vector}]"
    return f"{cvss} (source: {source})"


# --- Defensive de-duplication --------------------------------------------
# Identity of a finding for de-duplication purposes.
#
# Deliberately built from the FULL description, never a truncated or
# rendered one. That distinction is the whole point of this key: the report
# bug that prompted it (scan 117) showed four Redis CVEs as four identical
# rows, and they were identical only *after* the renderer cut the
# description to 60 characters. Keying on rendered text would have
# "resolved" that symptom by permanently discarding three real
# remote-code-execution findings.
#
# cve_id and severity are in the key alongside (finding_type, port,
# description) so the pass stays conservative: two rows have to agree on
# every one of them before either is dropped. The same CVE on two different
# ports differs on port; two different CVEs sharing a description differ on
# cve_id. Both stay separate, which is required behaviour.
_DEDUP_KEY_COLUMNS = ("finding_type", "port", "cve_id", "severity", "description")


def _dedup_key(finding: dict) -> tuple:
    return tuple(
        str(finding.get(column)) if finding.get(column) is not None else None
        for column in _DEDUP_KEY_COLUMNS
    )


def deduplicate_findings(findings: list, target: str = _FALLBACK_TARGET,
                         scan_id=None, quiet: bool = False) -> list:
    """
    Collapse rows that are identical on every column in _DEDUP_KEY_COLUMNS,
    keeping the first occurrence (the list is already worst-first, so the
    survivor is the best-ranked copy).

    This is a guard, not a fix for any known producer. Nothing in the
    codebase is currently known to double-insert a finding; the pass exists
    so that if something ever starts to, the reports absorb it instead of
    printing the same row twice.

    A collapse is never silent. Every distinct group that loses rows is
    logged and printed with its identity and the number dropped, because a
    de-duplicator that quietly deletes findings from a security report is a
    worse defect than the duplication it is guarding against.

    Returns a new list; the input and its dicts are not mutated.
    """
    kept = []
    seen = {}
    dropped = {}

    for finding in findings or []:
        key = _dedup_key(finding)
        if key in seen:
            dropped[key] = dropped.get(key, 0) + 1
            continue
        seen[key] = finding
        kept.append(finding)

    if not dropped:
        return kept

    logger = get_logger(target)
    total = sum(dropped.values())
    scan_label = f"scan {scan_id}" if scan_id is not None else "scan"
    logger.warning(
        f"[Summary] {scan_label} ({target}): de-duplication collapsed "
        f"{total} duplicate finding row(s) across {len(dropped)} group(s)"
    )
    if not quiet:
        print_warning(
            f"[Summary] collapsed {total} duplicate finding row(s) — "
            f"{len(dropped)} finding(s) had identical copies"
        )

    for key, count in dropped.items():
        finding_type, port, cve_id, severity, description = key
        identity = cve_id or (description or "")[:80] or finding_type or "unknown"
        detail = (
            f"[Summary] duplicate collapsed: {identity} "
            f"(type={finding_type}, port={port}, severity={severity}) "
            f"— {count} extra copy(ies) dropped, 1 kept"
        )
        logger.warning(detail)
        if not quiet:
            print_warning(detail)

    return kept


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


# Profiles whose designed scope leaves out a class of finding another
# profile would surface. This is not a defect list — each profile is doing
# what it is meant to. It exists because a report that is silent about its
# own scope reads as a statement about the host rather than about the scan:
# webaudit on pentest-ground.com reported 6 MEDIUM / 24 LOW while a quickscan
# of the same host found 2 CRITICAL (smoke_test7 §9.8), and nothing in the
# webaudit report said why.
#
# Kept factual and short on purpose. It is a scope statement, not a warning.
# The text carries no "Scope:" prefix of its own — each surface supplies its
# own label (the CLI banner has a bold one, the report blocks prepend it), and
# a self-prefixing string produced "Scope: Scope: this profile ..." in the
# banner.
_PROFILE_SCOPE_NOTES = {
    "webaudit": (
        "this profile audits the web application layer. It runs "
        "nuclei only in DAST mode for reflected XSS, not the severity "
        "template pass that quickscan and deepscan run against the host's "
        "other exposed services — so CVE-class findings on non-web ports "
        "are outside what this report covers. A quickscan or deepscan of "
        "the same host may surface findings this report does not."
    ),
}

SCOPE_NOTE_LABEL = "Scope"


def profile_scope_note(profile, labelled: bool = False) -> str:
    """The scope statement for a profile, or "" if it has none.

    One implementation shared by the text report, the PDF and the end-of-run
    CLI banner, so the three cannot drift into describing the same profile's
    scope differently. `labelled` prepends "Scope: " for the surfaces that do
    not draw their own label.
    """
    note = _PROFILE_SCOPE_NOTES.get(str(profile or "").strip().lower(), "")
    if note and labelled:
        return f"{SCOPE_NOTE_LABEL}: {note}"
    return note


def build_summary(scan_id, top_n: int = _DEFAULT_TOP_N, quiet: bool = False) -> dict:
    """
    Assemble everything the report writers need for one persisted scan.

    Parameters
    ----------
    scan_id : int   id of a row in the scans table
    quiet   : bool  suppress the console line only (logging is unchanged).
                    Set by callers that build a summary purely to read from
                    — the end-of-scan banner does, and one scan should not
                    print three identical "[Summary] scan N" lines just
                    because the txt writer, the pdf writer and the banner
                    each needed the same data.
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
    # Sorted first so the copy that survives a collapse is the best-ranked
    # one, and so both report writers see the same de-duplicated set —
    # running this here rather than in a renderer keeps txt and PDF from
    # ever disagreeing on how many findings a scan had.
    findings = deduplicate_findings(
        findings, target=target, scan_id=metadata["id"], quiet=quiet
    )
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
        if not quiet:
            print_warning(f"[Summary] scan {metadata['id']} ({target}) has no findings recorded")
        return summary

    logger.info(
        f"[Summary] scan {metadata['id']} ({target}): "
        f"{len(findings)} finding(s) {by_severity}"
    )
    if not quiet:
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
