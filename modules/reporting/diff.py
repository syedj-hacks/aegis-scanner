"""
modules/reporting/diff.py
Compare two finished scans: what is new, what got fixed, what is unchanged.

Why a stable key, and not a dict hash
--------------------------------------
The obvious implementation — hash each finding dict and compare the sets —
does not work here, and fails in the direction that matters. Findings carry
fields that legitimately differ between two scans of the same unchanged
target: a nikto description that reports a slightly different byte count, a
gobuster path whose `size` moved, a `cvss` that changed because NVD
re-rated the CVE, a remediation string that this project itself reworded
between the two runs. Hashing the dict makes every one of those look like
"one finding fixed, one finding new".

A diff that reports phantom churn is worse than no diff, because the whole
point is to be trusted when it says something changed. So findings are
matched on a deliberately narrow key of the fields that IDENTIFY a finding
rather than describe it:

    (finding_type, port, identifier)

where `identifier` is the CVE id where there is one, and otherwise the most
specific stable label that finding type has — a path for a discovered path,
a header name for a missing header, a rule id for a ZAP/nuclei rule, a
normalised description for anything else.

Severity is deliberately NOT in the key. A finding whose severity changed
between two scans is the same finding, and reporting it as one fixed plus
one new would hide the thing a reader actually wants to know — which is
that its severity changed. It is reported as `changed` instead.

Reading a diff honestly
-----------------------
"Fixed" means "present in scan A, absent in scan B". That is not the same
as "remediated", and this module does not claim it is: a tool that was
skipped, timed out, or failed in scan B produces exactly the same absence.
diff_scans() therefore also compares which tools ran in each scan, and
flags findings whose producing tool did not run in B as `unverified`
instead of quietly counting them as fixed. A scan where nikto crashed
should not report every nikto finding as resolved.
"""

import re

from database.db import get_findings_for_scan, get_scan_tools_run, get_scan_history
from modules.reporting.attribution import FINDING_TYPE_PRODUCERS

# Fields that carry a finding's identity, tried in order, per finding type.
# The first one present and non-empty wins.
_IDENTITY_FIELDS = (
    "cve_id",       # a CVE is the strongest identifier there is
    "path",         # discovered_path
    "header",       # missing_security_header / fingerprint_header
    "script_id",    # nmap_script
    "rule_id",      # zap_finding
    "template_id",  # nuclei_finding
    "parameter",    # xss_finding / sqlmap_finding
    "issue",        # sslyze_finding / testssl
    "name",         # technology_fingerprint
)

# Volatile fragments stripped before a description is used as a fallback
# identifier. Byte counts, timings and response sizes change run to run on
# a target that has not changed at all, and letting them into the key is
# what produces phantom churn.
_VOLATILE = re.compile(
    r"\b\d+\s*(?:bytes?|ms|s|seconds?)\b"     # "312 bytes", "45 ms"
    r"|\bHTTP\s+\d{3}\b"                       # status codes move on retries
    r"|\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}\S*"  # timestamps
    r"|\b\d+\s+cipher suite\(s\)\b",           # sslyze's per-run counts
    re.IGNORECASE,
)


def _identifier(finding: dict) -> str:
    """The most specific stable label this finding carries."""
    for field in _IDENTITY_FIELDS:
        value = str(finding.get(field) or "").strip()
        if value:
            return value.lower()

    # Fall back to the description with volatile numbers removed. Truncated
    # so a description that grows a trailing clause still matches.
    description = str(finding.get("description") or "").strip().lower()
    description = _VOLATILE.sub("", description)
    description = " ".join(description.split())
    return description[:160]


def finding_key(finding: dict) -> tuple:
    """
    The identity of a finding for diffing: (finding_type, port, identifier).

    Deliberately excludes severity, cvss, description detail, remediation
    and every timestamp — see the module docstring. Two findings with this
    key equal are the same finding observed twice.
    """
    if not isinstance(finding, dict):
        return ("", None, "")

    kind = str(
        finding.get("finding_type") or finding.get("type") or ""
    ).strip().lower()

    port = finding.get("port")
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        port = None

    return (kind, port, _identifier(finding))


def _tools_that_ran(scan_id) -> set:
    """
    The tools recorded as having actually RUN on a scan (not skipped, not
    failed), or None when the scan predates the scan_tools_run table.

    None and empty set mean different things and are kept distinct: None is
    "we have no record", which must not be read as "nothing ran".
    """
    try:
        rows = get_scan_tools_run(scan_id)
    except Exception:
        return None
    if not rows:
        return None
    return {
        str(r.get("tool_name") or "").strip().lower()
        for r in rows
        if str(r.get("outcome") or "").strip().lower() == "ran"
    }


def _producers_ran(finding: dict, ran: set) -> bool:
    """
    Whether any tool that could have produced `finding` ran in that scan.

    True when there is no record to check against (`ran` is None): with no
    evidence either way, the honest default is not to cast doubt on the
    result. Also true for a finding type with no known producer, for the
    same reason.
    """
    if ran is None:
        return True
    kind, _, _ = finding_key(finding)
    producers = FINDING_TYPE_PRODUCERS.get(kind)
    if not producers:
        return True
    # 'nvd' is an in-process REST call, never recorded as a subprocess tool
    # (see attribution.py) — its absence from the record proves nothing.
    if producers == {"nvd"}:
        return True
    return bool(producers & ran)


def diff_scans(scan_id_a, scan_id_b) -> dict:
    """
    Compare scan A (the earlier/baseline) with scan B (the later/current).

    Returns
    -------
    dict:
        scan_a, scan_b   : the two scan ids as given
        new              : list[dict]  in B, not in A
        fixed            : list[dict]  in A, not in B, and a producing tool
                                       DID run in B — so the absence is
                                       meaningful
        unverified       : list[dict]  in A, not in B, but no producing tool
                                       ran in B — absence proves nothing
        unchanged        : list[dict]  in both, same severity
        changed          : list[dict]  in both, severity differs; each entry
                                       carries severity_from / severity_to
        counts           : dict        the five list lengths
        comparable       : bool        False when either scan has no
                                       findings recorded at all

    Never raises: an unknown scan id yields empty lists rather than an
    exception, because this is called from a cron script whose job is to
    keep running.
    """
    result = {
        "scan_a": scan_id_a,
        "scan_b": scan_id_b,
        "new": [],
        "fixed": [],
        "unverified": [],
        "unchanged": [],
        "changed": [],
        "counts": {},
        "comparable": True,
    }

    try:
        findings_a = get_findings_for_scan(scan_id_a) or []
        findings_b = get_findings_for_scan(scan_id_b) or []
    except Exception:
        findings_a, findings_b = [], []

    if not findings_a and not findings_b:
        result["comparable"] = False

    ran_b = _tools_that_ran(scan_id_b)

    # Last occurrence wins on a duplicate key within one scan — the two
    # rows are the same finding by construction, so either is correct.
    by_key_a = {finding_key(f): f for f in findings_a}
    by_key_b = {finding_key(f): f for f in findings_b}

    for key, finding in by_key_b.items():
        if key not in by_key_a:
            result["new"].append(finding)

    for key, finding in by_key_a.items():
        if key in by_key_b:
            continue
        if _producers_ran(finding, ran_b):
            result["fixed"].append(finding)
        else:
            result["unverified"].append(finding)

    for key, finding_a in by_key_a.items():
        finding_b = by_key_b.get(key)
        if finding_b is None:
            continue
        sev_a = str(finding_a.get("severity") or "").upper()
        sev_b = str(finding_b.get("severity") or "").upper()
        if sev_a != sev_b:
            result["changed"].append(
                dict(finding_b, severity_from=sev_a, severity_to=sev_b)
            )
        else:
            result["unchanged"].append(finding_b)

    result["counts"] = {
        name: len(result[name])
        for name in ("new", "fixed", "unverified", "unchanged", "changed")
    }
    return result


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _sorted(findings: list) -> list:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(str(f.get("severity") or "").upper(), 9),
                       str(f.get("description") or "")),
    )


def render_diff(diff: dict, verbose: bool = False) -> str:
    """
    A plain-text rendering of diff_scans()'s output, suitable for a terminal
    or the body of a cron email.

    `unchanged` findings are counted but not listed unless `verbose` — on a
    real target they are the overwhelming majority, and a delta report that
    reprints them buries the delta.
    """
    lines = []
    counts = diff.get("counts") or {}

    lines.append(f"Scan diff: {diff.get('scan_a')} -> {diff.get('scan_b')}")
    lines.append("=" * 60)

    if not diff.get("comparable", True):
        lines += [
            "",
            "Neither scan recorded any findings — there is nothing to compare.",
            "Check both scans actually completed before reading this as 'no change'.",
            "",
        ]
        return "\n".join(lines)

    lines += [
        "",
        f"  NEW        {counts.get('new', 0):>4}   findings in {diff.get('scan_b')} that were not in {diff.get('scan_a')}",
        f"  FIXED      {counts.get('fixed', 0):>4}   gone, and a tool that would have found them did run",
        f"  UNVERIFIED {counts.get('unverified', 0):>4}   gone, but no producing tool ran — absence proves nothing",
        f"  CHANGED    {counts.get('changed', 0):>4}   still present, severity moved",
        f"  UNCHANGED  {counts.get('unchanged', 0):>4}   still present, same severity",
        "",
    ]

    def _section(title, key, note=None):
        findings = diff.get(key) or []
        if not findings:
            return
        lines.append(f"--- {title} ({len(findings)}) " + "-" * max(0, 40 - len(title)))
        if note:
            lines.append(f"    {note}")
        for finding in _sorted(findings):
            severity = finding.get("severity", "LOW")
            port = finding.get("port")
            where = f":{port}" if port is not None else ""
            description = " ".join(str(finding.get("description") or "").split())[:110]
            if key == "changed":
                severity = f"{finding.get('severity_from')}->{finding.get('severity_to')}"
            lines.append(f"    [{severity}]{where} {description}")
        lines.append("")

    _section("NEW", "new")
    _section("FIXED", "fixed")
    _section(
        "UNVERIFIED", "unverified",
        "These are absent from the later scan, but the tool that finds them "
        "did not run in it.\n    Do NOT read these as remediated.",
    )
    _section("SEVERITY CHANGED", "changed")
    if verbose:
        _section("UNCHANGED", "unchanged")

    return "\n".join(lines)


def latest_two_scans(target: str):
    """
    The (previous, latest) scan ids for `target`, or (None, None) when it
    has fewer than two scans on record.

    Exists for scripts/scheduled_scan.sh, whose whole job is "scan, then
    diff against the previous scan of the same target" — resolving that
    pair in SQL-free Python here keeps the shell script simple.
    """
    try:
        history = get_scan_history(target) or []
    except Exception:
        return None, None
    if len(history) < 2:
        return None, None
    # get_scan_history returns newest-first.
    return history[1].get("id"), history[0].get("id")
