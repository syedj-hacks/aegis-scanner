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

# The longest comma-separated fragment still treated as a list ITEM rather
# than prose. An enumeration of HTTP methods, cipher names or header names
# has short items; a sentence that happens to contain a comma does not.
# Keeps the normalisation below from reordering prose it does not
# understand.
_MAX_LIST_ITEM_LEN = 24


def _normalise_enumeration(text: str) -> str:
    """
    Sort a trailing comma-separated enumeration into a stable order.

    Tools report set-valued facts in whatever order they happened to
    observe them, and that order is not stable between runs. Verified on
    real data: nikto reported the same finding as

        [999990] OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
        [999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .

    in two scans of an unchanged target, and the diff duly announced one
    finding fixed and one new. The set is identical; only the order moved.
    A diff that reports that is not trustworthy on the occasions when
    something genuinely did change, which is the entire point of having one.

    Scoped deliberately narrowly. Only the text after the LAST colon is
    considered (that is where these enumerations live, after a "…Methods:"
    style label), and only when every comma-separated fragment is short
    enough to be a list item — so an ordinary sentence containing a comma is
    left exactly as it is rather than being silently reordered.
    """
    if "," not in text:
        return text

    head, sep, tail = text.rpartition(":")
    if not sep:
        head, tail = "", text

    # A trailing full stop is nikto's, not part of the last item.
    tail = tail.strip().rstrip(".").strip()
    items = [item.strip() for item in tail.split(",")]
    if len(items) < 2 or not all(0 < len(item) <= _MAX_LIST_ITEM_LEN for item in items):
        return text

    return f"{head}{sep} " + ", ".join(sorted(items))


def _identifier(finding: dict) -> str:
    """The most specific stable label this finding carries."""
    for field in _IDENTITY_FIELDS:
        value = str(finding.get(field) or "").strip()
        if value:
            return value.lower()

    # Fall back to the description with volatile numbers removed and any
    # trailing enumeration sorted. Truncated so a description that grows a
    # trailing clause still matches.
    description = str(finding.get("description") or "").strip().lower()
    description = _VOLATILE.sub("", description)
    description = " ".join(description.split())
    description = _normalise_enumeration(description)
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
        # `escalated` and `deescalated` partition `changed` by direction;
        # every entry in them is also in `changed`, which is kept whole so
        # existing readers (render_diff, scripts/scheduled_scan.sh) see
        # exactly what they saw before.
        "escalated": [],
        "deescalated": [],
        "counts": {},
        "delta_summary": "",
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
            entry = dict(finding_b, severity_from=sev_a, severity_to=sev_b)
            result["changed"].append(entry)
            # Split by DIRECTION as well as recording the change, because
            # the two directions mean opposite things and a single "2
            # severity changes" number tells a reader nothing about which
            # way their risk moved. A CVE re-rated LOW->CRITICAL and one
            # re-rated CRITICAL->LOW are not interchangeable.
            direction = _severity_direction(sev_a, sev_b)
            if direction > 0:
                result["escalated"].append(entry)
            elif direction < 0:
                result["deescalated"].append(entry)
        else:
            result["unchanged"].append(finding_b)

    result["counts"] = {
        name: len(result[name])
        for name in ("new", "fixed", "unverified", "unchanged", "changed",
                     "escalated", "deescalated")
    }
    result["delta_summary"] = _delta_summary(result)
    return result


def _severity_direction(severity_from: str, severity_to: str) -> int:
    """
    +1 when severity got worse, -1 when it improved, 0 when it cannot be
    compared.

    Returns 0 rather than guessing when either label is missing or
    unrecognised. An unscored finding (severity NULL, which summary.py
    grades LOW at render time) compared against a scored one is not
    evidence that anything moved — it is evidence that one of the two scans
    did not score it, and reporting that as an escalation would manufacture
    an alarm out of a schema gap.
    """
    rank_from = _SEVERITY_ORDER.get(str(severity_from or "").upper())
    rank_to = _SEVERITY_ORDER.get(str(severity_to or "").upper())
    if rank_from is None or rank_to is None:
        return 0
    # _SEVERITY_ORDER is worst-first (CRITICAL == 0), so a SMALLER rank is
    # a HIGHER severity.
    if rank_to < rank_from:
        return 1
    if rank_to > rank_from:
        return -1
    return 0


def _delta_summary(diff: dict) -> str:
    """
    The one-line "what moved since last time" sentence, printed after every
    scan and at the top of a --diff.

    Deliberately mentions `unverified` whenever there is any, even though it
    makes the sentence longer. That count is the difference between "3
    findings fixed" and "3 findings that nobody looked for this time", and
    a summary line that hides it is the exact false-reassurance this module
    exists to avoid.
    """
    counts = diff.get("counts") or {}
    if not diff.get("comparable", True):
        return "no comparable findings — check both scans actually completed"

    parts = [
        f"{counts.get('new', 0)} new",
        f"{counts.get('fixed', 0)} fixed",
    ]
    if counts.get("escalated"):
        parts.append(f"{counts['escalated']} escalated")
    if counts.get("deescalated"):
        parts.append(f"{counts['deescalated']} downgraded")
    if counts.get("unverified"):
        parts.append(f"{counts['unverified']} unverified (no producing tool ran)")

    unchanged = counts.get("unchanged", 0)
    summary = ", ".join(parts)
    if not any(counts.get(k) for k in ("new", "fixed", "escalated",
                                       "deescalated", "unverified")):
        return f"no change — {unchanged} finding(s) identical to scan #{diff.get('scan_a')}"
    return f"{summary} since scan #{diff.get('scan_a')} ({unchanged} unchanged)"


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


def scan_meta(scan_id) -> dict:
    """
    {id, target, profile, timestamp} for one scan, with None values when the
    scan is not in the database. Used to head a diff report so the reader
    knows which two runs are being compared and when.
    """
    empty = {"id": scan_id, "target": None, "profile": None, "timestamp": None}
    try:
        for row in get_scan_history() or []:
            if row.get("id") == scan_id:
                return {
                    "id": row.get("id"),
                    "target": row.get("target"),
                    "profile": row.get("profile"),
                    "timestamp": row.get("timestamp"),
                }
    except Exception:
        return empty
    return empty


# --- Rich terminal rendering ---------------------------------------------
# render_diff() above returns a plain string on purpose: it is what --diff
# pipes into a cron mail body, and Rich markup in an email is noise. This
# renders the same diff to an interactive terminal instead, where colour
# does real work — a reader scanning a 40-row table needs "which of these
# got worse" to be answerable without reading.
_STATUS_STYLES = {
    "NEW": "bold red",
    "FIXED": "green",
    "ESCALATED": "bold yellow",
    "DOWNGRADED": "cyan",
    "UNVERIFIED": "magenta",
    "UNCHANGED": "dim",
}


def print_diff(diff: dict, verbose: bool = False) -> None:
    """
    Print a diff to the terminal as a coloured summary line plus a table.

    `unchanged` rows are counted in the summary but only listed when
    `verbose` — on a real target they are the overwhelming majority (this
    project's own database has scans with 800+ unchanged findings), and a
    delta view that reprints them is not a delta view.

    Never raises: a malformed diff prints what it can.
    """
    from modules.utils.display import console, print_severity_badge
    from rich.table import Table
    from rich.panel import Panel

    counts = diff.get("counts") or {}
    scan_a, scan_b = diff.get("scan_a"), diff.get("scan_b")

    if not diff.get("comparable", True):
        console.print(Panel(
            f"Neither scan #{scan_a} nor scan #{scan_b} recorded any findings — "
            "there is nothing to compare.\n"
            "[dim]Check both scans actually completed before reading this as "
            "'no change'.[/dim]",
            title="SCAN DIFF", border_style="yellow",
        ))
        return

    # A diff across two different targets is not a delta, it is two unrelated
    # scans subtracted from each other — every finding shows as new or fixed
    # and none of it means anything. Nothing stops someone asking for it (and
    # occasionally it is deliberate, comparing a staging host against
    # production), so it is not refused, but it is called out: an unlabelled
    # "23,330 new findings" would otherwise read as a catastrophic regression.
    meta_a, meta_b = scan_meta(scan_a), scan_meta(scan_b)
    if meta_a.get("target") and meta_b.get("target") and \
            meta_a["target"] != meta_b["target"]:
        console.print(Panel(
            f"These two scans are of [bold]different targets[/bold] — "
            f"#{scan_a} is {meta_a['target']} and #{scan_b} is {meta_b['target']}.\n"
            "[dim]Read the counts below as a comparison of two unrelated hosts, "
            "not as a change over time.[/dim]",
            title="DIFFERENT TARGETS", border_style="yellow",
        ))

    console.print(Panel(
        f"[bold]Scan #{scan_a}[/bold] → [bold]#{scan_b}[/bold]\n\n"
        f"[bold red]{counts.get('new', 0)} new[/bold red]   "
        f"[green]{counts.get('fixed', 0)} fixed[/green]   "
        f"[bold yellow]{counts.get('escalated', 0)} escalated[/bold yellow]   "
        f"[cyan]{counts.get('deescalated', 0)} downgraded[/cyan]   "
        f"[magenta]{counts.get('unverified', 0)} unverified[/magenta]   "
        f"[dim]{counts.get('unchanged', 0)} unchanged[/dim]",
        title="SCAN DIFF", border_style="cyan",
    ))

    table = Table(show_lines=False, header_style="bold magenta")
    table.add_column("Status", justify="left")
    table.add_column("Port", justify="center")
    table.add_column("Service")
    table.add_column("CVE")
    table.add_column("Severity", justify="center")
    table.add_column("Description")

    def _add(status: str, findings: list):
        style = _STATUS_STYLES.get(status, "")
        for finding in _sorted(findings):
            if status == "ESCALATED" or status == "DOWNGRADED":
                severity = (
                    f"{finding.get('severity_from') or '?'} → "
                    f"{finding.get('severity_to') or '?'}"
                )
            else:
                severity = print_severity_badge(finding.get("severity") or "LOW")
            port = finding.get("port")
            description = " ".join(str(finding.get("description") or "").split())[:70]
            table.add_row(
                f"[{style}]{status}[/{style}]" if style else status,
                str(port) if port is not None else "-",
                str(finding.get("service") or "-"),
                str(finding.get("cve_id") or "-"),
                severity,
                f"[{style}]{description}[/{style}]" if style else description,
            )

    _add("NEW", diff.get("new") or [])
    _add("ESCALATED", diff.get("escalated") or [])
    _add("DOWNGRADED", diff.get("deescalated") or [])
    _add("FIXED", diff.get("fixed") or [])
    _add("UNVERIFIED", diff.get("unverified") or [])
    if verbose:
        _add("UNCHANGED", diff.get("unchanged") or [])

    if table.row_count:
        console.print(table)
    else:
        console.print("[dim]No differences to list.[/dim]")

    if counts.get("unverified"):
        console.print(
            f"[magenta]Note:[/magenta] {counts['unverified']} finding(s) are "
            f"absent from scan #{scan_b} but the tool that finds them did not "
            "run in it. [bold]Do not read those as remediated.[/bold]"
        )
    if not verbose and counts.get("unchanged"):
        console.print(
            f"[dim]{counts['unchanged']} unchanged finding(s) not listed — "
            "pass --diff-verbose to include them.[/dim]"
        )


def generate_diff_report(diff: dict, output_path: str = None) -> str:
    """
    Write the plain-text diff to a file and return its path (None on
    failure).

    Defaults to output/<target>/diff_<a>_to_<b>.txt, alongside the target's
    other reports, using scan B's target — B is the later scan, so it is
    the one whose state the report describes.

    Never raises: a diff that could not be written is reported and None is
    returned, exactly like the txt/pdf writers.
    """
    import os

    from modules.utils.config import output_dir
    from modules.utils.display import print_error, print_success

    scan_a, scan_b = diff.get("scan_a"), diff.get("scan_b")
    meta_a, meta_b = scan_meta(scan_a), scan_meta(scan_b)

    if output_path is None:
        target = meta_b.get("target") or meta_a.get("target") or "unknown"
        try:
            output_path = os.path.join(
                output_dir(target), f"diff_{scan_a}_to_{scan_b}.txt"
            )
        except OSError as exc:
            print_error(f"[Diff] could not create the output directory: {exc}")
            return None

    header = [
        "AEGIS SCANNER — SCAN DIFF",
        "=" * 60,
        f"  Baseline : scan #{scan_a}  {meta_a.get('target') or '?'}  "
        f"[{meta_a.get('profile') or '?'}]  {meta_a.get('timestamp') or '?'}",
        f"  Current  : scan #{scan_b}  {meta_b.get('target') or '?'}  "
        f"[{meta_b.get('profile') or '?'}]  {meta_b.get('timestamp') or '?'}",
        "",
        f"  {diff.get('delta_summary') or ''}",
        "",
    ]

    try:
        body = "\n".join(header) + "\n" + render_diff(diff, verbose=True)
    except Exception as exc:
        print_error(f"[Diff] failed to render the diff report: {exc}")
        return None

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
    except OSError as exc:
        print_error(f"[Diff] could not write {output_path}: {exc}")
        return None

    print_success(f"[Diff] report written to {output_path}")
    return output_path


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
