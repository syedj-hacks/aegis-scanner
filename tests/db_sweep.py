#!/usr/bin/env python3
"""
tests/db_sweep.py
Whole-database mechanical audit. Renders EVERY scan in database/aegis.db and
checks it for the defect classes previous passes fixed:

    crashes             a scan whose summary/report/PDF build raises
    ambiguous cells     a rendered cell that is a bare dash or "none"/"unknown"
    duplicate lines     the same top-finding line rendered twice
    attribution         a finding credited to a tool that never ran for it,
                        or whose declared type no longer fits its columns
                        (modules/reporting/attribution.py)

The first three are the sweep smoke_test5-8 ran from a scratch directory.
The fourth is new in smoke_test9 and is here rather than in a separate
script for a specific reason: the §4.2 regression was missed because the
attribution question was nobody's job. Run as one command, it cannot be the
step someone forgets.

    python tests/db_sweep.py            # audit every scan
    python tests/db_sweep.py 138 139    # audit only these scan ids

Exit status is 0 only when every check passes, so this is usable as a gate.
"""
import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import get_scan_history, get_findings_for_scan
from modules.reporting.attribution import check_scan
from modules.reporting.report_pdf import _cover_html, _details_html, _top_findings_html
from modules.reporting.report_txt import render_report
from modules.reporting.summary import build_summary

AMBIGUOUS = (" : -", ": none", ": not scored", ": unknown", ": none")

# Attribution mismatches that are HISTORICAL FACT rather than a live defect.
# Listed by findings.id, with the reason, and still printed on every run —
# they are excluded from the exit status only so that a real, new mismatch
# is not lost in a permanently-red gate. Nothing here has been rewritten;
# see smoke_test9 §3.4 for why correcting them was declined.
#
#   row 1  scan 1, 2026-07-23 21:50, target example.com — a CVE-bearing row
#          on a scan labelled "quickscan" that was written the day BEFORE
#          the quickscan orchestrator's first commit (c071b97, 2026-07-24
#          04:15), with no description, no finding_type and a product/version
#          ("Apache 2.4.49") example.com does not run. Early db.py-layer
#          testing, not a scan.
#   row 4  scan 3, 2026-07-24 03:33, target scanme.nmap.org — same shape,
#          same window, ~40 minutes before that commit.
#
# quickscan performs no NVD lookup in the current code, so both rows are
# credited to a producer their profile does not run.
KNOWN_HISTORICAL = {1, 4}


def sweep(scan_ids=None):
    scans = get_scan_history()
    if scan_ids:
        wanted = {int(s) for s in scan_ids}
        scans = [s for s in scans if s["id"] in wanted]

    checked = crashed = bad_cells = dup_lines = 0
    attribution_issues = []
    historical = []

    for scan in sorted(scans, key=lambda s: s["id"]):
        sid = scan["id"]
        profile = scan["profile"]
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                summary = build_summary(sid, quiet=True)
            text = render_report(summary)
            _ = _details_html(summary) + _cover_html(summary) + _top_findings_html(summary)
        except Exception as exc:
            crashed += 1
            print(f"  CRASH scan {sid}: {type(exc).__name__}: {exc}")
            continue
        checked += 1

        hits = [ln for ln in text.splitlines()
                if any(a in ln.lower() for a in AMBIGUOUS)]
        # Description/Remediation bodies are prose, not cells.
        hits = [h for h in hits if ":" in h and len(h.strip()) < 120]
        if hits:
            bad_cells += len(hits)
            print(f"  scan {sid}: {len(hits)} ambiguous cell(s), e.g. {hits[0].strip()[:80]}")

        top = [ln for ln in text.splitlines()
               if ln.strip().startswith(tuple(f"{i}." for i in range(1, 11)))
               and "[" in ln]
        if len(top) != len(set(top)):
            dup_lines += 1
            print(f"  scan {sid}: DUPLICATE top-finding line(s)")

        # Attribution runs against the STORED rows, not the rendered summary:
        # the question is whether each row is credited to a tool that could
        # have produced it, and build_summary()'s de-duplication would hide a
        # row rather than answer that.
        issues = check_scan(sid, profile, get_findings_for_scan(sid))
        for issue in issues:
            known = " [known historical]" if issue["finding_id"] in KNOWN_HISTORICAL else ""
            print(f"  scan {sid} ({profile}) row {issue['finding_id']}: "
                  f"{issue['issue']} — {issue['detail']}{known}")
        attribution_issues.extend(
            i for i in issues if i["finding_id"] not in KNOWN_HISTORICAL
        )
        historical.extend(i for i in issues if i["finding_id"] in KNOWN_HISTORICAL)

    print(f"\nscans rendered      : {checked}/{len(scans)}")
    print(f"crashes             : {crashed}")
    print(f"ambiguous cells     : {bad_cells}")
    print(f"dup top-find scans  : {dup_lines}")
    print(f"attribution issues  : {len(attribution_issues)}")
    print(f"  of which historical: {len(historical)} (known, not counted — see KNOWN_HISTORICAL)")

    if attribution_issues:
        by_issue = {}
        for issue in attribution_issues:
            by_issue[issue["issue"]] = by_issue.get(issue["issue"], 0) + 1
        for name, count in sorted(by_issue.items()):
            print(f"    {name:<20} {count}")

    return crashed + bad_cells + dup_lines + len(attribution_issues)


if __name__ == "__main__":
    sys.exit(1 if sweep(sys.argv[1:]) else 0)
