"""
smoke_test10 verification — the per-scan tools-run record (Phase 2).

The gap this closes (smoke_test9 §4.2/§8 item 1): attribution's check 1 could
only ask "does this finding's profile WIRE IN the credited tool", not "did
that tool actually RUN on this specific scan". A finding credited to a tool
the profile wires in but that was skipped, failed, or never reached on that
run passed the check anyway. The scan_tools_run table records what actually
ran, and check 1 now uses it.

  A  classify_tool_outcome() — the single ran/skipped/failed predicate the
     summary panel and the persisted record both go through
  B  the database layer: record_scan_tools() / get_scan_tools_run(), the
     empty-record and absent-table cases
  C  ran_producer_set() — normalisation (nmap) and the untracked producer
     (nvd) that can never be recorded as "ran"
  D  check_finding() with a per-scan ran-set: a tool that ran passes; a tool
     that was SKIPPED or FAILED on that run now FAILS (the whole point)
  E  check_scan() end to end through a real temp database, including the
     historical-scan fallback for a scan with no record
  F  the profile-level fallback is byte-for-byte the old behaviour when no
     ran-set is supplied (existing scans and callers are unaffected)
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database.db as dbmod
from modules.profiles._common import classify_tool_outcome
from modules.reporting.attribution import (
    check_finding, check_scan, ran_producer_set,
    UNTRACKED_PRODUCERS, _PRODUCER_ALIASES,
)

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


def row(**overrides):
    base = {
        "id": 1, "scan_id": 1, "port": None, "service": None, "version": None,
        "cve_id": None, "cvss": None, "severity": None, "description": None,
        "remediation": None, "finding_type": None, "product": None,
        "parameter": None, "payload": None, "evidence": None, "endpoint": None,
        "reference": None,
    }
    base.update(overrides)
    return base


print("=== A. classify_tool_outcome: one ran/skipped/failed predicate ===")

check("a clean result ran", classify_tool_outcome({"tool": "nmap"}) == "ran")
check("an errored result failed",
      classify_tool_outcome({"tool": "nmap", "error": "boom"}) == "failed")
check("a skipped result is skipped, not failed",
      classify_tool_outcome({"tool": "zaproxy", "skipped": True,
                             "error": "skipped by user (Ctrl+C)"}) == "skipped")
check("skip wins over error (the zap_wrap skip-flag contract)",
      classify_tool_outcome({"skipped": True, "error": "x"}) == "skipped")

print("\n=== B. database layer: record + read back ===")

tmpdir = tempfile.mkdtemp(prefix="aegis_t10_")
tmpdb = os.path.join(tmpdir, "t.db")
orig_path = dbmod.DB_PATH
try:
    dbmod.DB_PATH = tmpdb
    dbmod.init_db()

    sid = dbmod.insert_scan("172.28.0.20", "deepscan")
    dbmod.record_scan_tools(sid, [
        {"tool_name": "nmap", "port": None, "outcome": "ran"},
        {"tool_name": "nikto", "port": 80, "outcome": "ran"},
        {"tool_name": "zaproxy", "port": 80, "outcome": "skipped"},
        {"tool_name": "sqlmap", "port": 80, "outcome": "failed"},
    ])
    recs = dbmod.get_scan_tools_run(sid)
    check("all four records persisted", len(recs) == 4, len(recs))
    by_tool = {r["tool_name"]: r["outcome"] for r in recs}
    check("nmap recorded as ran", by_tool.get("nmap") == "ran", by_tool)
    check("zaproxy recorded as skipped", by_tool.get("zaproxy") == "skipped", by_tool)
    check("sqlmap recorded as failed", by_tool.get("sqlmap") == "failed", by_tool)
    check("the nikto record carries its port",
          any(r["tool_name"] == "nikto" and r["port"] == 80 for r in recs), recs)

    # A scan that never recorded anything reads back empty, not an error.
    sid_empty = dbmod.insert_scan("172.28.0.20", "deepscan")
    check("a scan with no record reads back []",
          dbmod.get_scan_tools_run(sid_empty) == [], dbmod.get_scan_tools_run(sid_empty))

    # record_scan_tools ignores malformed rows rather than raising.
    dbmod.record_scan_tools(sid_empty, [{"tool_name": "", "outcome": "ran"},
                                        {"port": 80, "outcome": "ran"}])
    check("rows with no tool_name are dropped, not inserted",
          dbmod.get_scan_tools_run(sid_empty) == [], dbmod.get_scan_tools_run(sid_empty))

    # Defensive: a database file that predates the table (no scan_tools_run)
    # must read back [] so the attribution check falls back instead of crashing.
    legacy = os.path.join(tmpdir, "legacy.db")
    conn = sqlite3.connect(legacy)
    conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, "
                 "timestamp TEXT, profile TEXT)")
    conn.commit()
    conn.close()
    dbmod.DB_PATH = legacy
    check("get_scan_tools_run tolerates a missing table",
          dbmod.get_scan_tools_run(1) == [], "raised or non-empty")
    dbmod.DB_PATH = tmpdb
finally:
    dbmod.DB_PATH = orig_path

print("\n=== C. ran_producer_set: normalisation + untracked producers ===")

# Only tools with outcome 'ran' count; skipped/failed do not.
ran = ran_producer_set([
    {"tool_name": "nmap", "outcome": "ran"},
    {"tool_name": "zaproxy", "outcome": "skipped"},
    {"tool_name": "sqlmap", "outcome": "failed"},
], "deepscan")
check("a skipped tool is not in the ran-set", "zaproxy" not in ran, ran)
check("a failed tool is not in the ran-set", "sqlmap" not in ran, ran)
check("a tool that ran is in the ran-set", "nmap" in ran, ran)

# nmap_service_detect normalises to the producer 'nmap'.
check("nmap_service_detect is a known alias for nmap",
      _PRODUCER_ALIASES.get("nmap_service_detect") == "nmap")
ran_svc = ran_producer_set([{"tool_name": "nmap_service_detect", "outcome": "ran"}],
                           "deepscan")
check("a service-detect-only run still credits producer 'nmap'",
      "nmap" in ran_svc, ran_svc)

# The XSS DAST pass runs nuclei under the name 'nuclei-xss'; an xss_finding
# (producer 'nuclei') must be credited to it.
check("nuclei-xss is a known alias for nuclei",
      _PRODUCER_ALIASES.get("nuclei-xss") == "nuclei")
ran_xss = ran_producer_set([{"tool_name": "nuclei-xss", "outcome": "ran"}], "deepscan")
check("a DAST-only nuclei run still credits producer 'nuclei'",
      "nuclei" in ran_xss, ran_xss)
check("an xss_finding passes when only the nuclei-xss step ran",
      check_finding(row(finding_type="xss_finding", description="reflected XSS",
                        port=80, parameter="q", payload="<script>"),
                    "deepscan", ran_tools=ran_xss) == [],
      check_finding(row(finding_type="xss_finding", description="x", port=80),
                    "deepscan", ran_tools=ran_xss))

# nvd never appears in tool_results, so it is added for any profile that does
# CVE enrichment — otherwise every cve row would be falsely flagged.
check("nvd is an untracked producer", "nvd" in UNTRACKED_PRODUCERS)
check("nvd is granted to deepscan even with no nvd record",
      "nvd" in ran_producer_set([{"tool_name": "nmap", "outcome": "ran"}], "deepscan"))
check("nvd is NOT granted to stealthscan (it runs no CVE lookup)",
      "nvd" not in ran_producer_set([{"tool_name": "nmap", "outcome": "ran"}],
                                    "stealthscan"))

print("\n=== D. check_finding with a per-scan ran-set (the gap) ===")

zap = row(finding_type="zap_finding", description="X-Frame-Options missing", port=80)

# The tool ran on this scan -> passes.
ran_with_zap = {"nmap", "nikto", "zaproxy", "nvd"}
check("a zap finding on a scan where ZAP ran passes",
      check_finding(zap, "deepscan", ran_tools=ran_with_zap) == [],
      check_finding(zap, "deepscan", ran_tools=ran_with_zap))

# The tool was SKIPPED on this scan -> now FAILS (the entire point of phase 2).
ran_without_zap = {"nmap", "nikto", "nvd"}   # zaproxy skipped, so absent
skipped_case = check_finding(zap, "deepscan", ran_tools=ran_without_zap)
check("a zap finding whose ZAP was SKIPPED on this run is now flagged",
      any(i["issue"] == "tool_never_ran" for i in skipped_case), skipped_case)
check("the flag is stamped per-scan basis",
      skipped_case and skipped_case[0].get("basis") == "per-scan", skipped_case)
check("the per-scan detail names ZAP and says it did not run on this scan",
      skipped_case and "zaproxy" in skipped_case[0]["detail"]
      and "this scan" in skipped_case[0]["detail"], skipped_case)

# Crucially: the SAME finding in the SAME profile passes the PROFILE-level
# check (deepscan wires ZAP in) — proving the per-scan basis catches what the
# profile basis structurally cannot.
check("the identical finding passes the profile-level check (the blind spot)",
      check_finding(zap, "deepscan") == [],
      check_finding(zap, "deepscan"))

# A FAILED tool is caught the same way as a skipped one.
sqlmap_find = row(finding_type="sqlmap_finding", description="SQLi confirmed", port=80)
ran_sqlmap_failed = {"nmap", "nikto", "nvd"}   # sqlmap failed, so absent
failed_case = check_finding(sqlmap_find, "deepscan", ran_tools=ran_sqlmap_failed)
check("a sqlmap finding whose sqlmap FAILED on this run is flagged",
      any(i["issue"] == "tool_never_ran" for i in failed_case), failed_case)

# A cve finding passes on a per-scan basis thanks to the nvd grant, even
# though nvd is never in the ran-set.
cve = row(finding_type="cve", cve_id="CVE-2016-8743", port=80)
ran_for_cve = ran_producer_set([{"tool_name": "nmap", "outcome": "ran"}], "deepscan")
check("a cve finding passes per-scan via the nvd grant",
      check_finding(cve, "deepscan", ran_tools=ran_for_cve) == [],
      check_finding(cve, "deepscan", ran_tools=ran_for_cve))

# An nmap open_port finding passes when only nmap_service_detect ran.
port_find = row(finding_type="open_port", port=80, service="http")
ran_svc_only = ran_producer_set([{"tool_name": "nmap_service_detect", "outcome": "ran"}],
                                "deepscan")
check("an open_port finding passes when only the service-detect nmap step ran",
      check_finding(port_find, "deepscan", ran_tools=ran_svc_only) == [],
      check_finding(port_find, "deepscan", ran_tools=ran_svc_only))

print("\n=== E. check_scan end to end through a real temp database ===")

dbmod.DB_PATH = tmpdb
try:
    # Scan 1: ZAP was skipped, and a zap_finding is stored crediting it.
    s_skip = dbmod.insert_scan("172.28.0.20", "deepscan")
    dbmod.record_scan_tools(s_skip, [
        {"tool_name": "nmap", "port": None, "outcome": "ran"},
        {"tool_name": "nikto", "port": 80, "outcome": "ran"},
        {"tool_name": "zaproxy", "port": 80, "outcome": "skipped"},
    ])
    zap_row = row(id=101, scan_id=s_skip, finding_type="zap_finding",
                  description="X-Frame-Options missing", port=80)
    issues = check_scan(s_skip, "deepscan", [zap_row])
    check("check_scan flags the zap finding on the skipped-ZAP scan",
          any(i["issue"] == "tool_never_ran" for i in issues), issues)
    check("...on a per-scan basis",
          issues and issues[0].get("basis") == "per-scan", issues)

    # Scan 2: ZAP actually ran; the same finding is correctly attributed.
    s_ran = dbmod.insert_scan("172.28.0.20", "deepscan")
    dbmod.record_scan_tools(s_ran, [
        {"tool_name": "nmap", "port": None, "outcome": "ran"},
        {"tool_name": "zaproxy", "port": 80, "outcome": "ran"},
    ])
    zap_row2 = row(id=102, scan_id=s_ran, finding_type="zap_finding",
                   description="X-Frame-Options missing", port=80)
    check("check_scan passes the zap finding on the scan where ZAP ran",
          check_scan(s_ran, "deepscan", [zap_row2]) == [],
          check_scan(s_ran, "deepscan", [zap_row2]))

    # Scan 3: NO tools-run record (a historical scan) -> profile-level fallback,
    # no crash, and a deepscan zap finding is accepted as before.
    s_hist = dbmod.insert_scan("172.28.0.20", "deepscan")
    zap_row3 = row(id=103, scan_id=s_hist, finding_type="zap_finding",
                   description="X-Frame-Options missing", port=80)
    hist_issues = check_scan(s_hist, "deepscan", [zap_row3])
    check("a scan with no record falls back to the profile check without crashing",
          hist_issues == [], hist_issues)

    # Scan 3 fallback still catches the profile-level class: a nikto finding on
    # a stealthscan with no record is flagged, on a profile basis.
    s_hist2 = dbmod.insert_scan("172.28.0.20", "stealthscan")
    nikto_row = row(id=104, scan_id=s_hist2, finding_type="nikto_finding",
                    description="x", port=80)
    fb = check_scan(s_hist2, "stealthscan", [nikto_row])
    check("the fallback still flags a nikto finding in stealthscan",
          any(i["issue"] == "tool_never_ran" for i in fb), fb)
    check("...on a profile basis",
          fb and fb[0].get("basis") == "profile", fb)
finally:
    dbmod.DB_PATH = orig_path

print("\n=== F. no ran-set supplied == the old profile-level behaviour ===")

# Every existing 2-arg call site and test must be unchanged.
check("a stealthscan open_port row still passes (2-arg call)",
      check_finding(row(port=80, service="http", finding_type="open_port"),
                    "stealthscan") == [])
nikto_stealth = check_finding(row(finding_type="nikto_finding", description="x", port=80),
                              "stealthscan")
check("a nikto finding in stealthscan is still flagged (2-arg call)",
      any(i["issue"] == "tool_never_ran" for i in nikto_stealth), nikto_stealth)
check("...and stamped profile basis",
      nikto_stealth and nikto_stealth[0].get("basis") == "profile", nikto_stealth)
check("an unknown profile with no ran-set is still 'cannot verify'",
      check_finding(row(finding_type="nikto_finding", description="x"),
                    "webaudit-helper-test") == [])

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
