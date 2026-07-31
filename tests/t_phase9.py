"""
smoke_test9 verification.

  A  the CVE duplicate-insert fix (Phase 1) at the COLLECTION layer
  B  the same fix through the real database, not just in memory
  C  dedup SAFETY: two legitimately different findings sharing a CVE must
     both survive — same category of check as smoke_test7's t_phase2 §F
  D  the render-time dedup guard is still in place as a safety net
  E  attribution correctness (Phase 3): the new whole-database check class
  F  the exact smoke_test8 §4.2 regression, reproduced and caught
  G  mapping/drift guards so a new finding type or profile tool cannot
     silently escape the attribution check
  H  the CURRENT database: every stored row, every scan

The CVE fixtures in A/B/C are the real NVD results from scan 140
(172.28.0.20, deepscan, 2026-07-25) — the run that reproduced the duplicate
for the third time. Nothing here is invented tool output.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.profiles.deepscan import _findings_from_cves
from modules.reporting.summary import (
    _enrich,
    FINDING_TYPE_TOOL, deduplicate_findings, field_display,
)
from modules.reporting.attribution import (
    FINDING_TYPE_PRODUCERS, NON_FINDING_TOOLS, PROFILE_PRODUCERS,
    check_finding, check_scan, producers_for, profile_producers,
)
from modules.enrichment.remediation import finding_kind as remediation_kind
from modules.enrichment.severity import finding_kind as severity_kind

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


# --- Real NVD results from scan 140 ---------------------------------------
# Path 1, service detection: nmap product "Apache httpd" 2.4.25
#     [CVE] Querying NVD for 'Apache httpd 2.4.25'   -> 1 CVE
# Path 2, header fingerprint: Server header parsed to "Apache" 2.4.25
#     [CVE] Querying NVD for 'apache http server 2.4.25' -> 3 CVEs
SERVICE_PATH_CVES = [
    {"cve_id": "CVE-2016-8743", "product": "Apache httpd", "version": "2.4.25",
     "cvss_score": 7.5, "cvss_severity": "HIGH",
     "description": "Apache HTTP Server ... permits ambiguous HTTP requests.",
     "references": []},
]
HEADER_PATH_CVES = [
    {"cve_id": "CVE-2017-7659", "product": "Apache", "version": "2.4.25",
     "cvss_score": 7.5, "cvss_severity": "HIGH",
     "description": "A maliciously constructed HTTP/2 request could cause "
                    "mod_http2 to dereference a NULL pointer.",
     "references": []},
    {"cve_id": "CVE-2016-8743", "product": "Apache", "version": "2.4.25",
     "cvss_score": 7.5, "cvss_severity": "HIGH",
     "description": "Apache HTTP Server ... permits ambiguous HTTP requests.",
     "references": []},
    {"cve_id": "CVE-2016-4975", "product": "Apache", "version": "2.4.25",
     "cvss_score": 6.1, "cvss_severity": "MEDIUM",
     "description": "Possible CRLF injection allowing HTTP response splitting.",
     "references": []},
]

print("=== A. collection-time CVE dedup (Phase 1) ===")

seen = set()
first = _findings_from_cves(SERVICE_PATH_CVES, 80, "http", seen=seen)
second = _findings_from_cves(HEADER_PATH_CVES, 80, "Apache/2.4.25 (Debian)", seen=seen)

check("service-detect path records its 1 CVE", len(first) == 1, len(first))
check("header path records only the 2 CVEs the first lookup missed",
      len(second) == 2, [f["cve_id"] for f in second])
check("the duplicate CVE is the one dropped",
      "CVE-2016-8743" not in [f["cve_id"] for f in second],
      [f["cve_id"] for f in second])
check("nothing else is dropped — CVE-2017-7659 and CVE-2016-4975 survive",
      {f["cve_id"] for f in second} == {"CVE-2017-7659", "CVE-2016-4975"},
      [f["cve_id"] for f in second])
check("4 NVD hits across both paths -> 3 findings, not 4",
      len(first) + len(second) == 3, len(first) + len(second))
check("the surviving copy is the service-detect one (richer product)",
      first[0]["product"] == "Apache httpd", first[0].get("product"))

# The two paths disagree about the product string for the SAME software —
# which is why a product+version-keyed cache could not have fixed this.
check("the two paths really do name the product differently",
      SERVICE_PATH_CVES[0]["product"] != HEADER_PATH_CVES[1]["product"],
      (SERVICE_PATH_CVES[0]["product"], HEADER_PATH_CVES[1]["product"]))

# Without a shared set, the old behaviour is unchanged (a caller that does
# not opt in still gets every CVE).
no_seen = (_findings_from_cves(SERVICE_PATH_CVES, 80, "http")
           + _findings_from_cves(HEADER_PATH_CVES, 80, "http"))
check("seen=None keeps the pre-fix behaviour (4 findings)", len(no_seen) == 4, len(no_seen))

# A CVE with no id cannot be keyed, and must not be silently swallowed.
unkeyed = _findings_from_cves([{"cve_id": None, "product": "x", "description": "d"},
                               {"cve_id": None, "product": "x", "description": "d"}],
                              80, "http", seen=set())
check("a CVE with no id is never dropped by the guard", len(unkeyed) == 2, len(unkeyed))

print("\n=== B. through the real database, not just in memory ===")
import database.db as dbmod

tmpdb = os.path.join(tempfile.mkdtemp(prefix="aegis_t9_"), "t.db")
orig_path = dbmod.DB_PATH
try:
    dbmod.DB_PATH = tmpdb
    dbmod.init_db()

    sid_fixed = dbmod.insert_scan("172.28.0.20", "deepscan")
    shared = set()
    dbmod.insert_findings_bulk(sid_fixed, _findings_from_cves(
        SERVICE_PATH_CVES, 80, "http", seen=shared))
    dbmod.insert_findings_bulk(sid_fixed, _findings_from_cves(
        HEADER_PATH_CVES, 80, "Apache/2.4.25 (Debian)", seen=shared))

    rows = dbmod.get_findings_for_scan(sid_fixed)
    dup = [r for r in rows if r["cve_id"] == "CVE-2016-8743"]
    check("exactly ONE stored row for the duplicated CVE", len(dup) == 1, len(dup))
    check("3 rows stored in total", len(rows) == 3, len(rows))
    check("all three CVEs are present in the database",
          {r["cve_id"] for r in rows} ==
          {"CVE-2016-8743", "CVE-2017-7659", "CVE-2016-4975"},
          sorted(r["cve_id"] for r in rows))
    check("the stored rows carry finding_type 'cve'",
          all(r["finding_type"] == "cve" for r in rows),
          [r["finding_type"] for r in rows])

    # The pre-fix path, for contrast: no shared set, both inserts land.
    sid_prefix = dbmod.insert_scan("172.28.0.20", "deepscan")
    dbmod.insert_findings_bulk(sid_prefix, _findings_from_cves(SERVICE_PATH_CVES, 80, "http"))
    dbmod.insert_findings_bulk(sid_prefix, _findings_from_cves(HEADER_PATH_CVES, 80, "http"))
    prefix_rows = dbmod.get_findings_for_scan(sid_prefix)
    prefix_dup = [r for r in prefix_rows if r["cve_id"] == "CVE-2016-8743"]
    check("without the shared set the duplicate row IS written (the bug)",
          len(prefix_dup) == 2, len(prefix_dup))
finally:
    dbmod.DB_PATH = orig_path

print("\n=== C. dedup safety: same CVE, different context, keep BOTH ===")

# Same CVE on two different ports — two services, two facts.
seen_ports = set()
p80 = _findings_from_cves(SERVICE_PATH_CVES, 80, "http", seen=seen_ports)
p8080 = _findings_from_cves(SERVICE_PATH_CVES, 8080, "http-alt", seen=seen_ports)
check("same CVE on port 80 and port 8080 -> BOTH recorded",
      len(p80) == 1 and len(p8080) == 1, (len(p80), len(p8080)))
check("the two carry their own ports",
      p80[0]["port"] == 80 and p8080[0]["port"] == 8080,
      (p80[0]["port"], p8080[0]["port"]))

# Same CVE, no port recorded at all, on two different services: (cve, None)
# collides, and that is the deliberate, documented limit of the key.
seen_none = set()
n1 = _findings_from_cves(SERVICE_PATH_CVES, None, "http", seen=seen_none)
n2 = _findings_from_cves(SERVICE_PATH_CVES, None, "https", seen=seen_none)
check("two portless copies of one CVE collapse (documented key limit)",
      len(n1) == 1 and len(n2) == 0, (len(n1), len(n2)))

# Different CVEs on the same port never collide.
seen_multi = set()
multi = _findings_from_cves(HEADER_PATH_CVES, 80, "http", seen=seen_multi)
check("three different CVEs on one port all survive", len(multi) == 3, len(multi))

print("\n=== D. the render-time guard is still there (safety net) ===")
pair = [
    {"finding_type": "cve", "port": 80, "cve_id": "CVE-2016-8743",
     "severity": "HIGH", "description": "same"},
    {"finding_type": "cve", "port": 80, "cve_id": "CVE-2016-8743",
     "severity": "HIGH", "description": "same"},
]
collapsed = deduplicate_findings(list(pair), target="t", scan_id=0, quiet=True)
check("an identical pair still collapses at render time", len(collapsed) == 1, len(collapsed))
different_ports = deduplicate_findings(
    [pair[0], dict(pair[1], port=8080)], target="t", scan_id=0, quiet=True)
check("the render guard still keeps the same CVE on two ports",
      len(different_ports) == 2, len(different_ports))

print("\n=== E. attribution correctness (Phase 3) ===")

# A row exactly as SQLite hands it back: every column present, most NULL.
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


stealth_port = row(port=80, service="http", finding_type="open_port")
check("a stealthscan open-port row is correctly attributed",
      check_finding(stealth_port, "stealthscan") == [],
      check_finding(stealth_port, "stealthscan"))

check("a nikto finding in deepscan is fine",
      check_finding(row(finding_type="nikto_finding", description="x", port=80),
                    "deepscan") == [])

nikto_in_stealth = check_finding(
    row(finding_type="nikto_finding", description="x", port=80), "stealthscan")
check("a nikto finding in stealthscan is flagged",
      any(i["issue"] == "tool_never_ran" for i in nikto_in_stealth), nikto_in_stealth)
check("the flag names the tool the reader would have seen",
      "nikto" in (nikto_in_stealth[0]["detail"] if nikto_in_stealth else ""),
      nikto_in_stealth)

check("a zap finding in webaudit is flagged (webaudit does not run ZAP)",
      any(i["issue"] == "tool_never_ran"
          for i in check_finding(row(finding_type="zap_finding", description="x"),
                                 "webaudit")))
check("the same zap finding in deepscan is fine",
      check_finding(row(finding_type="zap_finding", description="x"), "deepscan") == [])

check("an unknown profile is 'cannot verify', not a mismatch",
      check_finding(row(finding_type="nikto_finding", description="x"),
                    "webaudit-helper-test") == [])

# Field signature — the guard aimed at the NEXT shared column.
check("a cve row with no cve_id is flagged",
      any(i["issue"] == "field_signature"
          for i in check_finding(row(finding_type="cve", port=80), "deepscan")))
check("a cve row with a cve_id is not",
      check_finding(row(finding_type="cve", cve_id="CVE-1-1", port=80), "deepscan") == [])
sig = check_finding(row(finding_type="open_port", port=80, reference="http://x"),
                    "stealthscan")
check("a reference populated on an open_port row is flagged",
      any(i["issue"] == "field_signature" for i in sig), sig)
# CVSS on a missing_security_header is now LEGAL, not a violation: item 6
# (modules/enrichment/cvss.py) computes a local CVSS v3.1 vector for exactly
# these types. This assertion previously required the opposite; it was
# updated the day the scoring engine landed, together with
# summary._NOT_APPLICABLE["cvss"], which no longer lists the scored types.
check("a cvss populated on a missing_security_header row is NOW allowed (item 6)",
      not any(i["issue"] == "field_signature"
              for i in check_finding(row(finding_type="missing_security_header",
                                         description="x", cvss=4.7), "webaudit")))
# ...but a cvss on a type cvss.py deliberately leaves UNSCORED (open_port is
# exposure, not an assessed weakness) is still a signature violation, so the
# check still has teeth for the types that really cannot carry one.
check("a cvss populated on an open_port row is still flagged",
      any(i["issue"] == "field_signature"
          for i in check_finding(row(finding_type="open_port", port=80, cvss=9.8),
                                 "stealthscan")))

# The two classifiers are documented as one contract.
shapes = [
    row(finding_type="cve", cve_id="CVE-1-1"),
    row(finding_type="nikto_finding", description="x"),
    row(port=80, service="http"),
    row(port=80, service="http", product="nginx", version="1.2"),
    row(description="d", reference="http://x"),
    {"type": "discovered_path", "path": "/admin"},
    {"script_id": "ssl-enum-ciphers", "output": "x"},
    {},
]
disagree = [s for s in shapes if remediation_kind(s) != severity_kind(s)]
check("severity.py and remediation.py classify every shape identically",
      not disagree, [(remediation_kind(s), severity_kind(s)) for s in disagree])

print("\n=== F. the smoke_test8 §4.2 regression, reproduced ===")

# The bug: a shared column is added, every SQLite row carries it, and a
# classifier keyed on the KEY BEING PRESENT relabels unrelated findings.
# Reproduced by giving an open-port row a truthy value in the shared column
# — the state the buggy classifier believed every row was in.
#
# Classified through summary._enrich(), which is what a report classifies:
# it fills a NULL description with the derived sentence, and the buggy
# branch needed a description before it could claim the row. Checking the
# raw row instead would not reproduce the bug at all — the reason
# attribution.check_finding() enriches before classifying.
relabelled = _enrich(row(port=80, service="http", reference="http://cirt.net/1"))
check("a truthy shared column DOES still classify as nikto (by design)",
      remediation_kind(relabelled) == "nikto_finding", remediation_kind(relabelled))
caught = check_finding(relabelled, "stealthscan")
check("...and the attribution check CATCHES it in stealthscan",
      any(i["issue"] == "tool_never_ran" for i in caught), caught)
check("the caught issue names nikto and the profile",
      caught and "nikto" in caught[0]["detail"] and "stealthscan" in caught[0]["detail"],
      caught)

# The fixed classifiers: a row that merely CARRIES the column (NULL, as
# every real stealthscan row does) is not relabelled at all.
untouched = row(port=80, service="http")
check("a row carrying the column as NULL is not relabelled",
      remediation_kind(untouched) == "open_port", remediation_kind(untouched))
check("...and passes attribution in stealthscan",
      check_finding(untouched, "stealthscan") == [])
check("a row that DECLARES its type is never shape-sniffed at all",
      remediation_kind(row(finding_type="open_port", port=80,
                           reference="http://cirt.net/1")) == "open_port")

# The second instance this pass found: wordpress_fingerprinted is raised by
# gobuster's /wp-* marker, not by wpscan — and webaudit never runs wpscan.
check("wordpress_fingerprinted is credited to gobuster, not wpscan",
      FINDING_TYPE_TOOL["wordpress_fingerprinted"] == "gobuster",
      FINDING_TYPE_TOOL["wordpress_fingerprinted"])
check("a wordpress fingerprint in webaudit now passes attribution",
      check_finding(row(finding_type="wordpress_fingerprinted", port=443,
                        description="WordPress installation fingerprinted"),
                    "webaudit") == [],
      check_finding(row(finding_type="wordpress_fingerprinted", port=443), "webaudit"))
check("crediting it to wpscan would have failed in webaudit",
      "wpscan" not in profile_producers("webaudit"))
check("field_display now names gobuster on that row",
      field_display({"finding_type": "wordpress_fingerprinted"}, "service")
      == "not determined by gobuster",
      field_display({"finding_type": "wordpress_fingerprinted"}, "service"))

# sslyze findings had no tool mapping at all before this pass.
check("sslyze_finding has a tool mapping", FINDING_TYPE_TOOL.get("sslyze_finding") == "sslyze")
check("an sslyze finding in compliance passes attribution",
      check_finding(row(finding_type="sslyze_finding", port=443,
                        description="Legacy protocol: TLS 1.0"), "compliance") == [])
check("an sslyze finding in deepscan is flagged (deepscan runs no sslyze)",
      any(i["issue"] == "tool_never_ran"
          for i in check_finding(row(finding_type="sslyze_finding", port=443,
                                     description="x"), "deepscan")))

print("\n=== G. mapping + drift guards ===")

missing_producer = sorted(set(FINDING_TYPE_TOOL) - set(FINDING_TYPE_PRODUCERS))
check("every FINDING_TYPE_TOOL entry has a producer mapping",
      not missing_producer, missing_producer)
extra_producer = sorted(set(FINDING_TYPE_PRODUCERS) - set(FINDING_TYPE_TOOL))
check("every producer mapping has a FINDING_TYPE_TOOL entry",
      not extra_producer, extra_producer)

unknown_producers = {
    t: sorted(p) for t, p in FINDING_TYPE_PRODUCERS.items()
    if not p <= set().union(*PROFILE_PRODUCERS.values())
}
check("no finding type is produced by a tool no profile runs",
      not unknown_producers, unknown_producers)

# Every type any profile emits in code must be attribution-checkable.
import re
emitted = set()
for dirpath, _dirs, files in os.walk(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules")):
    for name in files:
        if not name.endswith(".py"):
            continue
        with open(os.path.join(dirpath, name)) as fh:
            emitted.update(re.findall(r'"type": "([a-z_]+)"', fh.read()))
# log_finding() types that are never persisted as findings rows.
emitted -= {"dns_resolution", "osint_email", "osint_host", "subdomain", "cve"}
unmapped = sorted(t for t in emitted if t and t not in FINDING_TYPE_PRODUCERS)
check("every finding type emitted anywhere in modules/ is mapped",
      not unmapped, unmapped)

# _WIRED_TOOLS must not drift away from PROFILE_PRODUCERS. deepscan is
# excluded: its _AVAILABLE_TOOLS is the codebase-wide set used for warnings,
# not a list of what it runs.
from modules.profiles import quickscan as m_quick, stealth as m_stealth
from modules.profiles import compliance as m_comp, webaudit as m_web

for profile, module in (("quickscan", m_quick), ("stealthscan", m_stealth),
                        ("compliance", m_comp), ("webaudit", m_web)):
    drifted = sorted((module._WIRED_TOOLS - NON_FINDING_TOOLS) - PROFILE_PRODUCERS[profile])
    check(f"{profile}: every wired tool is a declared producer", not drifted, drifted)

check("producers_for() is case/whitespace tolerant",
      producers_for("  CVE  ") == {"nvd"}, producers_for("  CVE  "))
check("profile_producers() returns None for an unknown profile",
      profile_producers("not-a-profile") is None)

print("\n=== H. the CURRENT database: every row, every scan ===")
dbmod.DB_PATH = orig_path
from database.db import get_scan_history, get_findings_for_scan

KNOWN_HISTORICAL = {1, 4}   # see tests/db_sweep.py for the full note
all_issues = []
scans = get_scan_history()
for scan in scans:
    all_issues.extend(check_scan(scan["id"], scan["profile"],
                                 get_findings_for_scan(scan["id"])))

live = [i for i in all_issues if i["finding_id"] not in KNOWN_HISTORICAL]
historical = [i for i in all_issues if i["finding_id"] in KNOWN_HISTORICAL]
check(f"zero live attribution mismatches across {len(scans)} scans",
      not live, live[:5])
check("the 2 known historical rows are still the only exceptions",
      len(historical) == 2, historical)
check("every scan in the database was checked", len(scans) > 100, len(scans))

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
