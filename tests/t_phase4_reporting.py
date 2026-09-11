"""
Phase 4 — reporting verification.

  A  risk_report: top_risks ranking (risk over raw severity), plain-language
     rendering, environment risk posture, criticality override
  B  JSON report: schema-versioned, all keys always present, findings
     full-fidelity, by_confidence tally, round-trips through json
  C  SARIF report: valid 2.1.0 shape (runs/tool/driver/rules/results),
     level mapping, per-finding properties carry the enrichment, rank from
     risk, partialFingerprints from uid, serialises
  D  PDF structure: Executive Summary + Technical Findings parts, risk
     banner, top-risks section, per-finding EPSS/confidence, renders to a
     non-empty PDF
  E  retention: json/sarif filenames are recognised and grouped with their
     scan; html fixed-name is left alone
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reporting.risk_report import risk_posture, top_risks
from modules.reporting.report_json import build_json_report
from modules.reporting.report_sarif import build_sarif_report
from modules.reporting.report_pdf import render_html
from modules.reporting.retention import _parse_stored_name

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


def _summary(findings, **meta):
    base = {"id": 1, "target": "h", "profile": "full", "timestamp": "2026-09-11"}
    base.update(meta)
    by = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = str(f.get("severity", "")).upper()
        if s in by:
            by[s] += 1
    return {"scan_metadata": base, "total_findings": len(findings),
            "by_severity": by, "top_findings": findings, "findings": findings,
            "error": None}


FINDINGS = [
    {"finding_type": "cve", "description": "Apache CVE-2017-7679",
     "severity": "HIGH", "cve_id": "CVE-2017-7679", "cvss": 7.5,
     "epss_score": 0.9, "risk_score": 7.1, "confidence": "Potential",
     "remediation": "Upgrade Apache", "port": 80, "finding_uid": "aegis-cve-1"},
    {"finding_type": "sqlmap_finding", "description": "SQLi in id",
     "severity": "CRITICAL", "risk_score": 9.8, "cvss": 9.8,
     "confidence": "Confirmed", "remediation": "Parameterise queries",
     "endpoint": "http://h/x.php?id=1", "port": 80, "finding_uid": "aegis-sqli-2"},
    {"finding_type": "missing_security_header", "description": "Missing CSP",
     "severity": "MEDIUM", "confidence": "Confirmed", "port": 80,
     "finding_uid": "aegis-hdr-3"},
]


# --- A: risk_report ---------------------------------------------------
print("\nA  risk_report")
risks = top_risks(FINDINGS, limit=5)
check("top_risks returns all", len(risks) == 3)
check("critical/highest-risk ranks first", risks[0]["title"].startswith("SQLi"))
check("plain-language mentions action", "action" in risks[0]["plain_language"].lower())
check("potential flagged in prose",
      any("potential" in r["plain_language"].lower() for r in risks))
check("EPSS surfaced in prose",
      any("exploit" in r["plain_language"].lower() for r in risks))

posture = risk_posture(_summary(FINDINGS), "critical")
check("posture has env score", 0 < posture["environment_risk"]["score"] <= 100)
check("criticality override honoured", posture["criticality"] == "critical")
crit = risk_posture(_summary(FINDINGS), "critical")["environment_risk"]["score"]
low = risk_posture(_summary(FINDINGS), "low")["environment_risk"]["score"]
check("criticality changes score", crit > low)


# --- B: JSON ----------------------------------------------------------
print("\nB  JSON report")
j = build_json_report(_summary(FINDINGS), "high")
check("schema_version present", j["schema_version"] == "1.0")
for key in ("scan", "risk", "summary", "top_risks", "findings"):
    check(f"top-level key {key}", key in j)
check("risk.environment_risk.score always present",
      "score" in j["risk"]["environment_risk"])
check("by_confidence tallied",
      j["summary"]["by_confidence"].get("Confirmed") == 2)
check("findings full fidelity (epss present)",
      any(f.get("epss_score") == 0.9 for f in j["findings"]))
check("finding carries risk_score", any(f.get("risk_score") for f in j["findings"]))
check("JSON serialises", json.dumps(j, default=str) and True)
# empty scan still has all keys
je = build_json_report(_summary([]))
check("empty scan: risk score is 0 not missing",
      je["risk"]["environment_risk"]["score"] == 0.0)
check("empty scan: findings is []", je["findings"] == [])


# --- C: SARIF ---------------------------------------------------------
print("\nC  SARIF report")
s = build_sarif_report(_summary(FINDINGS))
check("sarif version 2.1.0", s["version"] == "2.1.0")
check("has $schema", "$schema" in s)
run = s["runs"][0]
check("driver name", run["tool"]["driver"]["name"] == "Aegis Scanner")
check("one rule per finding type", len(run["tool"]["driver"]["rules"]) == 3)
check("result count matches findings", len(run["results"]) == 3)
crit_res = [r for r in run["results"] if "SQLi" in r["message"]["text"]][0]
check("critical -> error level", crit_res["level"] == "error")
check("result properties carry confidence",
      crit_res["properties"]["confidence"] == "Confirmed")
check("result rank from risk", crit_res.get("rank") == 98.0)
check("partialFingerprints from uid",
      crit_res["partialFingerprints"]["aegisFindingUid"] == "aegis-sqli-2")
med = [r for r in run["results"] if "CSP" in r["message"]["text"]][0]
check("medium -> warning level", med["level"] == "warning")
check("SARIF serialises", json.dumps(s, default=str) and True)
check("invocation records target",
      run["invocations"][0]["properties"]["target"] == "h")


# --- D: PDF structure -------------------------------------------------
print("\nD  PDF structure")
html = render_html(_summary(FINDINGS))
check("Executive Summary part", "Executive Summary" in html)
check("Technical Findings part", "Technical Findings" in html)
check("risk banner rendered", "Environment Risk Score" in html)
check("top risks section", "Top Risks" in html)
check("confidence shown on card", "Confirmed" in html and "Potential" in html)
check("EPSS shown on card", "EPSS 90%" in html)
check("risk score shown on card", "Risk 9.8/10" in html)
try:
    from weasyprint import HTML
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "r.pdf")
    HTML(string=html).write_pdf(p)
    check("PDF renders non-empty", os.path.getsize(p) > 1000)
except ImportError:
    check("PDF renders non-empty (weasyprint absent — skipped)", True)


# --- E: retention -----------------------------------------------------
print("\nE  retention recognises machine formats")
check("json filename parsed",
      _parse_stored_name("report_full_h_5.json") == ("full", 5))
check("sarif filename parsed",
      _parse_stored_name("report_full_h_5.sarif") == ("full", 5))
check("txt still parsed", _parse_stored_name("report_full_h_5.txt") == ("full", 5))
check("fixed report.html left alone", _parse_stored_name("report.html") is None)
check("unrelated file ignored", _parse_stored_name("notes.txt") is None)


print("\n" + "=" * 60)
print(f"PASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
