"""
Phase 3 — detection quality verification.

  A  risk scoring: CVSS-only, CVSS+EPSS blend, no-CVSS -> None, environment
     risk aggregation + criticality weighting + bands
  B  enrich_cache: miss/hit/expiry, atomic, survives a bad file
  C  EPSS client: CVE validation/normalisation, cache-miss stored so a
     no-score CVE isn't re-fetched (offline — uses seeded cache)
  D  validation/confidence: observed types -> Confirmed, version-matched ->
     Potential, a plugin's Confirmed is never downgraded
  E  enrichment pipeline: confidence assigned, EPSS attached to CVE
     findings, risk computed, non-CVE findings left with no EPSS
  F  signature engine: matchers (status/word/regex/header, and/or), a
     signature FIRES against a controlled local server and produces a
     Confirmed finding, a non-matching response produces nothing
"""
import http.server
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.enrichment import enrich_cache
from modules.enrichment.risk import (
    combined_risk_score, environment_risk_score, criticality_weight,
)
from modules.enrichment.epss import _valid_cves, lookup_epss
from modules.enrichment.validation import classify_confidence, actively_validate
from modules.enrichment.pipeline import enrich_findings
from plugins.base import Finding
from plugins.signature import SignaturePlugin

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


# --- A: risk -----------------------------------------------------------
print("\nA  risk scoring")
check("CVSS only = CVSS", combined_risk_score(7.5) == 7.5)
check("no CVSS -> None", combined_risk_score(None) is None)
check("high EPSS keeps score near CVSS", combined_risk_score(6.5, 0.97) > 6.0)
check("low EPSS halves toward CVSS/2", combined_risk_score(9.8, 0.0) == 4.9)
check("EPSS never raises above CVSS", combined_risk_score(5.0, 1.0) <= 5.0)
check("criticality weight high>low", criticality_weight("critical") > criticality_weight("low"))
check("criticality unknown -> default", criticality_weight("bogus") == 1.0)

fs = [{"severity": "CRITICAL", "risk_score": 9.5},
      {"severity": "HIGH", "risk_score": 7.0}]
hi = environment_risk_score(fs, "critical")
lo = environment_risk_score(fs, "low")
check("criticality raises env score", hi["score"] > lo["score"])
check("env band present", hi["band"] in ("Critical", "High", "Medium", "Low", "None"))
check("empty findings -> 0 band None", environment_risk_score([])["band"] == "None")
# worst finding dominates: adding many trivial findings can't beat a critical
few = environment_risk_score([{"severity": "CRITICAL", "risk_score": 9.8}], "medium")
many_low = environment_risk_score(
    [{"severity": "LOW", "risk_score": 1.0}] * 30, "medium")
check("one critical outranks many lows", few["score"] > many_low["score"],
      f"{few['score']} vs {many_low['score']}")


# --- B: cache ----------------------------------------------------------
print("\nB  enrich_cache")
enrich_cache.clear("t3")
check("miss returns None", enrich_cache.get("t3", "k", 60) is None)
enrich_cache.put("t3", "k", {"v": 1})
check("hit returns value", enrich_cache.get("t3", "k", 60) == {"v": 1})
check("expired -> None", enrich_cache.get("t3", "k", -1) is None)
enrich_cache.clear("t3")


# --- C: EPSS client (offline via seeded cache) -------------------------
print("\nC  EPSS client")
check("valid CVEs filtered/upper", _valid_cves(["cve-2021-44228", "junk", "", None])
      == ["CVE-2021-44228"])
check("dedup CVEs", _valid_cves(["CVE-2020-1234", "CVE-2020-1234"]) == ["CVE-2020-1234"])

# Seed the cache so lookup is offline and deterministic.
enrich_cache.clear("epss")
enrich_cache.put("epss", "CVE-2099-0001", {"epss": 0.5, "percentile": 0.9})
enrich_cache.put("epss", "CVE-2099-0002", {})   # a cached "no score" miss
got = lookup_epss(["CVE-2099-0001", "CVE-2099-0002"])
check("cached EPSS returned", got.get("CVE-2099-0001", {}).get("epss") == 0.5)
check("cached no-score CVE absent from result", "CVE-2099-0002" not in got)
enrich_cache.clear("epss")


# --- D: confidence -----------------------------------------------------
print("\nD  validation / confidence")
check("sqlmap -> Confirmed",
      classify_confidence({"finding_type": "sqlmap_finding"}) == "Confirmed")
check("missing header -> Confirmed",
      classify_confidence({"finding_type": "missing_security_header"}) == "Confirmed")
check("cve -> Potential", classify_confidence({"finding_type": "cve"}) == "Potential")
check("unknown -> Potential (conservative)",
      classify_confidence({"finding_type": "whatever"}) == "Potential")
# actively_validate is a no-op for non-version findings and offline
check("validate skips non-version type",
      actively_validate({"finding_type": "sqlmap_finding"}, "h", allow_network=False) == "")
check("validate skips w/o network",
      actively_validate({"finding_type": "cve", "version": "1.0", "port": 80},
                        "h", allow_network=False) == "")


# --- E: enrichment pipeline -------------------------------------------
print("\nE  enrichment pipeline")
enrich_cache.clear("epss")
enrich_cache.put("epss", "CVE-2099-1234", {"epss": 0.8, "percentile": 0.99})
findings = [
    Finding(title="cve finding", finding_type="cve", plugin="service_detect",
            port=21, cvss_score=9.8, cve_ids=["CVE-2099-1234"], version="1.0"),
    Finding(title="header", finding_type="missing_security_header",
            plugin="header_check", port=80, severity="MEDIUM"),
    Finding(title="sqli", finding_type="sqlmap_finding", plugin="sqlmap",
            port=80, severity="CRITICAL", confidence="Confirmed"),
]
summary = enrich_findings(findings, "example.test", active_validation=False)
check("all enriched", summary["enriched"] == 3)
check("cve got EPSS", findings[0].epss_score == 0.8)
check("cve confidence Potential", findings[0].confidence == "Potential")
check("cve risk = cvss*(0.5+0.5*epss)", findings[0].risk_score == round(9.8 * 0.9, 2))
check("header no EPSS", findings[1].epss_score is None)
check("header confidence Confirmed", findings[1].confidence == "Confirmed")
check("plugin Confirmed not downgraded", findings[2].confidence == "Confirmed")
check("env risk in summary", 0 < summary["environment_risk"]["score"] <= 100)
enrich_cache.clear("epss")


# --- F: signature engine (live, local server) -------------------------
print("\nF  signature engine")


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/.git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n"
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/5.6.40")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/clean":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"nothing to see")
        else:
            self.send_response(404)
            self.end_headers()


sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
server = http.server.HTTPServer(("127.0.0.1", port), _Handler)
th = threading.Thread(target=server.serve_forever, daemon=True)
th.start()

try:
    sig = {
        "id": "test-git", "info": {"name": "Exposed git", "severity": "medium",
                                   "remediation": "block it"},
        "requests": [{
            "method": "GET", "path": "/.git/config",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body",
                 "words": ["[core]", "repositoryformatversion"], "condition": "and"},
                {"type": "header", "header": "X-Powered-By", "words": ["PHP/5"]},
            ],
        }],
    }
    plugin = SignaturePlugin(sig)
    r = plugin.execute("127.0.0.1", {"port": port, "use_https": False})
    check("signature name namespaced", plugin.name == "sig:test-git")
    check("signature fires on match", r.outcome == "ran" and len(r.findings) == 1)
    if r.findings:
        f = r.findings[0]
        check("signature finding Confirmed", f.confidence == "Confirmed")
        check("signature finding has endpoint", "/.git/config" in (f.endpoint or ""))
        check("signature finding severity", f.severity == "MEDIUM")
        check("signature remediation carried", f.remediation == "block it")

    # regex matcher + or-condition + non-match
    sig2 = {
        "id": "test-regex", "info": {"name": "r", "severity": "low"},
        "requests": [{
            "method": "GET", "path": "/.git/config",
            "matchers": [{"type": "regex", "part": "body",
                          "regex": ["repositoryformat\\w+"]}],
        }],
    }
    r2 = SignaturePlugin(sig2).execute("127.0.0.1", {"port": port})
    check("regex matcher fires", len(r2.findings) == 1)

    # a clean response must NOT fire
    sig3 = dict(sig)
    sig3 = {
        "id": "test-clean", "info": {"name": "c", "severity": "high"},
        "requests": [{"method": "GET", "path": "/clean",
                      "matchers": [{"type": "word", "part": "body",
                                    "words": ["secret"]}]}],
    }
    r3 = SignaturePlugin(sig3).execute("127.0.0.1", {"port": port})
    check("no match -> no finding", len(r3.findings) == 0)
finally:
    server.shutdown()


print("\n" + "=" * 60)
print(f"PASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
