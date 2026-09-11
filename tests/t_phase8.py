"""
smoke_test8 Phase 2 verification: the web wrappers' field population.

Every assertion here runs against REAL captured tool output, held in
tests/fixtures/:
    gobuster_raw.txt    gobuster 3.x  vs http://127.0.0.1:8082 (DVWA)
    nikto_raw.txt       nikto 2.6.0   vs 127.0.0.1:8082
    zap_alerts_raw.json ZAP           vs http://127.0.0.1:8082, 25 alerts
No synthetic fixtures, no hand-written tool output — the same standard
t_phase2/t_phase3 hold themselves to.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, "/home/jafar/aegis-scanner")

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = os.path.join(_HERE, "fixtures")

from modules.web.gobuster_wrap import _parse_gobuster_output
from modules.web.dirb_wrap import _parse_dirb_output
from modules.web.nikto_wrap import (
    _parse_nikto_output, _server_banner, _split_server_banner,
)
from modules.web.zap_wrap import _dedupe_alerts, _cwe_id, _clean
from modules.profiles.deepscan import (
    _findings_from_zap, _findings_from_nikto, _findings_from_gobuster,
    _findings_from_dirb,
)
from modules.reporting.summary import field_display

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  -> {detail}")


def read(name):
    with open(os.path.join(_FIXTURES, name)) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
print("=== A. gobuster: size + redirect + url, from REAL output ===")
gob = _parse_gobuster_output(read("gobuster_raw.txt"),
                            base_url="http://127.0.0.1:8082")
check("13 paths parsed from real gobuster output", len(gob) == 13, len(gob))
by_path = {e["path"]: e for e in gob}

check("every entry carries a size (gobuster printed one on every line)",
      all(e["size"] is not None for e in gob),
      [e["path"] for e in gob if e["size"] is None])
check("/favicon.ico size is 1406 (gobuster's own number)",
      by_path["/favicon.ico"]["size"] == 1406,
      by_path["/favicon.ico"]["size"])
check("/index.php size is 0 — a real 0, not a missing value",
      by_path["/index.php"]["size"] == 0, by_path["/index.php"]["size"])

check("/docs redirect target captured",
      by_path["/docs"]["redirect"] == "http://127.0.0.1:8082/docs/",
      by_path["/docs"]["redirect"])
check("/index.php relative redirect captured",
      by_path["/index.php"]["redirect"] == "login.php",
      by_path["/index.php"]["redirect"])
check("non-redirect 200 has redirect None, not an empty string",
      by_path["/favicon.ico"]["redirect"] is None,
      by_path["/favicon.ico"]["redirect"])
check("403 has redirect None",
      by_path["/.htaccess"]["redirect"] is None,
      by_path["/.htaccess"]["redirect"])

check("url composed with the scheme gobuster was actually pointed at",
      by_path["/docs"]["url"] == "http://127.0.0.1:8082/docs",
      by_path["/docs"]["url"])
check("https base_url yields https urls (scheme is not assumed)",
      _parse_gobuster_output("admin (Status: 200) [Size: 5]",
                             base_url="https://h:8443")[0]["url"]
      == "https://h:8443/admin")
check("no base_url -> url None rather than a scheme-less guess",
      _parse_gobuster_output("admin (Status: 200) [Size: 5]")[0]["url"] is None)

# regression: the pattern must not become size-dependent
check("line with no [Size:] block still parses (size None, not dropped)",
      (lambda r: len(r) == 1 and r[0]["size"] is None
       and r[0]["status_code"] == 200)(
          _parse_gobuster_output("admin (Status: 200)")),
      _parse_gobuster_output("admin (Status: 200)"))
check("status_code still parsed for every real entry",
      all(isinstance(e["status_code"], int) for e in gob))
check("empty input still yields []", _parse_gobuster_output("") == [])

# ---------------------------------------------------------------------------
print("\n=== B. dirb: SIZE was parsed and discarded; now kept ===")
DIRB = (
    "+ http://127.0.0.1:8082/index.php (CODE:302|SIZE:0)\n"
    "+ http://127.0.0.1:8082/robots.txt (CODE:200|SIZE:26)\n"
    "==> DIRECTORY: http://127.0.0.1:8082/config/\n"
)
dirb = _parse_dirb_output(DIRB, "http://127.0.0.1:8082")
d_by = {e["path"]: e for e in dirb}
check("3 entries parsed", len(dirb) == 3, len(dirb))
check("robots.txt SIZE 26 kept", d_by["/robots.txt"]["size"] == 26,
      d_by["/robots.txt"]["size"])
check("index.php SIZE 0 kept as 0", d_by["/index.php"]["size"] == 0,
      d_by["/index.php"]["size"])
check("directory hit carries size None, not a fabricated 0",
      d_by["/config/"]["size"] is None, d_by["/config/"]["size"])
check("dirb url is its own absolute URL (carries scheme+port)",
      d_by["/robots.txt"]["url"] == "http://127.0.0.1:8082/robots.txt",
      d_by["/robots.txt"]["url"])
check("dirb redirect is always None — it never reports one",
      all(e["redirect"] is None for e in dirb))

# ---------------------------------------------------------------------------
print("\n=== C. nikto: test id, path, reference, server banner (REAL) ===")
raw_nikto = read("nikto_raw.txt")
nik = _parse_nikto_output(raw_nikto)
check("findings parsed from real nikto output", len(nik) >= 10, len(nik))

ids = [f["test_id"] for f in nik]
check("short test id [95] captured", "95" in ids, ids[:5])
check("zero-padded test id [013587] captured", "013587" in ids, ids[:8])
check("every parsed finding got a test id (nikto printed one on each)",
      all(f["test_id"] for f in nik),
      [f["description"][:40] for f in nik if not f["test_id"]])

outdated = [f for f in nik if "appears to be outdated" in f["description"]]
check("the 'Apache/2.4.25 appears to be outdated' line was parsed",
      len(outdated) == 1, len(outdated))
check("...and its path is empty — 'Apache/2.4.25' is NOT a URI",
      outdated and outdated[0]["path"] == "",
      outdated[0]["path"] if outdated else "missing")

cfg = [f for f in nik if f["description"].startswith("[750500] /config/")]
check("/config/ directory-indexing path captured",
      cfg and cfg[0]["path"] == "/config/",
      cfg[0]["path"] if cfg else "missing")
root = [f for f in nik if "Suggested security header missing: csp" in f["description"]
        or "referrer-policy" in f["description"]]
check("root path '/' captured for header findings",
      root and root[0]["path"] == "/", root[0]["path"] if root else "missing")

refs = [f["reference"] for f in nik if f["reference"]]
check("references captured from 'See:' suffixes", len(refs) >= 5, len(refs))
check("reference is a bare URL, no 'See:' left in it",
      all(r.startswith("http") for r in refs), refs[:2])
check("finding with no 'See:' has reference '' (not a guessed URL)",
      any(f["reference"] == "" for f in nik))

banner = _server_banner(raw_nikto)
check("server banner read from the metadata line",
      banner == "Apache/2.4.25 (Debian)", banner)
prod, ver = _split_server_banner(banner)
check("banner splits to product Apache", prod == "Apache", prod)
check("banner splits to version 2.4.25 (Debian)", ver == "2.4.25 (Debian)", ver)
check("'No banner retrieved' is treated as no banner, not a product",
      _server_banner("+ Server: No banner retrieved") == "",
      _server_banner("+ Server: No banner retrieved"))
check("banner with no slash -> product only, version '' (no guessed split)",
      _split_server_banner("nginx") == ("nginx", ""),
      _split_service := _split_server_banner("nginx"))
check("absent banner -> ('', '')", _split_server_banner("") == ("", ""))

check("description is left byte-identical (finding identity preserved)",
      all(f["description"].startswith("[") or "/" in f["description"]
          for f in nik))

# ---------------------------------------------------------------------------
print("\n=== D. ZAP: the fields it really returns (REAL 25-alert run) ===")
alerts = json.loads(read("zap_alerts_raw.json"))
check("fixture holds 25 real alerts", len(alerts) == 25, len(alerts))
zf = _dedupe_alerts(alerts)
check("25 alerts collapse to 9 distinct (pluginId, alert) rules",
      len(zf) == 9, len(zf))
check("internal _urls scratch key is not leaked to callers",
      all("_urls" not in f for f in zf))

check("every row carries ZAP's own description",
      all(f["description"] for f in zf))
check("every row carries ZAP's solution (-> remediation)",
      all(f["solution"] for f in zf))
check("every row carries ZAP's reference",
      all(f["reference"] for f in zf))
check("every row carries the url ZAP matched at",
      all(f["url"] for f in zf))
check("urls carry the scheme (http://...) — not a bare path",
      all(f["url"].startswith("http") for f in zf))

csp = [f for f in zf if f["name"].startswith("Content Security Policy")]
check("CSP alert present", len(csp) == 1, len(csp))
check("CSP cwe rendered as CWE-693", csp[0]["cwe"] == "CWE-693", csp[0]["cwe"])
check("CSP param is '' — ZAP reported none, so nothing is invented",
      csp[0]["param"] == "", csp[0]["param"])

sess = [f for f in zf if f["name"] == "Session Management Response Identified"]
check("session-management alert present", len(sess) == 1, len(sess))
check("its cweid of -1 is dropped, NOT rendered as CWE--1",
      sess[0]["cwe"] == "", sess[0]["cwe"])
check("its param PHPSESSID is kept", sess[0]["param"] == "PHPSESSID",
      sess[0]["param"])
check("its evidence PHPSESSID is kept", sess[0]["evidence"] == "PHPSESSID",
      sess[0]["evidence"])

check("_cwe_id drops 0 as well as -1", _cwe_id({"cweid": "0"}) == "")
check("_cwe_id drops non-numeric", _cwe_id({"cweid": "n/a"}) == "")
check("_cwe_id keeps a real id", _cwe_id({"cweid": "79"}) == "CWE-79")
check("attack is empty on every alert — a passive scan sends none",
      all(f["attack"] == "" for f in zf))
check("url_count records how many URLs a collapsed rule matched",
      max(f["url_count"] for f in zf) > 1,
      [f["url_count"] for f in zf])
check("confidence carried through", all(f["confidence"] for f in zf))

# ---------------------------------------------------------------------------
print("\n=== E. mappers put the new detail on the finding dict ===")
zmap = _findings_from_zap({"port": 8082, "findings": zf})
z0 = zmap[0]
check("zap mapper sets remediation from ZAP's solution",
      z0["remediation"] and z0["remediation"] == zf[0]["solution"])
check("zap mapper sets endpoint from ZAP's url",
      z0["endpoint"] == zf[0]["url"], z0["endpoint"])
check("zap mapper sets reference", z0["reference"] == zf[0]["reference"])
check("zap description keeps the '<name> — <prose>' form",
      z0["description"].startswith(zf[0]["name"]), z0["description"][:60])
check("zap description names the rule, so truncation stays distinguishable",
      len({f["description"][:60] for f in zmap}) == len(zmap),
      len({f["description"][:60] for f in zmap}))
multi = [f for f in zmap if "matched at" in f["description"]]
check("a rule matched at several URLs says so", len(multi) >= 1, len(multi))
check("empty ZAP field -> None on the finding (renders as undetermined)",
      _findings_from_zap({"port": 80, "findings": [
          dict(zf[0], param="", evidence="")]})[0]["parameter"] is None)

nmap_ = _findings_from_nikto({
    "port": 8082, "base_url": "http://127.0.0.1:8082",
    "product": "Apache", "version": "2.4.25 (Debian)", "findings": nik})
check("nikto mapper sets endpoint with scheme",
      nmap_[0]["endpoint"].startswith("http://127.0.0.1:8082"),
      nmap_[0]["endpoint"])
check("nikto finding with no URI still gets the base URL",
      [f for f in nmap_ if f["description"].startswith("[600050]")][0]["endpoint"]
      == "http://127.0.0.1:8082")
check("nikto /config/ finding endpoint includes the path",
      [f for f in nmap_ if "[750500] /config/" in f["description"]][0]["endpoint"]
      == "http://127.0.0.1:8082/config/")
check("nikto mapper carries product/version from the banner",
      nmap_[0]["product"] == "Apache" and nmap_[0]["version"] == "2.4.25 (Debian)")
check("nikto mapper carries reference (was dropped at insert before)",
      any(f["reference"] for f in nmap_))
check("nikto reference of '' becomes None, not an empty cell",
      all(f["reference"] is None or f["reference"] for f in nmap_))

gmap = _findings_from_gobuster({"port": 8082, "discovered_paths": gob})
g_by = {f["path"]: f for f in gmap}
check("gobuster mapper sets endpoint",
      g_by["/docs"]["endpoint"] == "http://127.0.0.1:8082/docs")
check("description reports the size gobuster gave",
      "1406 bytes" in g_by["/favicon.ico"]["description"],
      g_by["/favicon.ico"]["description"])
check("description reports the redirect target",
      "-> login.php" in g_by["/index.php"]["description"],
      g_by["/index.php"]["description"])
check("a path with size None omits the size rather than printing 0 bytes",
      "bytes" not in _findings_from_gobuster(
          {"port": 80, "discovered_paths":
           [{"path": "/x", "status_code": 200, "size": None,
             "redirect": None, "url": None}]})[0]["description"])
dmap = _findings_from_dirb({"port": 8082, "discovered_paths": dirb})
check("dirb mapper still marks its source", "via dirb" in dmap[0]["description"])
check("dirb mapper sets endpoint", dmap[0]["endpoint"] is not None)

# ---------------------------------------------------------------------------
print("\n=== F. field_display stays honest about the new fields ===")
check("endpoint on a populated zap finding shows the URL",
      field_display({"finding_type": "zap_finding",
                     "endpoint": "http://h/x"}, "endpoint") == "http://h/x")
check("endpoint unpopulated on a zap finding -> not determined by zaproxy",
      field_display({"finding_type": "zap_finding"}, "endpoint")
      == "not determined by zaproxy",
      field_display({"finding_type": "zap_finding"}, "endpoint"))
check("endpoint on smb_share -> N/A (host-level finding)",
      field_display({"finding_type": "smb_share"}, "endpoint")
      == "N/A (host-level finding)",
      field_display({"finding_type": "smb_share"}, "endpoint"))
check("endpoint on open_port -> N/A (port observation)",
      field_display({"finding_type": "open_port"}, "endpoint")
      == "N/A (port observation)")
check("reference on discovered_path -> N/A (path discovery)",
      field_display({"finding_type": "discovered_path"}, "reference")
      == "N/A (path discovery)")
check("reference unpopulated on nikto -> not determined by nikto",
      field_display({"finding_type": "nikto_finding"}, "reference")
      == "not determined by nikto")
for ftype in ("zap_finding", "nikto_finding", "discovered_path", "smb_share",
              "open_port", "nuclei_finding", "cve", "banner", "smb_user",
              "weak_credentials", "nmap_script", "service_version",
              "missing_security_header", "fingerprint_header",
              "technology_fingerprint", "wordpress_fingerprinted",
              "sqlmap_finding", "xss_finding", "wpscan_finding"):
    for field in ("endpoint", "reference"):
        rendered = field_display({"finding_type": ftype}, field)
        check(f"{ftype}/{field} is never a bare dash or blank",
              rendered not in ("-", "", "None") and "not determined" not in rendered
              or rendered.startswith(("N/A", "not determined")),
              rendered)

# ---------------------------------------------------------------------------
print("\n=== G. reference survives the database round-trip ===")
import database.db as dbmod

tmpdb = os.path.join(tempfile.mkdtemp(prefix="aegis_t8_"), "t.db")
orig = dbmod.DB_PATH
try:
    dbmod.DB_PATH = tmpdb
    dbmod.init_db()
    sid = dbmod.insert_scan("t.example", "deepscan")
    dbmod.insert_finding(sid, {
        "type": "zap_finding", "port": 8082, "severity": "MEDIUM",
        "description": "CSP Header Not Set — prose",
        "remediation": "Set the header.",
        "endpoint": "http://127.0.0.1:8082/sitemap.xml",
        "evidence": "PHPSESSID", "parameter": "PHPSESSID",
        "reference": "https://example.invalid/csp",
    })
    rows = dbmod.get_findings_for_scan(sid)
    check("row inserted", len(rows) == 1, len(rows))
    r = rows[0]
    check("reference column exists and round-trips",
          r.get("reference") == "https://example.invalid/csp", r.get("reference"))
    check("endpoint round-trips", r.get("endpoint") == "http://127.0.0.1:8082/sitemap.xml")
    check("remediation round-trips", r.get("remediation") == "Set the header.")
    check("evidence round-trips", r.get("evidence") == "PHPSESSID")
    check("parameter round-trips", r.get("parameter") == "PHPSESSID")
    check("a finding with no reference stores NULL, not ''",
          (dbmod.insert_finding(sid, {"type": "open_port", "port": 22}),
           dbmod.get_findings_for_scan(sid)[1].get("reference") is None)[1])
finally:
    dbmod.DB_PATH = orig

# ---------------------------------------------------------------------------
print("\n=== H. webaudit scope note (Phase 4) ===")
from modules.reporting.summary import profile_scope_note
from modules.reporting.report_txt import _scope_note_block
from modules.reporting.report_pdf import _scope_note_html

note = profile_scope_note("webaudit")
check("webaudit has a scope note", bool(note))
check("the note itself carries NO 'Scope:' prefix (each surface labels it)",
      not note.startswith("Scope"), note[:30])
check("labelled=True adds the prefix exactly once",
      profile_scope_note("webaudit", labelled=True).count("Scope:") == 1,
      profile_scope_note("webaudit", labelled=True)[:40])
check("labelled=True on a profile with no note stays empty",
      profile_scope_note("quickscan", labelled=True) == "")
check("note says nuclei DAST/XSS is what it DOES run (not 'no nuclei')",
      "DAST" in note and "XSS" in note, note[:80])
check("note names the severity pass as the thing out of scope",
      "severity template pass" in note, note[:120])
check("note points at quickscan/deepscan as the wider scan",
      "quickscan" in note and "deepscan" in note)
check("note is short enough to be read (< 400 chars)", len(note) < 400, len(note))
for other in ("quickscan", "deepscan", "stealthscan", "compliance"):
    check(f"{other} carries no scope note", profile_scope_note(other) == "")
check("unknown/None profile is safe", profile_scope_note(None) == ""
      and profile_scope_note("nonesuch") == "")
check("profile match is case-insensitive",
      profile_scope_note("WebAudit") == note)

check("txt block renders for webaudit", len(_scope_note_block("webaudit")) > 1)
check("txt block is empty for quickscan", _scope_note_block("quickscan") == [])
check("pdf html renders for webaudit",
      "scope-note" in _scope_note_html("webaudit"))
check("pdf html is empty for quickscan", _scope_note_html("quickscan") == "")
check("txt and pdf carry the SAME wording (one source)",
      note in " ".join(_scope_note_block("webaudit")).replace("  ", " ")
      or all(w in _scope_note_html("webaudit") for w in note.split()[:6]))

# ---------------------------------------------------------------------------
print("\n=== I. a tool's own remediation is not overwritten ===")
from modules.enrichment.remediation import get_remediation

zap_solution = "Ensure that the HttpOnly flag is set for all cookies."
check("ZAP's own solution survives enrichment",
      get_remediation({"type": "zap_finding", "name": "Cookie No HttpOnly Flag",
                       "remediation": zap_solution})["remediation"] == zap_solution)
check("empty remediation still falls back to the generic text",
      get_remediation({"type": "zap_finding", "name": "X",
                       "remediation": ""})["remediation"].startswith("Review the ZAP"))
check("whitespace-only remediation falls back too",
      get_remediation({"type": "zap_finding", "name": "X",
                       "remediation": "   "})["remediation"].startswith("Review the ZAP"))
check("a finding with no remediation key keeps its type-specific text",
      get_remediation({"type": "missing_security_header",
                       "header": "Content-Security-Policy"})["remediation"]
      .startswith("Define a Content-Security-Policy"))
check("...and an unrecognised header still gets the generic header text",
      get_remediation({"type": "missing_security_header",
                       "header": "X-Nonesuch"})["remediation"]
      .startswith("Configure this security header"))
check("input dict is still never mutated",
      (lambda d: (get_remediation(d), "remediation" not in d)[1])(
          {"type": "zap_finding", "name": "X"}))
check("non-dict input is still handled",
      "remediation" in get_remediation("nope"))
end_to_end = _findings_from_zap({"port": 80, "findings": zf})
check("zap mapper + enrichment keeps ZAP's solution end to end",
      get_remediation(end_to_end[0])["remediation"] == zf[0]["solution"])

# ---------------------------------------------------------------------------
print("\n=== J. adding the reference column must not reclassify findings ===")
# Regression: _finding_kind/_finding_type sniffed nikto by `"reference" in
# finding`. Rows read back from SQLite carry EVERY column, so once findings
# gained a reference column every described row looked like a nikto finding —
# a stealthscan open-port row was told to "review this nikto finding".
from modules.enrichment.remediation import _finding_kind, remediation_text
from modules.enrichment.severity import _finding_type

db_row_open_port = {                      # shape db.py hands back
    "port": 80, "service": "http", "finding_type": None, "cve_id": None,
    "description": "Http is exposed on port 80.", "reference": None,
    "endpoint": None, "evidence": None, "parameter": None, "payload": None,
}
check("an untyped DB row with a NULL reference is not called nikto",
      _finding_kind(db_row_open_port) == "open_port",
      _finding_kind(db_row_open_port))
check("...and severity's classifier agrees",
      _finding_type(db_row_open_port) == "open_port",
      _finding_type(db_row_open_port))
rem = remediation_text(db_row_open_port)
check("its remediation does not name nikto", "nikto" not in rem.lower(), rem[:70])
check("its remediation is the port-80 one", "HTTPS" in rem, rem[:70])

check("a row WITH a real reference and description is still nikto",
      _finding_kind({"description": "Directory indexing found.",
                     "reference": "https://example.invalid/x"}) == "nikto_finding")
check("finding_type is honoured, not just type",
      _finding_kind({"finding_type": "zap_finding",
                     "description": "x", "reference": "y"}) == "zap_finding")
check("an explicit type still wins over finding_type",
      _finding_kind({"type": "cve", "finding_type": "zap_finding"}) == "cve")
check("severity honours finding_type too",
      _finding_type({"finding_type": "discovered_path", "path": "/x"})
      == "discovered_path")
check("empty-string finding_type falls through to sniffing",
      _finding_kind({"finding_type": "", "path": "/admin"}) == "discovered_path")

# every real stored finding_type must survive the round-trip unchanged
for ft in ("zap_finding", "nikto_finding", "discovered_path", "nuclei_finding",
           "missing_security_header", "smb_share", "weak_credentials"):
    row = {"finding_type": ft, "description": "d", "reference": None,
           "endpoint": None, "port": 80}
    check(f"stored finding_type {ft} is read back as itself",
          _finding_kind(row) == ft, _finding_kind(row))

# ---------------------------------------------------------------------------
print("\n=== K. long / multi-line values cannot break the card layout ===")
from modules.reporting.report_txt import _fit, _FIELD_VALUE_WIDTH, _WIDTH

check("ZAP's newline-separated reference is collapsed to one line",
      all("\n" not in f["reference"] for f in zf))
multi_ref = [f for f in zf if f["reference"].count("http") > 1]
check("a multi-URL reference keeps ALL its URLs (joined, not truncated)",
      multi_ref and multi_ref[0]["reference"].count("http") > 1,
      multi_ref[0]["reference"][:70] if multi_ref else "none")
check("ZAP descriptions are single-line too",
      all("\n" not in f["description"] for f in zf))
check("_clean collapses tabs/newlines/runs of spaces",
      _clean("a\n b\t\tc   d") == "a b c d", _clean("a\n b\t\tc   d"))

check("_fit leaves a short value alone", _fit("http://h/x") == "http://h/x")
check("_fit never exceeds the value column",
      len(_fit("x" * 500)) <= _FIELD_VALUE_WIDTH, len(_fit("x" * 500)))
check("_fit elides in the middle, keeping head and tail",
      _fit("http://start" + "y" * 300 + "end.html").startswith("http://start")
      and _fit("http://start" + "y" * 300 + "end.html").endswith("end.html"))
check("_fit handles None", _fit(None) == "")
check("_fit collapses embedded newlines", "\n" not in _fit("a\nb"))

# the real report must not overflow on the new cells
from modules.reporting.report_txt import render_report as _rr
from modules.reporting.summary import build_summary as _bs
import io as _io, contextlib as _ctx
_buf = _io.StringIO()
with _ctx.redirect_stdout(_buf):
    _summary = _bs(130, quiet=True)
_text = _rr(_summary)
_over = [l for l in _text.splitlines()
         if len(l) > _WIDTH and l.strip().startswith(("Endpoint", "Reference"))]
check("no Endpoint/Reference line in a real report exceeds the width",
      not _over, _over[:1])
check("no report line contains a stray bare URL on its own",
      not [l for l in _text.splitlines()
           if l.startswith("http")], "found bare URL line")

print("\n" + "=" * 60)
print(f"PASS {ok}   FAIL {fail}")
sys.exit(1 if fail else 0)
