"""
modules/enrichment/severity.py
Severity normalisation for Aegis Scanner (Member C - enrichment layer).

Every finding the framework produces — a CVE from cve_lookup.py, an open
port from port_scanner.py, a missing header from header_check.py, a nikto
line, a gobuster path, a raw banner — arrives here in a different shape and
leaves with a single comparable `severity` label.

Scale
-----
The four tiers used across the project (display.SEVERITY_COLORS also
defines INFO, but this module never emits it: display.print_summary only
counts critical/high/medium/low, so an INFO-graded finding would silently
vanish from the summary). LOW is therefore the floor — nothing goes
ungraded.

Sources
-------
severity_source records how the grade was reached:
    "cvss"      — derived from an NVD CVSS score/rating
    "heuristic" — derived from the rules in this file

The heuristic tables below are deliberately plain data so teammates can
adjust a single entry without reading the control flow.
"""

from modules.utils.logger import log_finding
from modules.utils.display import print_info, print_warning

# ---------------------------------------------------------------------
# CVSS bands
# ---------------------------------------------------------------------
# Standard NVD qualitative ranges. Checked config.py first — it defines
# NVD_* API settings only, no severity bands — so they live here, the one
# module that grades findings.
#   9.0-10.0 CRITICAL | 7.0-8.9 HIGH | 4.0-6.9 MEDIUM | 0.1-3.9 LOW
# (A 0.0 "NONE" score is floored to LOW rather than dropped, so the
# finding still appears in the report.)
SEVERITY_BANDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Labels other tools use for the same four tiers.
_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "SEVERE": "CRITICAL",
    "HIGH": "HIGH",
    "IMPORTANT": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "LOW": "LOW",
    "MINOR": "LOW",
    # Anything merely informational is floored to LOW so print_summary
    # still counts it (see module docstring).
    "INFO": "LOW",
    "INFORMATIONAL": "LOW",
    "NONE": "LOW",
    "UNKNOWN": "LOW",
}

# ---------------------------------------------------------------------
# Heuristic tables (non-CVE findings)
# ---------------------------------------------------------------------

# Missing security headers, graded by what an attacker gains from the
# absence. HSTS/CSP/X-Frame-Options each enable a concrete attack
# (downgrade+MITM, XSS payload delivery, clickjacking); the remaining
# three are hardening niceties whose absence is rarely exploitable alone.
_MISSING_HEADER_SEVERITY = {
    "Strict-Transport-Security": "MEDIUM",
    "Content-Security-Policy": "MEDIUM",
    "X-Frame-Options": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "Referrer-Policy": "LOW",
    "X-XSS-Protection": "LOW",
}
_DEFAULT_MISSING_HEADER_SEVERITY = "LOW"

# Open ports with no CVE attached, graded by the exposure the service
# itself represents:
#   HIGH   — remote administration, cleartext credentials, or a datastore
#            that is routinely left unauthenticated
#   MEDIUM — service that commonly carries credentials/data in the clear
#            but is normal to expose (mail, plain HTTP)
#   LOW    — everything else (see _DEFAULT_PORT_SEVERITY)
# A port alone never scores CRITICAL: without a CVE there is no evidence
# of an exploitable flaw, only of exposure.
_PORT_SEVERITY = {
    21: "HIGH",      # ftp — cleartext credentials
    23: "HIGH",      # telnet — cleartext credentials + remote shell
    69: "HIGH",      # tftp — no authentication at all
    111: "HIGH",     # rpcbind — enumeration of RPC services
    135: "HIGH",     # msrpc
    139: "HIGH",     # netbios-ssn — SMB
    445: "HIGH",     # microsoft-ds — SMB
    512: "HIGH",     # rexec — cleartext remote execution
    513: "HIGH",     # rlogin — trust-based remote login
    514: "HIGH",     # rsh — trust-based remote shell
    1099: "HIGH",    # java-rmi — remote class loading
    1433: "HIGH",    # mssql
    1524: "HIGH",    # ingreslock — classic bindshell backdoor port
    2049: "HIGH",    # nfs
    2121: "HIGH",    # alt ftp
    3306: "HIGH",    # mysql
    3389: "HIGH",    # rdp
    5432: "HIGH",    # postgresql
    5900: "HIGH",    # vnc
    6000: "HIGH",    # x11 — remote display/keystroke access
    6379: "HIGH",    # redis — unauthenticated by default
    6667: "HIGH",    # irc — a backdoored ircd is a Metasploitable staple
    8009: "HIGH",    # ajp13 — Ghostcat-style file read
    9200: "HIGH",    # elasticsearch — unauthenticated by default
    27017: "HIGH",   # mongodb — unauthenticated by default
    25: "MEDIUM",    # smtp
    53: "MEDIUM",    # dns
    80: "MEDIUM",    # http — cleartext web
    110: "MEDIUM",   # pop3
    143: "MEDIUM",   # imap
    8080: "MEDIUM",  # http-alt
    8180: "MEDIUM",  # tomcat-alt
}
_DEFAULT_PORT_SEVERITY = "LOW"

# Fallback by nmap service name, for the same services running on a
# non-standard port (Metasploitable, for instance, runs a second FTP on
# 2121 and IRC on 6697). Without this a relocated telnet/VNC/database
# would be graded LOW purely because of its port number.
_SERVICE_SEVERITY = {
    "ftp": "HIGH",
    "ftp-data": "HIGH",
    "telnet": "HIGH",
    "tftp": "HIGH",
    "rexec": "HIGH",
    "rlogin": "HIGH",
    "shell": "HIGH",
    "exec": "HIGH",
    "login": "HIGH",
    "microsoft-ds": "HIGH",
    "netbios-ssn": "HIGH",
    "msrpc": "HIGH",
    "rpcbind": "HIGH",
    "nfs": "HIGH",
    "mysql": "HIGH",
    "postgresql": "HIGH",
    "ms-sql-s": "HIGH",
    "oracle": "HIGH",
    "mongodb": "HIGH",
    "redis": "HIGH",
    "elasticsearch": "HIGH",
    "vnc": "HIGH",
    "vnc-http": "HIGH",
    "ms-wbt-server": "HIGH",
    "x11": "HIGH",
    "java-rmi": "HIGH",
    "rmiregistry": "HIGH",
    "ajp13": "HIGH",
    "irc": "HIGH",
    "ircd": "HIGH",
    "bindshell": "HIGH",
    "ingreslock": "HIGH",
    "smtp": "MEDIUM",
    "pop3": "MEDIUM",
    "imap": "MEDIUM",
    "domain": "MEDIUM",
    "http": "MEDIUM",
    "http-alt": "MEDIUM",
    "http-proxy": "MEDIUM",
}

# Nikto emits free text, so it is graded by keyword. First match wins, so
# the list is ordered worst-first.
_NIKTO_KEYWORDS = [
    ("CRITICAL", (
        "backdoor", "remote shell", "remote code execution", "rce",
        "command execution", "command injection", "shellshock",
        "arbitrary code",
    )),
    ("HIGH", (
        "sql injection", "sqli", "file upload", "arbitrary file",
        "directory traversal", "path traversal", "local file inclusion",
        "remote file inclusion", "default account", "default password",
        "authentication bypass", "admin console", "phpmyadmin",
    )),
    ("MEDIUM", (
        "cross site scripting", "xss", "cross-site request forgery", "csrf",
        "directory indexing", "index of", "outdated", "out of date",
        "clickjack", "trace", "webdav", "phpinfo",
    )),
    ("LOW", (
        "header", "banner", "cookie", "robots.txt", "allowed http methods",
        "information disclosure", "retrieved",
    )),
]
_DEFAULT_NIKTO_SEVERITY = "LOW"

# Gobuster path discoveries, graded by what the path exposes. Matched as a
# substring of the lower-cased path, worst-first.
_PATH_KEYWORDS = [
    ("HIGH", (
        "/.git", "/.env", "/.svn", "/backup", "/.bak", "/config.php",
        "/wp-config", "/phpmyadmin", "/adminer", "/.htpasswd", "/id_rsa",
        "/shell", "/dump.sql",
    )),
    ("MEDIUM", (
        "/admin", "/login", "/manager", "/cgi-bin", "/console", "/upload",
        "/phpinfo", "/server-status", "/wp-admin", "/wp-login", "/test",
    )),
]
_DEFAULT_PATH_SEVERITY = "LOW"

# nmap --script results (compliance profile's ssl-enum-ciphers/http-headers,
# deepscan's -sC default scripts). Graded by keyword since script output is
# free text; ssl-enum-ciphers naming legacy protocols/export-grade ciphers
# is the clearest actionable signal available without a dedicated parser
# for every script's output format.
_NMAP_SCRIPT_KEYWORDS = [
    ("HIGH", ("sslv2", "sslv3", "export", "null cipher", "anon")),
    ("MEDIUM", ("tlsv1.0", "tls1.0", "tlsv1.1", "tls1.1", "rc4", "3des", "weak", "cbc")),
]
_DEFAULT_NMAP_SCRIPT_SEVERITY = "LOW"

# A WordPress install is not itself a flaw, but it is a large plugin
# attack surface and triggers wpscan (config.CONDITIONAL_TOOLS).
_WORDPRESS_SEVERITY = "MEDIUM"

# Version-disclosing banners/fingerprint headers: real information
# leakage, but only useful to an attacker as a precursor.
_BANNER_SEVERITY = "LOW"


def normalise_severity(value) -> str:
    """
    Coerce any severity-ish string onto the four-tier scale.
    Unrecognised values fall back to LOW rather than being dropped.
    """
    if not value:
        return "LOW"
    return _SEVERITY_ALIASES.get(str(value).strip().upper(), "LOW")


def severity_from_score(score) -> str:
    """Map a CVSS base score onto the four-tier scale (NVD bands)."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "LOW"
    for threshold, label in SEVERITY_BANDS:
        if value >= threshold:
            return label
    return "LOW"


def _extract_score(finding: dict):
    """
    Find a CVSS score anywhere in the finding.

    Accepts cve_lookup's per-CVE dicts (cvss_score), the db.py column name
    (cvss), and a whole lookup_cves() result — for which the worst CVE in
    the `cves` list is what grades the finding.
    """
    for key in ("cvss_score", "cvss", "base_score", "baseScore"):
        if finding.get(key) is not None:
            try:
                return float(finding[key])
            except (TypeError, ValueError):
                continue

    scores = [
        c.get("cvss_score")
        for c in (finding.get("cves") or [])
        if isinstance(c, dict) and c.get("cvss_score") is not None
    ]
    if scores:
        try:
            return max(float(s) for s in scores)
        except (TypeError, ValueError):
            return None

    return None


def _has_cve(finding: dict) -> bool:
    return bool(finding.get("cve_id") or finding.get("cves"))


def _match_keywords(text: str, table) -> str:
    """Return the severity of the first keyword table entry that matches."""
    lowered = (text or "").lower()
    for severity, keywords in table:
        for keyword in keywords:
            if keyword in lowered:
                return severity
    return ""


def _finding_type(finding: dict) -> str:
    """
    Work out what kind of finding this is.

    An explicit `type` (the label the scanning/web modules already pass to
    log_finding) wins; otherwise the shape is sniffed from the keys those
    modules actually return.
    """
    declared = str(finding.get("type") or "").strip().lower()
    if declared:
        return declared

    if _has_cve(finding):
        return "cve"
    if finding.get("script_id") is not None:
        return "nmap_script"          # {port, script_id, output}
    if finding.get("header") or finding.get("missing_header"):
        return "missing_security_header"
    if finding.get("description") is not None and "reference" in finding:
        return "nikto_finding"          # {description, reference}
    if finding.get("path"):
        return "discovered_path"        # {path, status_code}
    if finding.get("banner_text"):
        return "banner"                 # {port, banner_text}
    if finding.get("server_banner") or finding.get("powered_by"):
        return "fingerprint_header"
    if finding.get("product") or finding.get("version"):
        return "service_version"        # {port, service, version, product}
    if finding.get("port") is not None:
        return "open_port"              # {port, protocol, service, state}
    return "unknown"


def _heuristic_severity(finding: dict, kind: str) -> str:
    """
    Grade a finding that has no CVSS score behind it.

    Each branch is documented at its table definition above; the point of
    this function is only to pick the right table for the shape.
    """
    if kind == "missing_security_header":
        header = finding.get("header") or finding.get("missing_header") or ""
        return _MISSING_HEADER_SEVERITY.get(header, _DEFAULT_MISSING_HEADER_SEVERITY)

    if kind == "nikto_finding":
        text = f"{finding.get('description', '')} {finding.get('reference', '')}"
        return _match_keywords(text, _NIKTO_KEYWORDS) or _DEFAULT_NIKTO_SEVERITY

    if kind == "wordpress_fingerprinted":
        return _WORDPRESS_SEVERITY

    if kind == "nmap_script":
        output = str(finding.get("output") or "")
        return _match_keywords(output, _NMAP_SCRIPT_KEYWORDS) or _DEFAULT_NMAP_SCRIPT_SEVERITY

    if kind == "discovered_path":
        # Note: a 200 on a directory is NOT graded as directory indexing —
        # gobuster only reports that the path exists, not that an index was
        # rendered. Nikto's "Directory indexing found" line is what carries
        # that evidence, and it is graded MEDIUM by _NIKTO_KEYWORDS.
        return _match_keywords(str(finding.get("path") or ""),
                               _PATH_KEYWORDS) or _DEFAULT_PATH_SEVERITY

    if kind in ("banner", "fingerprint_header", "technology_fingerprint"):
        return _BANNER_SEVERITY

    if kind in ("open_port", "service_version"):
        try:
            port = int(finding.get("port"))
        except (TypeError, ValueError):
            port = None
        if port in _PORT_SEVERITY:
            return _PORT_SEVERITY[port]
        # Same service on a non-standard port still carries the same
        # exposure — grade it by name before falling back to the floor.
        service = str(finding.get("service") or "").strip().lower()
        return _SERVICE_SEVERITY.get(service, _DEFAULT_PORT_SEVERITY)

    if kind == "cve":
        # A CVE with no score at all: NVD has published it but not yet
        # rated it. Treat as MEDIUM — a known vulnerability that has not
        # been triaged is worth a look, but claiming HIGH would be
        # inventing evidence.
        return "MEDIUM"

    # Unknown shape — fall back to whatever label the producer supplied,
    # else the floor.
    return normalise_severity(finding.get("severity"))


def score_finding(finding: dict, target: str = "enrichment") -> dict:
    """
    Normalise any finding onto the project's four-tier severity scale.

    Parameters
    ----------
    finding : dict  a CVE from cve_lookup.lookup_cves()['cves'], a whole
                    lookup_cves() result, an open port, a service/version,
                    a missing header, a nikto line, a gobuster path or a
                    banner
    target  : str   scan target, used only to route the log line

    Returns
    -------
    dict — a shallow copy of `finding` (the input is never mutated) with:
        severity        : str  CRITICAL | HIGH | MEDIUM | LOW
        severity_source : str  "cvss" | "heuristic"
        cvss            : float | None  mirror of the CVSS score under the
                          column name database/db.py expects; only added
                          when a score was found and the key is absent

    Never raises: a non-dict argument comes back as a minimal LOW finding.
    """
    if not isinstance(finding, dict):
        print_warning(f"[Severity] ignoring non-dict finding: {type(finding).__name__}")
        return {
            "severity": "LOW",
            "severity_source": "heuristic",
            "error": f"invalid finding type: {type(finding).__name__}",
        }

    scored = dict(finding)
    kind = _finding_type(scored)

    score = _extract_score(scored)
    if score is not None:
        severity = severity_from_score(score)
        source = "cvss"
        if scored.get("cvss") is None:
            scored["cvss"] = score
    elif _has_cve(scored) and scored.get("cvss_severity"):
        # NVD rated it qualitatively but the numeric score did not survive
        # into this dict — still a CVSS-derived grade.
        severity = normalise_severity(scored.get("cvss_severity"))
        source = "cvss"
    else:
        severity = _heuristic_severity(scored, kind)
        source = "heuristic"

    scored["severity"] = normalise_severity(severity)
    scored["severity_source"] = source

    log_finding(target, {
        "type": kind,
        "cve_id": scored.get("cve_id"),
        "port": scored.get("port"),
        "severity": scored["severity"],
        "severity_source": source,
    })

    return scored


def score_findings(findings, target: str = "enrichment") -> list:
    """
    Convenience wrapper: grade a list of findings, worst-first.

    modules/reporting/ can hand the whole finding set straight to this.
    """
    scored = [score_finding(f, target=target) for f in (findings or [])]
    scored.sort(key=lambda f: SEVERITY_LEVELS.index(f.get("severity", "LOW"))
                if f.get("severity") in SEVERITY_LEVELS else len(SEVERITY_LEVELS))
    return scored


if __name__ == "__main__":
    samples = [
        {"cve_id": "CVE-2011-2523", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
        {"cve_id": "CVE-0000-0000", "cvss_score": 5.3},
        {"type": "open_port", "port": 23, "service": "telnet", "state": "open"},
        {"type": "open_port", "port": 8081, "service": "unknown", "state": "open"},
        {"type": "missing_security_header", "port": 80, "header": "Content-Security-Policy"},
        {"type": "nikto_finding", "description": "Backdoor found in /cgi-bin", "reference": ""},
        {"type": "discovered_path", "path": "/wp-admin/", "status_code": 200},
    ]
    for s in score_findings(samples):
        print_info(f"  {s['severity']:<8} ({s['severity_source']}) <- {s}")
