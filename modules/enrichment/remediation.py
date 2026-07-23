"""
modules/enrichment/remediation.py
Remediation guidance for Aegis Scanner (Member C - enrichment layer).

Last stage of the enrichment chain:

    lookup_cves() -> score_finding() -> get_remediation()

For a CVE-backed finding the advice is drawn from the NVD reference list
cve_lookup.py captured — a Patch or Vendor Advisory link is the single most
useful thing to hand an operator, so it is surfaced verbatim. Everything
else falls back to the static tables below, which are deliberately plain
data: one to two sentences per entry, easy for a teammate to review or
reword without touching the control flow.

This module performs no I/O — no subprocesses and no HTTP — so there is
nothing here to wrap in run_tool()/safe_call(); it only ever reads the
finding dict it is handed.
"""

from modules.utils.display import print_warning

# ---------------------------------------------------------------------
# CVE-backed guidance
# ---------------------------------------------------------------------
# NVD reference tags, best-first. A Patch link points at the actual fix; a
# Vendor Advisory explains it; Mitigation covers the "no patch yet" case;
# Release Notes are weaker again. Third Party Advisory is last but still
# worth surfacing — plenty of older CVEs (CVE-2011-2523, the vsftpd
# backdoor, among them) carry no vendor-tagged reference at all, and
# without this entry those findings lose their only usable link.
# Exploit / Mailing List / VDB Entry links are deliberately never offered
# as remediation.
_REFERENCE_TAG_PRIORITY = ("Patch", "Vendor Advisory", "Mitigation",
                           "Release Notes", "Third Party Advisory")

# Tags that represent an actual fix from the vendor, as opposed to a
# third-party write-up. Controls how the advice is worded.
_VENDOR_FIX_TAGS = ("Patch", "Vendor Advisory", "Release Notes")

# ---------------------------------------------------------------------
# Static tables (non-CVE findings)
# ---------------------------------------------------------------------

_HEADER_REMEDIATION = {
    "Strict-Transport-Security": (
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "over HTTPS so browsers refuse to downgrade to plaintext."
    ),
    "Content-Security-Policy": (
        "Define a Content-Security-Policy restricting script/style sources to "
        "trusted origins; start in report-only mode to find breakage first."
    ),
    "X-Frame-Options": (
        "Set 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) to "
        "block clickjacking via hidden iframes."
    ),
    "X-Content-Type-Options": (
        "Set 'X-Content-Type-Options: nosniff' so browsers honour the declared "
        "Content-Type instead of guessing it."
    ),
    "Referrer-Policy": (
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' to stop full "
        "URLs (and any tokens in them) leaking to third-party sites."
    ),
    "X-XSS-Protection": (
        "Set 'X-XSS-Protection: 0' and rely on a Content-Security-Policy — the "
        "legacy auditor this header controls is removed from modern browsers."
    ),
}
_DEFAULT_HEADER_REMEDIATION = (
    "Configure this security header at the web server or reverse proxy so it "
    "is applied to every response."
)

# Keyed by port; matched before the service-name table below.
_PORT_REMEDIATION = {
    21: "Replace FTP with SFTP/FTPS — FTP sends credentials in cleartext. If it must stay, disable anonymous login and restrict access by source IP.",
    23: "Disable telnet and use SSH instead; telnet transmits credentials and session data in cleartext.",
    69: "Disable TFTP unless a device genuinely needs it — it offers no authentication at all. Firewall it to the specific hosts that require it.",
    111: "Restrict rpcbind to trusted networks or disable it; exposing it lets an attacker enumerate every RPC service on the host.",
    135: "Block msrpc (135) at the network edge — it should never be reachable from an untrusted network.",
    139: "Block NetBIOS (139) at the perimeter and disable SMBv1; expose file sharing only on trusted internal segments.",
    445: "Restrict SMB (445) to trusted networks, disable SMBv1, and require signing to prevent relay attacks.",
    512: "Disable the rexec service — it authenticates in cleartext. Use SSH for remote execution.",
    513: "Disable rlogin — it trusts .rhosts entries and sends credentials in cleartext. Use SSH.",
    514: "Disable rsh — it allows trust-based remote shells with no real authentication. Use SSH.",
    1099: "Restrict or disable Java RMI (1099); an exposed registry commonly allows remote class loading and code execution.",
    1433: "Do not expose MSSQL to untrusted networks — bind it to localhost or a private interface and require strong authentication.",
    1524: "Port 1524 answering is a classic bindshell backdoor. Treat the host as compromised, take it off the network and rebuild it.",
    2049: "Restrict NFS exports to specific trusted hosts with root_squash enabled; never export to the world.",
    2121: "Same guidance as FTP: replace with SFTP/FTPS, or restrict this alternate FTP port to trusted sources.",
    3306: "Bind MySQL to localhost or a private interface, require authentication, and firewall 3306 from untrusted networks.",
    3389: "Do not expose RDP directly. Put it behind a VPN, enable Network Level Authentication, and enforce account lockout.",
    5432: "Bind PostgreSQL to a private interface, enforce scram-sha-256 auth in pg_hba.conf, and firewall 5432.",
    5900: "Do not expose VNC — it has weak/no authentication. Tunnel it over SSH or a VPN and set a strong password.",
    6000: "Disable X11 TCP listening ('-nolisten tcp'); an exposed X server lets an attacker read the screen and inject keystrokes.",
    6379: "Redis is unauthenticated by default. Bind it to localhost, enable requirepass, and enable protected-mode.",
    6667: "Audit this IRC daemon and its version — backdoored ircd builds are a known compromise vector. Disable it if it is not required.",
    8009: "Restrict or disable the AJP connector (8009); exposed connectors allow file read and, in some versions, remote code execution.",
    9200: "Elasticsearch ships without authentication. Bind it to a private interface and enable the security features before exposing it.",
    27017: "MongoDB is unauthenticated by default. Enable authorisation, bind to a private interface, and firewall 27017.",
    25: "Ensure the SMTP service is not an open relay and require STARTTLS for authenticated submission.",
    80: "Redirect all HTTP traffic to HTTPS and serve the site over TLS so credentials and sessions are not sent in the clear.",
    110: "Disable plaintext POP3 or require STARTTLS/POP3S so mailbox credentials are not sent in the clear.",
    143: "Disable plaintext IMAP or require STARTTLS/IMAPS so mailbox credentials are not sent in the clear.",
}

# Fallback by service name for ports the table above does not cover.
_SERVICE_REMEDIATION = {
    "ftp": _PORT_REMEDIATION[21],
    "telnet": _PORT_REMEDIATION[23],
    "microsoft-ds": _PORT_REMEDIATION[445],
    "netbios-ssn": _PORT_REMEDIATION[139],
    "mysql": _PORT_REMEDIATION[3306],
    "postgresql": _PORT_REMEDIATION[5432],
    "ms-sql-s": _PORT_REMEDIATION[1433],
    "vnc": _PORT_REMEDIATION[5900],
    "ms-wbt-server": _PORT_REMEDIATION[3389],
    "x11": _PORT_REMEDIATION[6000],
    "redis": _PORT_REMEDIATION[6379],
    "mongodb": _PORT_REMEDIATION[27017],
    "nfs": _PORT_REMEDIATION[2049],
    "irc": _PORT_REMEDIATION[6667],
}

_DEFAULT_PORT_REMEDIATION = (
    "Confirm this service needs to be reachable from untrusted networks; if "
    "not, firewall the port or bind the service to a private interface."
)

# Matched as a substring of the lower-cased path, worst-first.
_PATH_REMEDIATION = [
    (("/.git", "/.svn"),
     "Remove the version-control directory from the web root — it exposes full source history. Block /.git and /.svn at the web server."),
    (("/.env", "/config.php", "/wp-config", "/.htpasswd", "/id_rsa"),
     "Move this configuration/credential file outside the web root and rotate every secret it contains, since it must be assumed disclosed."),
    (("/backup", "/.bak", "/dump.sql"),
     "Remove backups and database dumps from the web root; store them off the web server with restricted permissions."),
    (("/phpmyadmin", "/adminer", "/manager", "/console"),
     "Restrict this database/app admin console by source IP or VPN, and change any default credentials immediately."),
    (("/wp-admin", "/wp-login"),
     "Restrict the WordPress login by IP or a WAF rule, enforce strong passwords with MFA, and rate-limit login attempts."),
    (("/admin", "/login"),
     "Protect the admin/login interface with strong authentication, MFA and rate limiting; restrict it by source IP where practical."),
    (("/phpinfo", "/server-status"),
     "Remove or restrict this diagnostic endpoint — it discloses server configuration, paths and module versions."),
    (("/cgi-bin",),
     "Remove unused CGI scripts and disable the cgi-bin handler; legacy CGI is a common remote-code-execution path."),
    (("/upload", "/shell"),
     "Verify this path does not allow unauthenticated file upload or execution; restrict it and store uploads outside the web root."),
]
_DEFAULT_PATH_REMEDIATION = (
    "Confirm this path is intended to be publicly reachable; remove or "
    "restrict it if it is not part of the published application."
)

# Nikto emits free text, so its guidance is keyword-matched, worst-first.
_NIKTO_REMEDIATION = [
    (("backdoor", "remote shell", "arbitrary code", "remote code execution", "command execution", "command injection"),
     "Treat this host as compromised: isolate it, preserve evidence, and rebuild from a known-good image rather than patching in place."),
    (("sql injection", "sqli"),
     "Parameterise all database queries and validate input; retest the affected endpoint once the fix is deployed."),
    (("directory traversal", "path traversal", "file inclusion"),
     "Canonicalise and whitelist any user-supplied path, and run the service as an unprivileged user confined to its document root."),
    (("default account", "default password", "default credentials"),
     "Change the default credentials immediately and disable any unused default accounts."),
    (("directory indexing", "index of"),
     "Disable automatic directory listing (Apache: 'Options -Indexes') so the file tree is not browsable."),
    (("outdated", "out of date", "appears to be"),
     "Upgrade the software to a currently supported release — the running version no longer receives security fixes."),
    (("phpinfo",),
     "Delete phpinfo() test pages from the web root; they disclose configuration, paths and module versions."),
    (("trace", "track"),
     "Disable the HTTP TRACE/TRACK methods ('TraceEnable off') to prevent cross-site tracing."),
    (("webdav",),
     "Disable WebDAV unless it is required; if it is, require authentication and restrict write access."),
    (("cross site scripting", "xss"),
     "Encode all user-controlled output for its context and deploy a Content-Security-Policy as defence in depth."),
    (("cookie", "httponly", "secure flag"),
     "Set the Secure, HttpOnly and SameSite attributes on session cookies."),
    (("etag", "inode"),
     "Configure 'FileETag MTime Size' so ETags no longer disclose server inode numbers."),
]
_DEFAULT_NIKTO_REMEDIATION = (
    "Review this nikto finding against the application's intended "
    "configuration and remove or restrict the exposed functionality."
)

_BANNER_REMEDIATION = (
    "Suppress version details in service banners (Apache: 'ServerTokens Prod' "
    "and 'ServerSignature Off') so the exact build is not advertised to "
    "attackers looking for a matching exploit."
)

_WORDPRESS_REMEDIATION = (
    "Keep WordPress core, themes and plugins fully patched and remove unused "
    "ones; run wpscan against this install to enumerate vulnerable components."
)

_UNKNOWN_REMEDIATION = (
    "Review this finding manually — no automated remediation guidance is "
    "available for it."
)


def _pick_reference(references) -> tuple:
    """
    Return (url, tag) for the most actionable reference in an NVD
    reference list, or ("", "") if none of the useful tags are present.

    Preference order is _REFERENCE_TAG_PRIORITY; a link tagged Exploit or
    Mailing List is never returned as remediation advice. The tag comes
    back too so the caller can word vendor fixes differently from
    third-party advisories.
    """
    if not references:
        return "", ""

    for wanted in _REFERENCE_TAG_PRIORITY:
        for ref in references:
            if not isinstance(ref, dict):
                continue
            if wanted in (ref.get("tags") or []) and ref.get("url"):
                return ref["url"], wanted
    return "", ""


def _describe_product(finding: dict) -> str:
    """'vsftpd 2.3.4' / 'vsftpd' / 'the affected service' for prose use."""
    product = str(finding.get("product") or finding.get("service") or "").strip()
    version = str(finding.get("version") or "").strip()
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    return "the affected service"


def _cve_remediation(finding: dict) -> str:
    """
    Guidance for a CVE-backed finding.

    Works for a single CVE dict from cve_lookup and for a whole
    lookup_cves() result, in which case the worst-scoring CVE (the list is
    already sorted worst-first) is the one advised on.
    """
    cve = finding
    if not finding.get("cve_id") and finding.get("cves"):
        cve = finding["cves"][0]

    cve_id = cve.get("cve_id") or "the reported CVE"
    product = _describe_product(finding) if finding.get("product") else _describe_product(cve)

    url, tag = _pick_reference(cve.get("references"))
    if url and tag in _VENDOR_FIX_TAGS:
        return (
            f"Apply the vendor fix for {cve_id} on {product}: {url}. "
            "If patching is not immediately possible, restrict access to the "
            "service until it is."
        )
    if url:
        # Mitigation / third-party advisory: real guidance, but not a
        # vendor patch — say so rather than implying an official fix.
        return (
            f"Upgrade {product} to a fixed release; see the published advisory "
            f"for {cve_id}: {url}. Restrict access to the service until it is "
            "patched."
        )

    return (
        f"Upgrade {product} to a release that fixes {cve_id} (see "
        f"https://nvd.nist.gov/vuln/detail/{cve_id}). Until then, restrict "
        "access to the service to trusted networks only."
    )


def _match_table(text: str, table) -> str:
    """First keyword-table entry whose keyword appears in `text`."""
    lowered = (text or "").lower()
    for keywords, advice in table:
        for keyword in keywords:
            if keyword in lowered:
                return advice
    return ""


def _finding_kind(finding: dict) -> str:
    """
    Same shape-sniffing contract as severity._finding_type: an explicit
    `type` wins, otherwise the shape is inferred from the keys the
    scanning/web modules actually return.
    """
    declared = str(finding.get("type") or "").strip().lower()
    if declared:
        return declared

    if finding.get("cve_id") or finding.get("cves"):
        return "cve"
    if finding.get("header") or finding.get("missing_header"):
        return "missing_security_header"
    if finding.get("description") is not None and "reference" in finding:
        return "nikto_finding"
    if finding.get("path"):
        return "discovered_path"
    if finding.get("banner_text"):
        return "banner"
    if finding.get("server_banner") or finding.get("powered_by"):
        return "fingerprint_header"
    if finding.get("product") or finding.get("version"):
        return "service_version"
    if finding.get("port") is not None:
        return "open_port"
    return "unknown"


def remediation_text(finding: dict) -> str:
    """
    Return the remediation string for `finding` without copying the dict.
    Useful for reporting code that only wants the sentence.
    """
    if not isinstance(finding, dict):
        return _UNKNOWN_REMEDIATION

    kind = _finding_kind(finding)

    if kind == "cve" or finding.get("cve_id") or finding.get("cves"):
        return _cve_remediation(finding)

    if kind == "missing_security_header":
        header = finding.get("header") or finding.get("missing_header") or ""
        return _HEADER_REMEDIATION.get(header, _DEFAULT_HEADER_REMEDIATION)

    if kind == "nikto_finding":
        text = f"{finding.get('description', '')} {finding.get('reference', '')}"
        return _match_table(text, _NIKTO_REMEDIATION) or _DEFAULT_NIKTO_REMEDIATION

    if kind == "wordpress_fingerprinted":
        return _WORDPRESS_REMEDIATION

    if kind == "discovered_path":
        return _match_table(str(finding.get("path") or ""),
                            _PATH_REMEDIATION) or _DEFAULT_PATH_REMEDIATION

    if kind in ("banner", "fingerprint_header"):
        return _BANNER_REMEDIATION

    if kind in ("open_port", "service_version"):
        try:
            port = int(finding.get("port"))
        except (TypeError, ValueError):
            port = None
        if port in _PORT_REMEDIATION:
            return _PORT_REMEDIATION[port]
        service = str(finding.get("service") or "").strip().lower()
        if service in _SERVICE_REMEDIATION:
            return _SERVICE_REMEDIATION[service]
        if kind == "service_version" and finding.get("version"):
            # No CVE matched, but an exact version is being advertised.
            return (
                f"Confirm {_describe_product(finding)} is a currently supported, "
                "fully patched release, and suppress the version string from its "
                "banner."
            )
        return _DEFAULT_PORT_REMEDIATION

    return _UNKNOWN_REMEDIATION


def get_remediation(finding: dict) -> dict:
    """
    Attach remediation guidance to an enriched finding.

    Parameters
    ----------
    finding : dict  typically the output of severity.score_finding(), but
                    any finding shape the framework produces works

    Returns
    -------
    dict — a shallow copy of `finding` (the input is never mutated) with:
        remediation : str  one to two sentences of actionable guidance;
                           for CVE-backed findings this leads with the NVD
                           Patch/Vendor Advisory URL when one was captured

    Never raises: a non-dict argument comes back as a minimal dict carrying
    the generic "review this manually" guidance.
    """
    if not isinstance(finding, dict):
        print_warning(f"[Remediation] ignoring non-dict finding: {type(finding).__name__}")
        return {
            "remediation": _UNKNOWN_REMEDIATION,
            "error": f"invalid finding type: {type(finding).__name__}",
        }

    enriched = dict(finding)
    enriched["remediation"] = remediation_text(enriched)
    return enriched


def remediate_findings(findings) -> list:
    """Convenience wrapper: attach remediation to a whole list of findings."""
    return [get_remediation(f) for f in (findings or [])]


if __name__ == "__main__":
    from modules.utils.display import print_info

    samples = [
        {"cve_id": "CVE-2011-2523", "cvss_score": 9.8,
         "references": [{"url": "https://example.org/adv", "tags": ["Vendor Advisory"]}]},
        {"type": "missing_security_header", "header": "Content-Security-Policy"},
        {"type": "open_port", "port": 23, "service": "telnet"},
        {"type": "discovered_path", "path": "/.git/config"},
        {"type": "nikto_finding", "description": "Directory indexing found.", "reference": ""},
        {"port": 21, "banner_text": "220 (vsFTPd 2.3.4)"},
    ]
    for s in samples:
        print_info(f"  {get_remediation(s)['remediation']}")
