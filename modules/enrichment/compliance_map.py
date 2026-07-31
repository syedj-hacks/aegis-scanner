"""
modules/enrichment/compliance_map.py
Maps a finding to the PCI-DSS, ISO 27001 and NIST 800-53 controls it bears
on — for the `compliance` profile only.

Scope, and why it is narrow
---------------------------
This runs for `profile == "compliance"` and nothing else. That is a
deliberate limit, not an unfinished rollout.

A control reference is a claim that a finding is evidence about a specific
requirement, and it is read by people who act on it — an auditor, or an
engineer preparing for one. Stamping "PCI-DSS Req 6.2.4" onto every CVE a
deepscan happens to turn up would make that claim thousands of times an
hour, mostly about hosts that are not in a cardholder-data environment at
all. The reference stops meaning "this was assessed against the standard"
and starts meaning "a keyword matched", which is worse than no reference,
because the first reading is the one a reader will take.

So: compliance findings get mappings; other profiles leave the field NULL
and their reports are byte-for-byte unchanged.

Honesty of the mappings themselves
----------------------------------
Every mapping below is one where the connection is direct and defensible —
a TLS weakness genuinely is what PCI-DSS Req 4.2.1 is about. Where a
finding type has no honest mapping, it gets NONE rather than a
loosely-related control: an empty field says "not assessed", which is true,
while a wrong control reference sends someone to read a requirement that
turns out to have nothing to do with what was found.

Control references are cited to the current revisions this project targets:
PCI-DSS v4.0, ISO/IEC 27001:2022 Annex A, and NIST SP 800-53 Rev. 5. The
revision matters — ISO 27001's Annex A was renumbered wholesale in the 2022
revision, so a bare "A.10.1.1" would be ambiguous between two standards a
reader might have open.
"""

# finding_type -> list of control references.
#
# Ordered PCI, ISO, NIST within each entry so a reader scanning a report
# column always finds the same framework in the same position.
_TYPE_CONTROLS = {
    # Weak/legacy TLS, from either sslyze or testssl.sh (both emit into
    # this finding family — see modules/web/testssl_wrap.py).
    "sslyze_finding": [
        "PCI-DSS v4.0 Req 4.2.1 (strong cryptography for cardholder data in transit)",
        "ISO 27001:2022 A.8.24 (use of cryptography)",
        "NIST 800-53 Rev.5 SC-8(1) (transmission confidentiality — cryptographic protection)",
    ],
    "missing_security_header": [
        "PCI-DSS v4.0 Req 6.4.1 (protect public-facing web applications)",
        "ISO 27001:2022 A.8.26 (application security requirements)",
        "NIST 800-53 Rev.5 SC-8 (transmission confidentiality and integrity)",
    ],
    "cve": [
        "PCI-DSS v4.0 Req 6.3.1 (identify and manage security vulnerabilities)",
        "PCI-DSS v4.0 Req 6.3.3 (install applicable security patches)",
        "ISO 27001:2022 A.8.8 (management of technical vulnerabilities)",
        "NIST 800-53 Rev.5 RA-5 (vulnerability monitoring and scanning)",
        "NIST 800-53 Rev.5 SI-2 (flaw remediation)",
    ],
    "weak_credentials": [
        "PCI-DSS v4.0 Req 2.2.2 (vendor default accounts removed or disabled)",
        "PCI-DSS v4.0 Req 8.3.1 (strong authentication for all access)",
        "ISO 27001:2022 A.5.17 (authentication information)",
        "NIST 800-53 Rev.5 IA-5 (authenticator management)",
    ],
    "open_port": [
        "PCI-DSS v4.0 Req 1.2.5 (only necessary services, protocols and ports allowed)",
        "ISO 27001:2022 A.8.20 (networks security)",
        "NIST 800-53 Rev.5 CM-7 (least functionality)",
    ],
    "service_version": [
        "PCI-DSS v4.0 Req 2.2.1 (system components configured securely)",
        "ISO 27001:2022 A.8.9 (configuration management)",
        "NIST 800-53 Rev.5 CM-6 (configuration settings)",
    ],
    # Version/technology disclosure. Genuinely an information-exposure
    # control question, and nothing more than that.
    "banner": [
        "ISO 27001:2022 A.8.9 (configuration management)",
        "NIST 800-53 Rev.5 SI-11 (error handling — no sensitive detail exposed)",
    ],
    "fingerprint_header": [
        "ISO 27001:2022 A.8.9 (configuration management)",
        "NIST 800-53 Rev.5 SI-11 (error handling — no sensitive detail exposed)",
    ],
    "technology_fingerprint": [
        "ISO 27001:2022 A.8.9 (configuration management)",
        "NIST 800-53 Rev.5 SI-11 (error handling — no sensitive detail exposed)",
    ],
    "sqlmap_finding": [
        "PCI-DSS v4.0 Req 6.2.4 (protect against injection attacks in software)",
        "ISO 27001:2022 A.8.28 (secure coding)",
        "NIST 800-53 Rev.5 SI-10 (information input validation)",
    ],
    "xss_finding": [
        "PCI-DSS v4.0 Req 6.2.4 (protect against injection attacks in software)",
        "ISO 27001:2022 A.8.28 (secure coding)",
        "NIST 800-53 Rev.5 SI-10 (information input validation)",
    ],
    "discovered_path": [
        "PCI-DSS v4.0 Req 6.4.1 (protect public-facing web applications)",
        "ISO 27001:2022 A.8.3 (information access restriction)",
        "NIST 800-53 Rev.5 AC-3 (access enforcement)",
    ],
    "smb_share": [
        "PCI-DSS v4.0 Req 1.2.5 (only necessary services, protocols and ports allowed)",
        "ISO 27001:2022 A.8.3 (information access restriction)",
        "NIST 800-53 Rev.5 AC-3 (access enforcement)",
    ],
}

# nmap --script findings are the compliance profile's own core evidence
# (ssl-enum-ciphers and http-headers), so they are mapped by WHICH script
# produced them rather than lumped under one control. A script this table
# does not know is left unmapped rather than assigned the TLS controls,
# which would be a specific and probably wrong claim.
_SCRIPT_CONTROLS = {
    "ssl-enum-ciphers": _TYPE_CONTROLS["sslyze_finding"],
    "ssl-cert": [
        "PCI-DSS v4.0 Req 4.2.1 (strong cryptography for cardholder data in transit)",
        "ISO 27001:2022 A.8.24 (use of cryptography)",
        "NIST 800-53 Rev.5 SC-17 (public key infrastructure certificates)",
    ],
    "http-headers": _TYPE_CONTROLS["missing_security_header"],
    "http-security-headers": _TYPE_CONTROLS["missing_security_header"],
}

# Frameworks, in the order reports group them. The prefix is what a
# reference string is matched on, so it must stay in step with the strings
# above — tests/t_compliance_map.py asserts every reference starts with one
# of these.
FRAMEWORKS = (
    ("PCI-DSS", "PCI-DSS v4.0"),
    ("ISO 27001", "ISO/IEC 27001:2022"),
    ("NIST 800-53", "NIST SP 800-53 Rev. 5"),
)


def compliance_refs(finding: dict, profile: str = None):
    """
    The control references for `finding`, or None.

    Returns None — not an empty list — for every profile other than
    `compliance`, and for any finding type with no honest mapping. None is
    what db.py stores as NULL, which is how a report tells "not assessed
    against a framework" apart from "assessed and mapped to nothing".

    Never raises.
    """
    if profile != "compliance" or not isinstance(finding, dict):
        return None

    kind = str(
        finding.get("type") or finding.get("finding_type") or ""
    ).strip().lower()

    if kind == "nmap_script":
        script_id = str(finding.get("script_id") or "").strip().lower()
        refs = _SCRIPT_CONTROLS.get(script_id)
        return list(refs) if refs else None

    refs = _TYPE_CONTROLS.get(kind)
    return list(refs) if refs else None


def apply_compliance_refs(finding: dict, profile: str = None) -> dict:
    """
    Shallow copy of `finding` with `compliance_refs` set, when one applies.

    A no-op returning an unchanged copy for non-compliance profiles, which
    is what keeps every other profile's findings and reports identical to
    before this module existed.
    """
    if not isinstance(finding, dict):
        return finding
    refs = compliance_refs(finding, profile=profile)
    if not refs:
        return dict(finding)
    return dict(finding, compliance_refs=refs)


def framework_of(reference: str):
    """
    The framework label a single reference string belongs to, or None.

    Used by the report generators to group findings by framework without
    each of them re-implementing the prefix match.
    """
    text = str(reference or "").strip()
    for prefix, label in FRAMEWORKS:
        if text.startswith(prefix):
            return label
    return None


def group_by_framework(findings) -> dict:
    """
    Group findings by framework: {framework label: [(reference, finding)]}.

    One finding appears under every framework it maps to — that is the
    point, since the same weak cipher is evidence for a PCI requirement AND
    an ISO control, and an auditor reads one framework at a time. Frameworks
    with no findings are omitted entirely rather than rendered empty.
    """
    grouped = {}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        refs = finding.get("compliance_refs")
        if not refs:
            continue
        if isinstance(refs, str):
            # A row read back from SQLite, where this is a TEXT column.
            refs = [r.strip() for r in refs.split(",") if r.strip()]
            # Control references contain commas of their own inside their
            # parenthesised descriptions, so a naive split fragments them.
            # Re-join any fragment that does not itself start a framework.
            merged = []
            for ref in refs:
                if framework_of(ref) or not merged:
                    merged.append(ref)
                else:
                    merged[-1] += ", " + ref
            refs = merged
        for ref in refs:
            label = framework_of(ref)
            if not label:
                continue
            grouped.setdefault(label, []).append((ref, finding))

    return grouped
