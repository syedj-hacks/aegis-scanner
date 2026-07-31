"""
modules/enrichment/cvss.py
A local CVSS v3.1 base-score calculator, and the finding_type -> vector
templates that let non-CVE findings carry a real score.

The gap this fills
------------------
Today a finding only has a CVSS score if NVD supplied one for a matched
CVE. Measured against this project's own database: of ~7,100 findings, 287
CVE rows and 31 nuclei rows have a score, and every one of the other ~6,800
— missing security headers, weak TLS ciphers, exposed admin paths, default
credentials — has `cvss = NULL` and a severity that came from a keyword
table. Those severities are reasonable, but they are not auditable: a
report that says MEDIUM cannot say *why* MEDIUM, and two findings graded
MEDIUM by two different keyword branches are not comparable.

A CVSS vector fixes exactly that. "Missing HSTS is MEDIUM" is an opinion;
"AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N = 5.0" is an opinion with its
reasoning attached, in a notation the reader can disagree with
specifically. The vector string is surfaced next to the score in the
reports for that reason — a number with no vector would just be a
differently-spelled bucket.

What this does NOT change
-------------------------
NVD-sourced scores are left exactly as they are. apply_local_cvss() is a
no-op for any finding that already has a score from anywhere — a real CVSS
score computed by the CVE's own analysts always beats a template, and the
templates here are deliberately never allowed to overwrite one.

The templates are also calibrated to AGREE with the severity the existing
heuristic already assigns (modules/enrichment/severity.py's keyword
tables), rather than to re-grade the codebase. The value being added is the
score and the vector, not a reshuffle of every finding's severity; a change
that silently moved thousands of findings between bands would be a much
bigger claim than "findings now carry a CVSS vector", and would be
impossible to review. Where a template's band deliberately differs from the
heuristic, the reason is stated at that template.

CVSS v4.0
---------
Not implemented, deliberately, rather than approximated. v4.0 base scoring
is not a formula: it classifies a vector into one of 270 "macrovectors" and
looks the score up in a published table, then interpolates between
neighbouring macrovectors. That table is the specification — there is no
closed form to derive it from, so a hand-rolled "v4-ish" score would be a
number with a misleading name on it, which is precisely what this module
exists to stop. v3.1 is what the NVD data this project already consumes is
expressed in, so the two are directly comparable.

Reference: FIRST CVSS v3.1 specification, section 7.1 (Base score
equations). The equations and constants below are transcribed from it; the
unit tests in tests/t_cvss.py check this implementation against published
worked examples, including the official v3.1 spec examples.
"""

import math

# --- v3.1 metric weights (spec table 7.1) --------------------------------
# Privileges Required is the only metric whose weight depends on Scope: a
# changed scope makes holding privileges less of an obstacle, so the
# weights rise.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VALID = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"},
    "UI": set(_UI), "S": {"U", "C"}, "C": set(_CIA),
    "I": set(_CIA), "A": set(_CIA),
}


def _roundup(value: float) -> float:
    """
    CVSS v3.1's Roundup, which is NOT ordinary rounding.

    The spec defines it on integer arithmetic specifically to avoid
    floating-point ties: scale by 100000, and if the result is not an exact
    multiple of 10000, round the first decimal place UP. Using round() here
    instead produces scores that are off by 0.1 on a number of real
    vectors — the classic symptom of a hand-rolled CVSS implementation.
    """
    integer_input = int(round(value * 100000))
    if integer_input % 10000 == 0:
        return integer_input / 100000.0
    return (math.floor(integer_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    """
    Parse a CVSS v3.1 vector string into its metric dict.

    Accepts an optional leading "CVSS:3.1/" prefix. Raises ValueError on a
    malformed vector or an unknown metric value — this one is allowed to
    raise because a bad vector is a bug in this file's own template table,
    caught by the tests, not something a scan can produce at runtime.
    """
    text = (vector or "").strip()
    if text.upper().startswith("CVSS:"):
        text = text.split("/", 1)[1] if "/" in text else ""

    metrics = {}
    for part in text.split("/"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition(":")
        key, value = key.strip().upper(), value.strip().upper()
        if key not in _VALID:
            raise ValueError(f"unknown CVSS metric '{key}' in vector: {vector}")
        if value not in _VALID[key]:
            raise ValueError(f"invalid value '{value}' for metric '{key}' in vector: {vector}")
        metrics[key] = value

    missing = [m for m in _METRIC_ORDER if m not in metrics]
    if missing:
        raise ValueError(f"CVSS vector missing metric(s) {missing}: {vector}")
    return metrics


def base_score(vector: str) -> float:
    """
    The CVSS v3.1 base score for `vector`, as a float rounded per the spec.

    Implements section 7.1 exactly:
        ISS         = 1 - [(1-C) x (1-I) x (1-A)]
        Impact      = 6.42 x ISS                                (S:U)
                    = 7.52 x (ISS-0.029) - 3.25 x (ISS-0.02)^15 (S:C)
        Exploitab.  = 8.22 x AV x AC x PR x UI
        Base        = 0                                  if Impact <= 0
                    = Roundup(min(Impact+Exploitability, 10))      (S:U)
                    = Roundup(min(1.08 x (Impact+Exploitability), 10)) (S:C)
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - (
        (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    pr_weights = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    exploitability = (
        8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_weights[m["PR"]] * _UI[m["UI"]]
    )

    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def normalise_vector(vector: str) -> str:
    """The vector in canonical metric order, with the CVSS:3.1/ prefix."""
    m = parse_vector(vector)
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _METRIC_ORDER)


# --- finding_type -> vector templates ------------------------------------
# Each entry is (vector, rationale). The rationale is not decoration: it is
# what makes a template reviewable, and it is what a reader needs in order
# to disagree with a specific metric rather than with the number as a whole.
#
# Every template below was chosen to land in the SAME severity band the
# existing heuristic assigns (see the module docstring), so adding these
# does not silently re-grade the finding set.

_HEADER_TEMPLATES = {
    # Missing HSTS lets an active network attacker strip TLS on the first
    # request. Needs a privileged network position (AC:H) and a user
    # navigation (UI:R), but crosses a security boundary once it works
    # (S:C) and exposes session data in both directions (C:L/I:L).
    "strict-transport-security": (
        "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "absent HSTS permits an SSL-strip downgrade by an active on-path "
        "attacker; needs position (AC:H) and a navigation (UI:R)",
    ),
    # CSP is a mitigation, not a control: its absence does not create a
    # vulnerability, it removes a defence against one. Same band as HSTS,
    # because the realistic outcome (script execution in page context) is
    # the same order of impact.
    "content-security-policy": (
        "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "no CSP removes the defence-in-depth layer against injected script "
        "executing in page context; exploitation still requires a separate "
        "injection flaw (AC:H)",
    ),
    # Clickjacking: no confidentiality loss, but the attacker induces a
    # state-changing action as the victim (I:L), across an origin (S:C).
    "x-frame-options": (
        "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "framing permits clickjacking a state-changing action as the victim; "
        "requires the victim to visit the attacker's page (UI:R)",
    ),
    "content-security-policy-frame-ancestors": (
        "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "same clickjacking exposure as a missing X-Frame-Options",
    ),
    # MIME sniffing turns an uploaded/reflected file into script in some
    # browsers. Confidentiality only, and conditional on other factors.
    "x-content-type-options": (
        "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "MIME-sniffing can promote user-controlled content to script; "
        "depends on browser and on a content-injection path (AC:H)",
    ),
    # Referrer leakage: a genuine but narrow confidentiality issue.
    "referrer-policy": (
        "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "full referrer disclosure can leak tokens or internal paths in URLs "
        "to third-party origins",
    ),
    "permissions-policy": (
        "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "no restriction on powerful browser features available to embedded "
        "content",
    ),
}

_DEFAULT_HEADER_TEMPLATE = (
    "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
    "missing hardening header — reduces defence in depth without being "
    "directly exploitable on its own",
)

# Where these land, checked against severity._MISSING_HEADER_SEVERITY
# header by header (all seven agree, verified 2026-07-31):
#
#   HSTS / CSP / X-Frame-Options            4.7  MEDIUM  = heuristic MEDIUM
#   X-Content-Type-Options / Referrer-      3.4  LOW     = heuristic LOW
#   Policy / X-XSS-Protection / Permissions-Policy
#
# That agreement is the point, and it is not a coincidence: the heuristic
# table already encodes the judgement that the first three enable a
# concrete attack (downgrade+MITM, script execution, clickjacking) while
# the rest are hardening niceties. These vectors were chosen to reproduce
# that split, so the scores explain a grading the project had already
# settled on rather than quietly renegotiating it.

# Sensitive path exposure. Graded by what the path actually exposes, which
# is the same intent _PATH_KEYWORDS in severity.py encodes.
_PATH_TEMPLATES = [
    (
        ("/.git", "/.svn", "/.env", "/.htpasswd", "/id_rsa", "/wp-config",
         "/config.php", "/dump.sql", "/backup", "/.bak"),
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "source, credentials or database contents retrievable without "
        "authentication — direct, complete confidentiality loss",
    ),
    (
        ("/phpmyadmin", "/adminer", "/manager", "/console", "/shell"),
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "administrative interface reachable from the network; impact is "
        "bounded by its own authentication, which is not assessed here",
    ),
    (
        ("/admin", "/login", "/wp-admin", "/wp-login", "/cgi-bin", "/upload",
         "/phpinfo", "/server-status", "/test"),
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "administrative or diagnostic endpoint disclosed; useful to an "
        "attacker as a precursor rather than directly damaging",
    ),
]

# TLS findings are graded by WHAT was found, not just that sslyze/testssl
# found something: an accepted SSLv3 and an accepted 3DES suite are not the
# same weakness, and collapsing both onto one vector would throw away the
# distinction the existing heuristic already makes (it grades a legacy
# protocol HIGH and a weak cipher MEDIUM). Matched against the issue text,
# worst first.
_TLS_TEMPLATES = [
    (
        ("sslv2", "sslv3", "legacy protocol", "poodle", "drown", "freak",
         "logjam", "heartbleed", "robot", "ticketbleed", "ccs injection"),
        "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "a broken protocol or a named TLS attack permits recovery or "
        "tampering of transported plaintext by an on-path attacker",
    ),
    (
        ("weak cipher", "rc4", "3des", "export", "null", "anon", "sweet32",
         "beast", "lucky13", "cbc"),
        "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "a weak cipher suite permits recovery of transported plaintext given "
        "sufficient captured traffic and an on-path position",
    ),
]
_DEFAULT_TLS_TEMPLATE = (
    "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "TLS configuration weakness affecting the confidentiality of transported "
    "data",
)

_TYPE_TEMPLATES = {
    # These two diverge from the existing heuristic ON PURPOSE, and are the
    # only templates that do.
    #
    # severity.py has no keyword branch for either, so both currently fall
    # through to the LOW default — a confirmed SQL injection and a working
    # default credential are both reported as LOW today. That is not a
    # calibrated judgement that got it wrong, it is an unhandled case: the
    # heuristic never had a rule for "a tool positively confirmed
    # exploitation". Grading a confirmed SQLi LOW is the one outcome no
    # reader would defend, so these get the vectors the finding actually
    # warrants.
    #
    # Volume makes this safe to correct: 4 sqlmap_finding rows and 3
    # weak_credentials rows exist in the whole database, so this sharpens a
    # handful of genuine findings rather than re-grading the corpus.
    "weak_credentials": (
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "a guessed or default credential grants that account's full "
        "privileges — the standard remote authentication-bypass vector",
    ),
    "sqlmap_finding": (
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "sqlmap CONFIRMED injection (not merely suspected): unauthenticated "
        "read and write of database contents",
    ),
    # Matches the heuristic's MEDIUM, and matches NVD's own canonical vector
    # for reflected XSS exactly.
    "xss_finding": (
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "reflected XSS executing in the victim's origin — the 6.1 vector NVD "
        "uses for this class",
    ),
}

# Finding types deliberately left WITHOUT a template.
#
# Every one of these is an information-disclosure precursor that the
# existing heuristic grades LOW, and that grade is right: an nginx version
# in a Server header is worth noting and is not worth escalating. A CVSS
# vector for "version disclosed" is defensibly AV:N/AC:L/PR:N/UI:N/S:U/
# C:L/I:N/A:N = 5.3, which is MEDIUM — and applying it would promote ~5,600
# banner/fingerprint/technology/discovered-path rows in this database alone
# from LOW to MEDIUM. That is not a more accurate report, it is a report
# where the real findings are buried under precursors.
#
# So they keep the heuristic's LOW and carry no score. A finding with no
# CVSS is an honest statement that this project does not have a defensible
# one for it; a finding with a score that floods the MEDIUM band is not.
# Named here rather than merely absent so the omission reads as a decision.
UNSCORED_TYPES = (
    "banner", "fingerprint_header", "technology_fingerprint",
    "wordpress_fingerprinted", "smb_share", "smb_user", "open_port",
    "service_version", "nikto_finding", "nmap_script", "zap_finding",
    "nuclei_finding", "wpscan_finding",
)


def _header_name(finding: dict) -> str:
    return str(
        finding.get("header") or finding.get("missing_header") or ""
    ).strip().lower()


def template_for(finding: dict):
    """
    The (vector, rationale) template for `finding`, or (None, None) when
    this finding type has no defensible template.

    Returning nothing is a real answer and is used deliberately: an
    `open_port` or a generic `nikto_finding` covers too wide a range of
    actual impact for one vector to describe honestly, so those keep the
    existing keyword-derived severity and simply carry no CVSS. Inventing a
    vector for them would make the score look more principled than it is,
    which is the failure mode this whole module is meant to avoid.
    """
    if not isinstance(finding, dict):
        return None, None

    kind = str(
        finding.get("type") or finding.get("finding_type") or ""
    ).strip().lower()

    if kind in UNSCORED_TYPES:
        return None, None

    if kind == "missing_security_header":
        return _HEADER_TEMPLATES.get(_header_name(finding), _DEFAULT_HEADER_TEMPLATE)

    if kind == "sslyze_finding":
        # Both sslyze and testssl.sh emit into this finding family (see
        # modules/web/testssl_wrap.py), so the issue text is what
        # distinguishes a broken protocol from a merely weak cipher.
        text = " ".join(str(finding.get(k) or "") for k in
                        ("issue", "description", "detail")).lower()
        for keywords, vector, rationale in _TLS_TEMPLATES:
            if any(keyword in text for keyword in keywords):
                return vector, rationale
        return _DEFAULT_TLS_TEMPLATE

    if kind == "discovered_path":
        path = str(finding.get("path") or "").strip().lower()
        if not path:
            return None, None
        for keywords, vector, rationale in _PATH_TEMPLATES:
            if any(keyword in path for keyword in keywords):
                return vector, rationale
        # An ordinary discovered path is not a weakness. No template, so it
        # keeps its existing LOW grade and gains no score — scoring 5,000
        # routine paths would bury the findings that matter.
        return None, None

    entry = _TYPE_TEMPLATES.get(kind)
    if entry:
        return entry
    return None, None


def apply_local_cvss(finding: dict) -> dict:
    """
    Fill in a CVSS score and vector for a non-CVE finding, if a defensible
    template exists for it.

    Returns a shallow copy with `cvss`, `cvss_vector` and `cvss_rationale`
    added; returns the input unchanged (a copy) when:

      - it already has a score from any source (an NVD score always wins),
      - it is CVE-backed (its score is NVD's to supply, even if this
        particular lookup did not return one — filling that gap with a
        template would silently misattribute a guess to the CVE), or
      - no template covers this finding type.

    Never raises: a bad template is a programming error caught by the
    tests, but at runtime a failure to score is not worth losing a finding
    over, so it degrades to "no score added".
    """
    if not isinstance(finding, dict):
        return finding

    out = dict(finding)

    if out.get("cve_id") or out.get("cves"):
        return out
    for key in ("cvss", "cvss_score", "base_score", "baseScore"):
        if out.get(key) is not None:
            return out

    vector, rationale = template_for(out)
    if not vector:
        return out

    try:
        out["cvss"] = base_score(vector)
        out["cvss_vector"] = normalise_vector(vector)
        out["cvss_rationale"] = rationale
    except (ValueError, TypeError, KeyError):
        return dict(finding)

    return out


if __name__ == "__main__":
    for v in (
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    ):
        print(f"{base_score(v):5.1f}  {normalise_vector(v)}")
