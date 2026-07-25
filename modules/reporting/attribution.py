"""
modules/reporting/attribution.py
Attribution correctness for stored findings — "did the tool this finding is
credited to actually run?" and "does this row's declared type still match
the columns it carries?"

Why this module exists
----------------------
smoke_test8 §4.2 records a defect that 317 unit assertions and a
whole-database render sweep both passed straight through: adding the
`reference` column made every SQLite row satisfy a classifier branch keyed
on that key merely being PRESENT, so a stealthscan open-port finding was
rendered with nikto's remediation text — naming a tool that never ran in
that profile. It was caught by a human reading one report.

The sweep that missed it checks for ambiguous cells, duplicate rendered
lines and crashes. None of those is the same question as "is this finding
attributed to the right tool", which is what this module answers, for every
row in the database, mechanically:

  1. TOOL PLAUSIBILITY — classify the row exactly as a report will
     (remediation.finding_kind(), the same call the renderer makes), map
     that kind to the tool(s) that can produce it, and check at least one of
     them is a tool the scan's profile actually runs. A finding credited to
     a tool the profile never invokes is wrong however confident the prose.

  2. CLASSIFIER AGREEMENT — severity.py and remediation.py document their
     classifiers as the same contract. Checked rather than trusted: a row
     the two disagree about is graded by one set of rules and remediated by
     another.

  3. FIELD SIGNATURE — a row's declared finding_type must still fit the
     columns it carries: nothing may populate a field that summary.py
     declares inapplicable for that type, and a type's own identity field
     (a `cve` without a cve_id) may not be missing. This is the check that
     a future shared column has to get past. `reference` was added for
     nikto/ZAP/wpscan and silently became true of every row; the next
     column will too, and this check is what notices when it lands on a
     finding type that has no business carrying it.

What check 1 can and cannot prove
---------------------------------
The database stores scans and findings — it does NOT store which tools ran
for a given scan (tool_results lives in memory for the duration of a run and
reaches the reports, not the schema). So the cross-reference is against the
set of tools the scan's PROFILE runs, which is the honest strongest
available answer to "could this tool have produced this row". It catches the
whole class the smoke_test8 §4.2 bug belongs to — a tool that does not run
in this profile at all — and it does not catch a tool that is wired into the
profile but was skipped, failed, or never reached on that particular run.
Stated here so no reader over-reads a clean sweep.
"""

from modules.enrichment.remediation import finding_kind as remediation_kind
from modules.enrichment.severity import finding_kind as severity_kind
from modules.reporting.summary import FINDING_TYPE_TOOL, _NOT_APPLICABLE, _enrich

# --- Who can produce what -------------------------------------------------
# finding_type -> the tool(s) that can actually raise it. Tool names are the
# ones modules/profiles/_common.py:GLOBAL_AVAILABLE_TOOLS uses, plus two
# producers that are not subprocess tools and therefore are not in that set:
#
#   header_check  modules/web/header_check.py (a `requests` call)
#   nvd           modules/enrichment/cve_lookup.py (an NVD REST call)
#
# This is deliberately about the PRODUCER, not about what the finding is
# advice to run next: wordpress_fingerprinted is raised by gobuster hitting a
# /wp-* marker path and is the trigger that makes deepscan run wpscan later.
# Crediting it to wpscan (which is what FINDING_TYPE_TOOL did until this
# pass) misattributes a gobuster finding, and does so in webaudit, where
# wpscan never runs at all.
FINDING_TYPE_PRODUCERS = {
    "banner": {"banner_grab"},
    "cve": {"nvd"},
    "discovered_path": {"gobuster", "dirb"},
    "fingerprint_header": {"header_check"},
    "missing_security_header": {"header_check"},
    "nikto_finding": {"nikto"},
    "nmap_script": {"nmap"},
    "nuclei_finding": {"nuclei"},
    "open_port": {"nmap"},
    "service_version": {"nmap"},
    "smb_share": {"enum4linux"},
    "smb_user": {"enum4linux"},
    "sqlmap_finding": {"sqlmap"},
    "sslyze_finding": {"sslyze"},
    "technology_fingerprint": {"whatweb"},
    "weak_credentials": {"hydra"},
    "wordpress_fingerprinted": {"gobuster"},
    "wpscan_finding": {"wpscan"},
    "xss_finding": {"nuclei"},
    "zap_finding": {"zaproxy"},
}

# profile -> every producer that profile can invoke.
#
# Kept here rather than derived from each profile's _WIRED_TOOLS because
# those sets answer a different question (which of the tools PROFILES lists
# does this profile call — they carry no entry for header_check or nvd, which
# are not config-listed tools, and webaudit's omits nuclei, which it does run
# in DAST mode for the XSS pass). test_attribution's drift guard asserts
# every _WIRED_TOOLS entry appears here, so the two cannot silently diverge.
PROFILE_PRODUCERS = {
    "quickscan": {"nmap", "whatweb", "nuclei"},
    "stealthscan": {"nmap"},
    "compliance": {"nmap", "sslyze", "whatweb"},
    "webaudit": {
        "nmap", "nikto", "gobuster", "dirb", "whatweb", "sslyze",
        "banner_grab", "header_check", "nvd", "nuclei",
    },
    # deepscan runs everything with a wrapper except sslyze (compliance and
    # webaudit own the TLS audit); wpscan/sqlmap/hydra/enum4linux only fire
    # when their CONDITIONAL_TOOLS trigger is met, which is still "this
    # profile can produce it".
    "deepscan": {
        "nmap", "nikto", "gobuster", "dirb", "whatweb", "nuclei", "zaproxy",
        "banner_grab", "header_check", "nvd", "wpscan", "sqlmap", "hydra",
        "enum4linux",
    },
}

# Tools a profile wires in that never produce a findings row: DNS/subdomain/
# OSINT recon writes to the report's recon section and the log, not to the
# findings table. Excluded from the drift guard that checks every profile's
# _WIRED_TOOLS against PROFILE_PRODUCERS above.
NON_FINDING_TOOLS = {"nslookup", "subfinder", "amass", "theharvester"}

# A finding type's own identity column — the one that, missing, means the row
# cannot really be of that type. Only listed where the answer is certain:
# every `cve` row is a CVE lookup result and has a cve_id, and every
# discovered_path row came from a path sweep. Types whose identity lives in
# prose (nikto_finding, zap_finding) are not listed rather than guessed at.
REQUIRED_FIELDS = {
    "cve": ("cve_id",),
    "nikto_finding": ("description",),
    "nuclei_finding": ("description",),
    "zap_finding": ("description",),
    "sqlmap_finding": ("description",),
    "xss_finding": ("description",),
}

# Columns worth checking a signature against: the shared ones a schema
# change adds and a classifier might then trip over. Anything summary.py's
# _NOT_APPLICABLE declares inapplicable for a type must be NULL on rows of
# that type.
_SIGNATURE_FIELDS = ("cve_id", "cvss", "service", "version", "endpoint", "reference")


def _populated(value) -> bool:
    return value is not None and str(value).strip() not in ("", "None")


def producers_for(finding_type) -> set:
    """The tools that can raise `finding_type`; empty set when unmapped."""
    return set(FINDING_TYPE_PRODUCERS.get(str(finding_type or "").strip().lower(), ()))


def profile_producers(profile) -> set:
    """
    Every producer the named profile can invoke, or None when the profile is
    not one of the five real ones — historical databases carry rows written
    by ad-hoc test profiles ("webaudit-helper-test"), and the honest answer
    for those is "cannot verify", not "mismatch".
    """
    key = str(profile or "").strip().lower()
    producers = PROFILE_PRODUCERS.get(key)
    return set(producers) if producers is not None else None


def check_finding(finding: dict, profile: str) -> list:
    """
    Run all three checks against one finding row as a report would see it.

    `finding` is a findings row (or an enriched copy of one — summary._enrich
    only adds fields, so either works). Returns a list of issue dicts:

        {issue, finding_type, effective_type, detail}

    where `issue` is one of:
        tool_never_ran      the tool credited with this finding is not one
                            the profile runs
        classifier_disagree severity.py and remediation.py classify this row
                            differently
        unmapped_type       a declared finding_type with no producer mapping
                            — a new type nobody taught this module about
        field_signature     a column is populated that this finding type
                            declares inapplicable, or an identity column is
                            missing

    An empty list means the row is correctly attributed.
    """
    issues = []
    declared = str(finding.get("finding_type") or finding.get("type") or "").strip().lower()

    # Classify the row the way a REPORT does — on summary._enrich()'s output,
    # not on the raw row. This is not a detail: _enrich() fills a NULL
    # description with _describe()'s derived sentence, and the §4.2 bug fired
    # only on rows that had a description by the time the classifier saw one.
    # Checking the raw row would have missed the exact defect this module
    # exists for.
    rendered = _enrich(finding) if isinstance(finding, dict) else finding
    effective = remediation_kind(rendered)
    other = severity_kind(rendered)

    if effective != other:
        issues.append({
            "issue": "classifier_disagree",
            "finding_type": declared or None,
            "effective_type": effective,
            "detail": (f"remediation.py says '{effective}', severity.py says "
                       f"'{other}' — the two are documented as one contract"),
        })

    allowed = profile_producers(profile)
    producers = producers_for(effective)

    if not producers:
        if effective not in ("unknown", ""):
            issues.append({
                "issue": "unmapped_type",
                "finding_type": declared or None,
                "effective_type": effective,
                "detail": (f"no producer mapping for '{effective}' — add one to "
                           "FINDING_TYPE_PRODUCERS so it can be attribution-checked"),
            })
    elif allowed is not None and not (producers & allowed):
        tool = FINDING_TYPE_TOOL.get(effective, effective)
        issues.append({
            "issue": "tool_never_ran",
            "finding_type": declared or None,
            "effective_type": effective,
            "detail": (f"rendered as a '{effective}' finding (credited to {tool}), "
                       f"but the '{profile}' profile runs none of "
                       f"{sorted(producers)}"),
        })

    # Signature checks apply to a row's DECLARED type only: an untyped row
    # has made no claim about itself for a column to contradict.
    for field in (_SIGNATURE_FIELDS if declared else ()):
        if _NOT_APPLICABLE.get(field, {}).get(declared) and _populated(finding.get(field)):
            issues.append({
                "issue": "field_signature",
                "finding_type": declared,
                "effective_type": effective,
                "detail": (f"'{field}' is populated ({finding.get(field)!r}) on a "
                           f"'{declared}' row, which summary.py declares it cannot "
                           "apply to"),
            })

    for field in REQUIRED_FIELDS.get(declared, ()):
        if not _populated(finding.get(field)):
            issues.append({
                "issue": "field_signature",
                "finding_type": declared,
                "effective_type": effective,
                "detail": f"'{field}' is empty on a '{declared}' row, which requires it",
            })

    return issues


def check_scan(scan_id: int, profile: str, findings: list) -> list:
    """
    Attribution issues for one scan's findings, each stamped with the
    scan_id and the finding's row id so a sweep can point at the row.
    """
    out = []
    for finding in findings or []:
        for issue in check_finding(finding, profile):
            out.append(dict(issue, scan_id=scan_id, finding_id=finding.get("id"),
                            profile=profile))
    return out
