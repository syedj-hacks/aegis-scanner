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
Two bases, in order of strength:

  PER-SCAN (preferred).  As of the scan_tools_run table, a scan records which
  tools actually ran on it (ran / skipped / failed), classified from the same
  tool_results the summary panel counts. When that record exists, check 1
  cross-references a finding's producer against the tools that actually RAN on
  that specific scan — so a finding credited to a tool the profile wires in
  but that was skipped, failed, or never reached on this run is now caught,
  which the profile basis below cannot see.

  PROFILE (fallback).  Scans written before the table existed carry no record.
  For those, the cross-reference falls back to the set of tools the scan's
  PROFILE runs — the honest strongest answer available for a historical scan.
  It catches the whole class the smoke_test8 §4.2 bug belongs to (a tool that
  does not run in this profile at all) but not the skipped/failed/never-reached
  case above.

Every issue this module raises carries a `basis` of "per-scan" or "profile" so
a reader knows which question was actually asked of a given row. No historical
scan is backfilled with a record it never captured — the fallback is the
correct answer for those, not a gap.

One producer is deliberately never per-scan-verified: `nvd`, the NVD CVE
lookup (modules/enrichment/cve_lookup.py), is an in-process REST call, not a
subprocess tool, so it never appears in tool_results and cannot be recorded as
ran/skipped/failed. A `cve` finding is therefore checked per-scan against the
tools that ran PLUS nvd-if-the-profile-does-CVE-enrichment (see
UNTRACKED_PRODUCERS), rather than being falsely flagged on every scan.
"""

from modules.enrichment.remediation import finding_kind as remediation_kind
from modules.enrichment.severity import finding_kind as severity_kind
from modules.reporting.summary import FINDING_TYPE_TOOL, _NOT_APPLICABLE, _enrich
from database.db import get_scan_tools_run

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

# tool_results records a tool under the name its wrapper stamps, which is not
# always the producer name FINDING_TYPE_PRODUCERS uses:
#   - nmap runs as two distinct steps, the port scan ("nmap") and
#     service/script detection ("nmap_service_detect"), both producer "nmap".
#   - the XSS DAST pass drives nuclei under the name "nuclei-xss" and is what
#     raises an xss_finding (producer "nuclei"); aliasing it means an
#     xss_finding is credited correctly even on a scan where only the DAST
#     nuclei invocation ran.
# Normalised when building a scan's ran-set so those findings are credited to
# the right producer whichever wrapper-named step actually ran.
_PRODUCER_ALIASES = {
    "nmap_service_detect": "nmap",
    "nuclei-xss": "nuclei",
}

# Producers that never flow through tool_results and so can never be recorded
# in scan_tools_run: nvd is an in-process NVD REST call, not a subprocess the
# profiles time and count. A per-scan check therefore cannot see nvd as "ran";
# it is instead allowed whenever the scan's profile does CVE enrichment at all
# (profile_producers includes "nvd"), which is the honest per-scan answer for
# an in-process producer. Without this, every stored `cve` row would be
# falsely flagged the moment its scan gained a tools-run record.
UNTRACKED_PRODUCERS = {"nvd"}

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


def ran_producer_set(records: list, profile: str) -> set:
    """
    The set of PRODUCERS that actually ran on a scan, derived from its
    scan_tools_run records ([{tool_name, port, outcome}, ...]).

    A producer counts as "ran" only when at least one of its records has
    outcome 'ran' (a tool that only ever failed or was skipped cannot have
    produced a finding). Wrapper tool names are normalised to producer names
    via _PRODUCER_ALIASES, and the in-process producers that never appear in
    tool_results (UNTRACKED_PRODUCERS, i.e. nvd) are added when the scan's
    profile does that enrichment — see the module docstring.
    """
    ran = {
        _PRODUCER_ALIASES.get(r["tool_name"], r["tool_name"])
        for r in (records or [])
        if r.get("outcome") == "ran"
    }
    prof = profile_producers(profile) or set()
    ran |= (prof & UNTRACKED_PRODUCERS)
    return ran


def check_finding(finding: dict, profile: str, ran_tools: set = None) -> list:
    """
    Run all three checks against one finding row as a report would see it.

    `finding` is a findings row (or an enriched copy of one — summary._enrich
    only adds fields, so either works).

    `ran_tools` is the per-scan basis for check 1: the set of producers that
    actually ran on this scan (from ran_producer_set()). Pass it to check a
    finding against what ran on its specific scan; leave it None to fall back
    to the profile-level check (the only option for a scan with no tools-run
    record). check_scan() supplies it automatically.

    Returns a list of issue dicts:

        {issue, finding_type, effective_type, detail, [basis]}

    where `issue` is one of:
        tool_never_ran      the tool credited with this finding did not run —
                            per-scan basis: it was skipped/failed/never reached
                            on this scan; profile basis: this profile never
                            runs it. The issue carries `basis` saying which.
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

    # Check 1 basis: prefer the per-scan ran-set when the caller supplied one
    # (the scan has a tools-run record), else fall back to the profile's tool
    # set. A historical scan with no record is checked exactly as before.
    if ran_tools is not None:
        allowed = ran_tools
        basis = "per-scan"
    else:
        allowed = profile_producers(profile)
        basis = "profile"
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
        if basis == "per-scan":
            detail = (f"rendered as a '{effective}' finding (credited to {tool}), "
                      f"but none of {sorted(producers)} ran on this scan — tools "
                      f"that ran: {sorted(allowed)} (per-scan tools-run record)")
        else:
            detail = (f"rendered as a '{effective}' finding (credited to {tool}), "
                      f"but the '{profile}' profile runs none of "
                      f"{sorted(producers)}")
        issues.append({
            "issue": "tool_never_ran",
            "finding_type": declared or None,
            "effective_type": effective,
            "basis": basis,
            "detail": detail,
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

    Loads the scan's tools-run record and checks check 1 against what
    actually ran on this scan when a record exists (per-scan basis), falling
    back to the profile-level check when it does not — the case for every
    scan written before scan_tools_run existed. The two are never mixed for a
    single scan: an empty record list means "no record", not "nothing ran".
    """
    records = get_scan_tools_run(scan_id)
    ran_tools = ran_producer_set(records, profile) if records else None
    out = []
    for finding in findings or []:
        for issue in check_finding(finding, profile, ran_tools=ran_tools):
            out.append(dict(issue, scan_id=scan_id, finding_id=finding.get("id"),
                            profile=profile))
    return out
