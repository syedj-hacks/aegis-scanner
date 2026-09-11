"""
modules/enrichment/pipeline.py
The Phase 3 enrichment pass over a scan's findings.

Given the findings a scan produced, this:

  1. Assigns each finding a CONFIDENCE (Confirmed vs Potential) from its
     type — the false-positive distinction (see validation.py).
  2. Optionally runs lightweight ACTIVE VALIDATION on version-matched web
     findings to corroborate the version claim with a live banner re-read.
  3. Attaches EPSS exploit-probability to every finding carrying a CVE, in
     ONE batched, cached FIRST.org lookup for the whole scan.
  4. Computes each finding's combined CVSS+EPSS RISK SCORE.

It works on either Finding objects (the engine) or the flat legacy dicts
(a profile could call it too), reading/writing through accessors that
handle both. It never raises and never removes a finding: enrichment can
only add data. A finding with no CVE gets no EPSS and keeps its CVSS-only
risk; a network failure leaves confidence/CVSS untouched.
"""

from __future__ import annotations

from modules.enrichment.epss import lookup_epss
from modules.enrichment.risk import combined_risk_score, environment_risk_score
from modules.enrichment.validation import (
    classify_confidence, actively_validate,
)
from modules.utils.display import print_info


def _get(f, key, default=None):
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def _set(f, key, value):
    if isinstance(f, dict):
        f[key] = value
    else:
        setattr(f, key, value)


def _cve_ids(f) -> list:
    if isinstance(f, dict):
        ids = f.get("cve_ids")
        if ids:
            return list(ids)
        single = f.get("cve_id")
        return [single] if single else []
    ids = getattr(f, "cve_ids", None)
    if ids:
        return list(ids)
    single = getattr(f, "cve_id", None)
    return [single] if single else []


def enrich_findings(findings, target: str, active_validation: bool = True) -> dict:
    """
    Enrich a scan's findings in place. Returns a summary dict
    {enriched, with_cve, with_epss, validated, environment_risk}.

    `active_validation=False` skips the live banner re-reads (for a stealth
    scan, or an offline run) but still assigns confidence and EPSS/risk from
    data already in hand — confidence and EPSS need no probe against the
    target.
    """
    findings = list(findings or [])
    if not findings:
        return {"enriched": 0, "with_cve": 0, "with_epss": 0,
                "validated": 0, "environment_risk": environment_risk_score([])}

    # 1 + 2: confidence and (optional) active validation.
    validated = 0
    for f in findings:
        # Only set confidence from type when the producing plugin has not
        # already made a stronger claim. A plugin that set Confirmed on an
        # observed behaviour is authoritative; do not downgrade it.
        current = _get(f, "confidence")
        if current != "Confirmed":
            _set(f, "confidence", classify_confidence(f))
        if active_validation:
            note = actively_validate(f, target)
            if note:
                validated += 1

    # 3: batched EPSS lookup for every CVE in the whole scan at once.
    all_cves = []
    for f in findings:
        all_cves.extend(_cve_ids(f))
    epss_map = lookup_epss(all_cves, target=target) if all_cves else {}

    with_cve = with_epss = 0
    for f in findings:
        cves = _cve_ids(f)
        if cves:
            with_cve += 1
        # A finding's EPSS is the highest among its CVEs — the most
        # exploitable CVE drives the finding's exploit likelihood.
        best_epss = None
        best_pct = None
        for cve in cves:
            entry = epss_map.get(str(cve).upper())
            if entry and (best_epss is None or entry["epss"] > best_epss):
                best_epss = entry["epss"]
                best_pct = entry.get("percentile")
        if best_epss is not None:
            with_epss += 1
            _set(f, "epss_score", best_epss)
            _set(f, "epss_percentile", best_pct)

        # 4: combined risk score.
        cvss = _get(f, "cvss_score", None)
        if cvss is None:
            cvss = _get(f, "cvss", None)   # legacy dict key
        _set(f, "risk_score", combined_risk_score(cvss, best_epss))

    env = environment_risk_score(findings, _scan_criticality(findings))

    print_info(
        f"[enrich] {len(findings)} finding(s): {with_cve} with CVE, "
        f"{with_epss} with EPSS, {validated} actively validated; "
        f"environment risk {env['score']}/100 ({env['band']})"
    )

    return {
        "enriched": len(findings),
        "with_cve": with_cve,
        "with_epss": with_epss,
        "validated": validated,
        "environment_risk": env,
    }


def _scan_criticality(findings) -> str:
    """
    The asset criticality for this scan, read off any finding that carries
    one (the engine stamps it from the per-target config). Defaults to
    medium when unset — every existing scan and caller behaves as before.
    """
    for f in findings:
        crit = _get(f, "criticality")
        if crit:
            return crit
    return "medium"
