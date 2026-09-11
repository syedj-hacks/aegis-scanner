"""
modules/enrichment/risk.py
Combined CVSS + EPSS risk scoring, and the environment-level Risk Score.

PER-FINDING RISK SCORE (0-10)
-----------------------------
CVSS measures severity (how bad if exploited); EPSS measures likelihood
(how probable exploitation is). A single actionable number needs both. The
formula, chosen to be explainable rather than clever:

    risk = cvss * (0.5 + 0.5 * epss)

- With no EPSS data the multiplier is 1.0, so risk == cvss: a finding is
  never PENALISED for the absence of EPSS data (that would silently
  down-rank everything EPSS hasn't scored, which is most CVEs).
- With EPSS present, a finding's score is scaled between half its CVSS
  (nobody's exploiting it) and its full CVSS (everybody is). So a CVSS 9.8
  with EPSS ~0 lands near 4.9 and a CVSS 6.5 with EPSS ~1 lands at 6.5 —
  the mass-exploited medium can out-rank the theoretical critical, which is
  the whole point of bringing EPSS in.

This is deliberately NOT a proprietary black box. A scanner that reorders a
team's work has to be able to say WHY, and "cvss scaled by exploit
probability" is a sentence a reader can check.

ENVIRONMENT RISK SCORE (0-100)
------------------------------
One number for the whole scanned environment, for the executive summary.
Aggregates the per-finding risk scores weighted by asset criticality, so a
critical finding on a throwaway host does not dominate a real one on the
crown-jewel asset. See environment_risk_score().
"""

from __future__ import annotations

# Asset criticality multipliers. A per-target field (see config /
# --criticality) states how important the asset is; it scales that target's
# findings in the environment roll-up. Names chosen to read plainly in a
# report ("criticality: high").
CRITICALITY_WEIGHTS = {
    "low": 0.5,
    "medium": 1.0,
    "high": 1.5,
    "critical": 2.0,
}
DEFAULT_CRITICALITY = "medium"


def combined_risk_score(cvss, epss=None) -> float | None:
    """
    Per-finding risk 0-10 from CVSS base score and optional EPSS probability.

    Returns None only when there is no CVSS at all — a finding with no
    severity number has no risk number either, and inventing one would be
    the version-string-matching false confidence Phase 3 is trying to
    reduce. Non-CVE findings therefore rank by their severity bucket
    elsewhere, not by a fabricated risk score.
    """
    if cvss is None:
        return None
    try:
        cvss = float(cvss)
    except (TypeError, ValueError):
        return None
    cvss = max(0.0, min(cvss, 10.0))

    if epss is None:
        return round(cvss, 2)
    try:
        epss = float(epss)
    except (TypeError, ValueError):
        return round(cvss, 2)
    epss = max(0.0, min(epss, 1.0))

    return round(cvss * (0.5 + 0.5 * epss), 2)


def criticality_weight(criticality) -> float:
    """Multiplier for an asset criticality label; unknown -> default."""
    return CRITICALITY_WEIGHTS.get(
        str(criticality or DEFAULT_CRITICALITY).strip().lower(),
        CRITICALITY_WEIGHTS[DEFAULT_CRITICALITY],
    )


def environment_risk_score(findings, criticality=DEFAULT_CRITICALITY) -> dict:
    """
    Roll a scan's findings up into one environment Risk Score, 0-100.

    Method, and why:
      - Each finding contributes its combined risk (0-10). Findings with no
        risk score (no CVSS) contribute a small floor based on their
        severity bucket, so a scan of only header/config findings still
        produces a non-zero, sensibly-ordered posture rather than 0.
      - The aggregate is NOT a mean (which would let one trivial finding
        drag a bad score down) and NOT a raw sum (which would make score
        depend on finding count more than severity). It is a
        severity-saturating aggregate: the worst findings dominate, and
        adding more low findings moves it a little, never past the high
        ones. Concretely: sort contributions desc, weight the k-th by
        1/(k+1), sum, scale to 0-100, then apply the asset criticality
        multiplier and clamp.

    Returns {score, band, top_contributors, criticality, weight}.
    """
    severity_floor = {"CRITICAL": 8.0, "HIGH": 6.0, "MEDIUM": 3.5,
                      "LOW": 1.0, "INFO": 0.2}

    contributions = []
    for f in findings or []:
        risk = f.get("risk_score") if isinstance(f, dict) else getattr(f, "risk_score", None)
        if risk is None:
            sev = (f.get("severity") if isinstance(f, dict)
                   else getattr(f, "severity", None)) or "LOW"
            risk = severity_floor.get(str(sev).upper(), 1.0)
        contributions.append(float(risk))

    if not contributions:
        return {"score": 0.0, "band": "None", "top_contributors": 0,
                "criticality": criticality, "weight": criticality_weight(criticality)}

    contributions.sort(reverse=True)
    # Rank-decayed sum: worst finding full weight, next half, next third...
    aggregate = sum(c / (k + 1) for k, c in enumerate(contributions))
    # A single CVSS-10 finding gives aggregate 10 -> we want that to read as
    # a high-but-not-max posture; scale so ~three criticals saturate.
    raw = 100.0 * (1.0 - 1.0 / (1.0 + aggregate / 12.0))

    weight = criticality_weight(criticality)
    score = max(0.0, min(100.0, raw * weight))

    if score >= 75:
        band = "Critical"
    elif score >= 50:
        band = "High"
    elif score >= 25:
        band = "Medium"
    elif score > 0:
        band = "Low"
    else:
        band = "None"

    return {
        "score": round(score, 1),
        "band": band,
        "top_contributors": min(len(contributions), 5),
        "criticality": criticality,
        "weight": weight,
    }
