"""
modules/reporting/risk_report.py
The executive-summary risk layer shared by every report writer.

build_summary() gives the writers the findings and severity counts. This
module adds the two things a professional report's executive summary needs
on top of that:

  environment Risk Score   one 0-100 number for the whole scanned asset,
                           from every finding's combined CVSS+EPSS risk
                           weighted by the asset's configurable criticality
                           (Phase 4). See modules/enrichment/risk.py.

  top risks in plain language   the five findings that most deserve
                           attention, each rendered as a sentence a
                           non-specialist can act on — not a CVE id and a
                           number, but "what it is, why it matters, what to
                           do". Ranked by combined risk where present, then
                           severity, so a mass-exploited medium can appear
                           above a theoretical critical (the whole reason
                           EPSS is in the pipeline).

Kept out of the individual writers so the PDF, the (future) JSON/SARIF and
the TXT report cannot disagree about the environment's risk posture — they
all read it from here.
"""

from __future__ import annotations

from modules.enrichment.risk import environment_risk_score, combined_risk_score


# Asset criticality is configurable per target. A scan can carry it on its
# findings (the engine stamps it); a report can also be asked for it
# explicitly. Absent everywhere, medium is assumed — the neutral default
# that changes no existing report.
def _finding_risk(f: dict):
    """A finding's combined risk, computing it from cvss+epss if not stored."""
    risk = f.get("risk_score")
    if risk is not None:
        return risk
    cvss = f.get("cvss") if f.get("cvss") is not None else f.get("cvss_score")
    return combined_risk_score(cvss, f.get("epss_score"))


def _plain_language(f: dict) -> str:
    """
    One plain-language sentence for a top risk.

    Deliberately avoids jargon where it can: leads with the human
    description the finding already carries, then appends the concrete
    "why it matters" signal (exploit probability, confirmed-vs-potential)
    and the first line of remediation. A reader who is not a security
    specialist should be able to act on this without a glossary.
    """
    desc = (f.get("description") or f.get("title") or "Finding").strip()
    # Keep it to one sentence's worth.
    desc = desc.split("\n")[0]
    if len(desc) > 180:
        desc = desc[:177].rstrip() + "..."

    bits = [desc]

    confidence = f.get("confidence")
    epss = f.get("epss_score")
    if epss is not None:
        pct = f" ({epss * 100:.0f}% chance of exploitation in the next 30 days)"
        bits.append(f"This is actively exploited in the wild{pct}." if epss >= 0.5
                    else f"Exploitation in the wild is currently unlikely{pct}.")
    if confidence == "Potential":
        bits.append("Flagged as potential (matched on version/banner, not yet "
                    "confirmed by active testing) — verify before prioritising.")
    elif confidence == "Confirmed":
        bits.append("Confirmed by active observation during the scan.")

    remediation = (f.get("remediation") or "").strip().split("\n")[0]
    if remediation:
        if len(remediation) > 160:
            remediation = remediation[:157].rstrip() + "..."
        bits.append(f"Recommended action: {remediation}")

    return " ".join(bits)


def top_risks(findings, limit: int = 5) -> list:
    """
    The `limit` findings that most deserve attention, each as
    {rank, severity, risk_score, title, cve_id, confidence, plain_language}.

    Ranked by combined risk (desc), then severity rank, then whether it is
    Confirmed — so the list a reader sees first is genuinely the most
    actionable, not merely the highest CVSS.
    """
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def key(f):
        risk = _finding_risk(f)
        return (
            risk if risk is not None else -1,
            severity_rank.get(str(f.get("severity", "")).upper(), 0),
            1 if f.get("confidence") == "Confirmed" else 0,
        )

    ranked = sorted(findings or [], key=key, reverse=True)
    out = []
    for i, f in enumerate(ranked[:limit], start=1):
        out.append({
            "rank": i,
            "severity": f.get("severity"),
            "risk_score": _finding_risk(f),
            "title": (f.get("description") or f.get("title") or "Finding").split("\n")[0][:120],
            "cve_id": f.get("cve_id"),
            "confidence": f.get("confidence"),
            "epss_score": f.get("epss_score"),
            "plain_language": _plain_language(f),
        })
    return out


def risk_posture(summary: dict, criticality: str = None) -> dict:
    """
    The executive-summary risk block for a scan summary.

    Returns {environment_risk: {score, band, ...}, top_risks: [...],
    criticality}. `criticality` overrides whatever the findings carry; with
    neither, medium is assumed.
    """
    findings = summary.get("findings") or []
    if criticality is None:
        for f in findings:
            if f.get("criticality"):
                criticality = f["criticality"]
                break
    criticality = criticality or "medium"

    env = environment_risk_score(findings, criticality)
    return {
        "environment_risk": env,
        "top_risks": top_risks(findings, limit=5),
        "criticality": criticality,
    }
