"""
plugins/_mappers.py
The bridge from the existing result-to-finding mappers to the plugin layer.

Every `_findings_from_<tool>()` function in modules/profiles/ is the
live-verified answer to "what does this tool's output mean" — which fields
of a nikto line are the endpoint and which is the citation, why a wpscan
finding's severity is per-finding rather than forced to HIGH, why a ZAP
alert's URL count is folded into its description. That knowledge was
earned against real targets and is documented in place.

So the plugins REUSE those functions rather than reimplementing them. This
module is the single import point for that, for two reasons:

  1. One place to look when a mapper moves, instead of twenty plugin files
     each reaching into a profile module's privates.
  2. It makes the dependency direction explicit and one-way. plugins/
     imports from modules/; nothing in modules/ imports from plugins/.
     Without that rule the legacy profiles and the plugin engine become
     mutually dependent and neither can be changed alone.

The names are private-by-convention in their home modules. Importing them
here is deliberate: the alternative is a second copy of each mapper, and a
second copy is a second place for detection behaviour to drift — which is
precisely the failure this codebase has documented repeatedly.
"""

# Discovery / scanning layer
from modules.profiles.deepscan import (
    _findings_from_banners as findings_from_banners,
    _findings_from_cves as findings_from_cves,
    _findings_from_dirb as findings_from_dirb,
    _findings_from_enum4linux as findings_from_enum4linux,
    _findings_from_gobuster as findings_from_gobuster,
    _findings_from_headers as findings_from_headers,
    _findings_from_hydra as findings_from_hydra,
    _findings_from_nikto as findings_from_nikto,
    _findings_from_nuclei as findings_from_nuclei,
    _findings_from_sqlmap as findings_from_sqlmap,
    _findings_from_whatweb as findings_from_whatweb,
    _findings_from_wpscan as findings_from_wpscan,
    _findings_from_xss as findings_from_xss,
    _findings_from_zap as findings_from_zap,
)

# sslyze and testssl share one mapper — both emit the same
# {issue, detail} finding shape, which is why compliance.py feeds testssl
# output through the sslyze mapper too.
from modules.profiles.webaudit import (
    _findings_from_sslyze as findings_from_sslyze,
)

# Passive recon layer
from modules.profiles.recon import (
    _findings_from_buckets as findings_from_buckets,
    _findings_from_leaks as findings_from_leaks,
    _findings_from_subdomains as findings_from_subdomains,
)

from modules.enrichment.severity import score_finding
from modules.enrichment.remediation import get_remediation

__all__ = [
    "findings_from_banners", "findings_from_buckets", "findings_from_cves",
    "findings_from_dirb", "findings_from_enum4linux", "findings_from_gobuster",
    "findings_from_headers", "findings_from_hydra", "findings_from_leaks",
    "findings_from_nikto", "findings_from_nuclei", "findings_from_sqlmap",
    "findings_from_sslyze", "findings_from_subdomains",
    "findings_from_whatweb", "findings_from_wpscan", "findings_from_xss",
    "findings_from_zap", "score_and_remediate",
]


def score_and_remediate(findings: list) -> list:
    """
    Run the existing severity scorer and remediation lookup over legacy
    finding dicts — the same two-step every profile applies before insert.

    Kept here (rather than each plugin calling both) so a plugin cannot
    accidentally persist an unscored finding, which is what produces a row
    with a NULL severity that summary.py then grades LOW by default.
    """
    return [get_remediation(score_finding(f)) for f in (findings or [])]
