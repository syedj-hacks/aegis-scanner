"""
plugins/passive.py
Passive-context plugins: attack-surface discovery that contacts ONLY third
parties (certificate-transparency logs, cloud-storage namespaces, breach
databases) and never the target itself.

These carry passive=True. The safety throttle ignores them (there is no
target being probed to throttle), and the stealth/recon profiles are built
from them. The one rule the recon layer is emphatic about — a breach check
with no API key reports NOT RUN, never "clean" — lives in the underlying
module (modules/recon/leaked_creds.py); the plugin does not second-guess it.
"""

from plugins.base import ScannerPlugin, findings_from_legacy, CONFIRMED
from plugins._mappers import (
    findings_from_subdomains, findings_from_buckets, findings_from_leaks,
    score_and_remediate,
)

from modules.recon.cert_transparency import find_subdomains_crtsh
from modules.recon.subdomain import enumerate_subdomains
from modules.recon.cloud_enum_wrap import find_cloud_buckets
from modules.recon.leaked_creds import check_leaked_creds


class SubdomainPlugin(ScannerPlugin):
    name = "subdomain_enum"
    description = "Passive subdomain discovery (crt.sh CT logs + subfinder/amass)."
    target_types = ("passive",)
    severity_baseline = "INFO"
    order = 10
    passive = True

    def applicable(self, config):
        # Needs a domain. A bare company name (recon company-mode) or an IP
        # has nothing to enumerate against — reported as not-applicable, the
        # same "not run and honest about why" the recon profile insists on.
        return bool(config.get("domain") or config.get("is_domain"))

    def run(self, target, config):
        # crt.sh is the always-available source; subfinder/amass augment it
        # when installed. enumerate_subdomains() already degrades over the
        # ones that are missing, so both are called and merged by source.
        crtsh = find_subdomains_crtsh(target, target=target) or {}
        extra = enumerate_subdomains(target) or {}
        by_source = {"crtsh": crtsh.get("subdomains") or []}
        for source, names in (extra.get("by_source") or {}).items():
            by_source[source] = names
        return {"by_source": by_source, "error": crtsh.get("error")}

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_subdomains(raw.get("by_source") or {})),
            plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class CloudBucketPlugin(ScannerPlugin):
    name = "cloud_enum"
    description = "Discover publicly-readable cloud storage buckets matching the target."
    target_types = ("passive",)
    severity_baseline = "MEDIUM"
    order = 11
    passive = True

    def run(self, target, config):
        keyword = config.get("keyword") or target
        return find_cloud_buckets(keyword, target=target)

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_buckets(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED  # a publicly-readable bucket responded
        return findings


class BreachPlugin(ScannerPlugin):
    name = "hibp"
    description = "Check discovered addresses against Have I Been Pwned (needs API key)."
    target_types = ("passive",)
    severity_baseline = "HIGH"
    order = 12
    passive = True

    def applicable(self, config):
        return bool(config.get("emails"))

    def run(self, target, config):
        return check_leaked_creds(config.get("emails") or [], target=target)

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_leaks(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings
