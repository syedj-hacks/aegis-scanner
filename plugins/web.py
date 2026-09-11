"""
plugins/web.py
Web-context plugins: the tools that need an open HTTP(S) port.

Each wraps one live-verified wrapper module and reuses that tool's
existing mapper (via plugins/_mappers.py). The engine runs these against
every web port it found open, passing the port and the http-vs-https
decision in `config` — exactly the two things the legacy profiles compute
per port before their tool loop.

`config` keys these read:
    port        int    the web port to probe
    use_https   bool   whether that port speaks TLS
    profile     str    active profile name (rate-limit lookups, wordlist)
    auth        obj    optional authenticated-scan credential
    severity    list   nuclei severity filter (from the profile)
"""

from plugins.base import ScannerPlugin, findings_from_legacy, CONFIRMED
from plugins._mappers import (
    findings_from_headers, findings_from_whatweb, findings_from_nikto,
    findings_from_gobuster, findings_from_dirb, findings_from_nuclei,
    findings_from_sslyze, findings_from_zap, findings_from_wpscan,
    score_and_remediate,
)

from modules.web.header_check import check_headers
from modules.web.whatweb_wrap import run_whatweb
from modules.web.nikto_wrap import run_nikto
from modules.web.gobuster_wrap import run_gobuster
from modules.web.dirb_wrap import run_dirb
from modules.web.nuclei_wrap import run_nuclei
from modules.web.sslyze_wrap import run_sslyze
from modules.web.testssl_wrap import run_testssl
from modules.web.zap_wrap import run_zap_baseline
from modules.web.wpscan_wrap import run_wpscan


class _WebPlugin(ScannerPlugin):
    """Shared boilerplate: pull the per-port context out of config."""
    target_types = ("web",)

    def _port(self, config):
        return config.get("port", 80)

    def _https(self, config):
        return bool(config.get("use_https"))

    def applicable(self, config):
        # A web plugin only makes sense once the engine has a web port to
        # point it at. The engine sets this per invocation; a bare host
        # scan with no open web port simply never reaches here.
        return config.get("port") is not None


class HeaderPlugin(_WebPlugin):
    name = "header_check"
    description = "Audit HTTP security headers and capture Server/X-Powered-By."
    severity_baseline = "MEDIUM"
    order = 20

    def run(self, target, config):
        return check_headers(target, port=self._port(config), use_https=self._https(config))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_headers(raw)), plugin=self.name)
        # A missing header IS observed — the response either carried it or
        # it did not. This is one of the few "Confirmed" web findings that
        # rests on no version guess.
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class WhatWebPlugin(_WebPlugin):
    name = "whatweb"
    description = "Fingerprint the web stack (server, framework, CMS, versions)."
    severity_baseline = "INFO"
    order = 21
    requires = ("whatweb",)

    def run(self, target, config):
        return run_whatweb(target, port=self._port(config), use_https=self._https(config))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_whatweb(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED  # a fingerprint is a read fact
        return findings


class NiktoPlugin(_WebPlugin):
    name = "nikto"
    description = "nikto web-server misconfiguration and known-issue scan."
    severity_baseline = "MEDIUM"
    order = 30
    requires = ("nikto",)

    def run(self, target, config):
        return run_nikto(target, port=self._port(config), use_https=self._https(config),
                         profile=config.get("profile"), auth=config.get("auth"))

    def parse_output(self, raw):
        return findings_from_legacy(
            score_and_remediate(findings_from_nikto(raw)), plugin=self.name)


class GobusterPlugin(_WebPlugin):
    name = "gobuster"
    description = "Directory/file brute-force (content discovery) with gobuster."
    severity_baseline = "LOW"
    order = 31
    requires = ("gobuster",)

    def run(self, target, config):
        return run_gobuster(target, port=self._port(config), use_https=self._https(config),
                            wordlist=config.get("gobuster_wordlist"),
                            profile=config.get("profile"), auth=config.get("auth"))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_gobuster(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED  # the path returned a real status
        return findings


class DirbPlugin(_WebPlugin):
    name = "dirb"
    description = "Supplementary directory/file brute-force with dirb."
    severity_baseline = "LOW"
    order = 32
    requires = ("dirb",)

    def run(self, target, config):
        return run_dirb(target, port=self._port(config), use_https=self._https(config),
                        wordlist=config.get("dirb_wordlist"), profile=config.get("profile"))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_dirb(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class NucleiPlugin(_WebPlugin):
    name = "nuclei"
    description = "Template-based vulnerability checks (nuclei community set)."
    severity_baseline = "MEDIUM"
    order = 33
    requires = ("nuclei",)

    def run(self, target, config):
        return run_nuclei(target, port=self._port(config), use_https=self._https(config),
                          severity=config.get("nuclei_severity"),
                          profile=config.get("profile"), auth=config.get("auth"))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_nuclei(raw)), plugin=self.name)
        # A nuclei template MATCHED — it sent a probe and the response met
        # the template's matcher. That is an observation, not a version
        # inference, so nuclei matches are Confirmed. (A template that only
        # version-matches is the exception; nuclei itself flags those as
        # info/unknown and they stay at the mapper's severity.)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class SslyzePlugin(_WebPlugin):
    name = "sslyze"
    description = "TLS configuration audit (protocols, ciphers) with sslyze."
    severity_baseline = "MEDIUM"
    order = 34
    requires = ("sslyze",)

    def applicable(self, config):
        # TLS-only. A plaintext port has no cipher suite to inventory.
        return config.get("port") is not None and self._https(config)

    def run(self, target, config):
        return run_sslyze(target, port=self._port(config))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_sslyze(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class TestsslPlugin(_WebPlugin):
    name = "testssl"
    description = "Active TLS vulnerability tests (Heartbleed, ROBOT, ...) with testssl.sh."
    severity_baseline = "MEDIUM"
    order = 35
    requires = ("testssl.sh",)

    def available(self):
        # testssl.sh ships under several binary names/paths across distros;
        # accept any of them rather than failing a present tool on a name.
        import shutil
        for candidate in ("testssl.sh", "testssl"):
            if shutil.which(candidate):
                return True, ""
        return False, "missing required tool(s): testssl.sh"

    def applicable(self, config):
        return config.get("port") is not None and self._https(config)

    def run(self, target, config):
        return run_testssl(target, port=self._port(config))

    def parse_output(self, raw):
        # testssl and sslyze share the {issue, detail} finding shape, so
        # both go through the sslyze mapper — the same reuse compliance.py
        # relies on.
        findings = findings_from_legacy(
            score_and_remediate(findings_from_sslyze(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class ZapPlugin(_WebPlugin):
    name = "zaproxy"
    description = "OWASP ZAP baseline passive scan (spider + passive rules)."
    severity_baseline = "MEDIUM"
    order = 36

    def run(self, target, config):
        return run_zap_baseline(target, port=self._port(config),
                                use_https=self._https(config), auth=config.get("auth"))

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_zap(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED
        return findings


class WpscanPlugin(_WebPlugin):
    name = "wpscan"
    description = "WordPress-specific enumeration and vulnerability checks (wpscan)."
    severity_baseline = "MEDIUM"
    order = 40
    requires = ("wpscan",)

    def applicable(self, config):
        # Only where a WordPress install was actually fingerprinted — the
        # same signal deepscan's conditional-tool gate uses. Pointing wpscan
        # at a non-WordPress host wastes a scan and produces nothing.
        return bool(config.get("wordpress_fingerprinted") or config.get("is_wordpress"))

    def run(self, target, config):
        return run_wpscan(target, port=self._port(config), use_https=self._https(config),
                          api_token=config.get("wpscan_api_token"))

    def parse_output(self, raw):
        return findings_from_legacy(
            score_and_remediate(findings_from_wpscan(raw, raw.get("port"))), plugin=self.name)
