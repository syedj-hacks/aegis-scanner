"""
plugins/service.py
Service-context plugins: checks that need a specific non-web service on a
known port — SMB enumeration and login-service credential testing.

These are the "conditional tools" of the legacy deepscan (config.
CONDITIONAL_TOOLS): they run only when the scan actually found the service
they target, never speculatively. The gating lives in applicable() so the
engine records a skipped-with-reason result — "no SMB port open" — rather
than the check silently not appearing.

Credential testing (hydra) sends real login attempts. It is marked
active/intrusive and a safety-conscious profile can exclude it; it is
never run against a target the profile did not select it for.
"""

from plugins.base import ScannerPlugin, findings_from_legacy, CONFIRMED
from plugins._mappers import (
    findings_from_hydra, findings_from_enum4linux, score_and_remediate,
)

from modules.scanning.hydra_wrap import run_hydra
from modules.scanning.enum4linux_wrap import run_enum4linux

# The same maps deepscan uses to decide these fire — kept in step with
# config.CONDITIONAL_TOOLS' intent.
_LOGIN_SERVICE_MAP = {
    "ssh": "ssh", "ftp": "ftp", "rdp": "rdp",
    "ms-wbt-server": "rdp", "telnet": "telnet",
}
_SMB_PORTS = {139, 445}


class Enum4linuxPlugin(ScannerPlugin):
    name = "enum4linux"
    description = "SMB/NetBIOS enumeration — shares and users via null session."
    target_types = ("service",)
    severity_baseline = "MEDIUM"
    order = 41
    requires = ("enum4linux",)

    def _smb_open(self, config):
        return any(p.get("port") in _SMB_PORTS
                   for p in (config.get("open_ports") or []))

    def applicable(self, config):
        return self._smb_open(config)

    def run(self, target, config):
        return run_enum4linux(target)

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_enum4linux(raw)), plugin=self.name)
        for finding in findings:
            finding.confidence = CONFIRMED  # a listed share/user was observed
        return findings


class HydraPlugin(ScannerPlugin):
    name = "hydra"
    description = "Targeted weak-credential test against one login service (intrusive)."
    target_types = ("service",)
    severity_baseline = "HIGH"
    order = 42
    requires = ("hydra",)

    def _login_service(self, config):
        """(hydra_service_name, port) for the first login service open, or (None, None)."""
        for svc in (config.get("services") or []):
            name = str(svc.get("service") or "").lower()
            mapped = _LOGIN_SERVICE_MAP.get(name)
            if mapped:
                return mapped, svc.get("port")
        return None, None

    def applicable(self, config):
        service, _ = self._login_service(config)
        return service is not None

    def run(self, target, config):
        service, port = self._login_service(config)
        return run_hydra(target, service, port=port)

    def parse_output(self, raw):
        findings = findings_from_legacy(
            score_and_remediate(findings_from_hydra(raw)), plugin=self.name)
        for finding in findings:
            # A credential that hydra actually logged in with is as
            # confirmed as a finding gets.
            finding.confidence = CONFIRMED
        return findings
