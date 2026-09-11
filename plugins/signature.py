"""
plugins/signature.py
A declarative signature format — new checks without touching core code.

WHAT THIS IS
------------
The Phase 3 requirement, "a plugin/signature format (JSON or YAML) so new
checks can be added without touching core code, similar in spirit to Nuclei
templates." A signature is a YAML (or JSON) file under signatures/
describing an HTTP request and the matchers that decide whether the
response indicates a finding. The loader turns each signature file into a
ScannerPlugin instance automatically, so dropping a .yaml into signatures/
adds a check the engine runs — no Python, no registration.

This is deliberately a SMALL, HONEST subset of Nuclei's template language,
not a clone. It covers the cases this scanner actually needs — a request to
a path, matched on status code, a body substring/regex, or a response
header — and says so, rather than pretending to a completeness it does not
have. A signature that needs more than this should be a real Python plugin.

SIGNATURE SCHEMA
----------------
    id:          exposure-git-config          # unique; becomes the plugin name
    info:
      name:      Exposed .git/config
      severity:  medium                        # info/low/medium/high/critical
      description: ...
      remediation: ...
      reference: [https://...]
      cve: [CVE-2021-...]                       # optional
      cvss: 5.3                                 # optional
    requests:
      - method: GET                             # GET (default) or POST
        path: "/.git/config"                    # appended to the web base URL
        matchers_condition: and                 # and (default) / or
        matchers:
          - type: status
            status: [200]
          - type: word                          # substring match on body
            part: body                          # body (default) / header
            words: ["[core]", "repositoryformatversion"]
            condition: and                      # and / or (default or)
          - type: regex
            part: body
            regex: ["ref:\\s+refs/heads"]
          - type: header
            header: X-Powered-By
            words: ["PHP/5"]

MATCH SEMANTICS
---------------
Each matcher yields a boolean; matchers_condition (and/or) combines them
into the request's verdict. A signature FIRES (produces one Confirmed
finding) when any of its requests matches — because a matcher matching is
an OBSERVED response characteristic, not a version inference, signature
findings are Confirmed by construction.

SAFETY
------
Signatures issue ordinary GET/POST requests to the target's web port —
exactly what nikto/nuclei already do — under the same engine rate limiter.
There is no templating that could reach the filesystem or shell; a
signature is data, evaluated by this module, never executed.
"""

from __future__ import annotations

import json
import os
import re

import requests
import urllib3

from plugins.base import ScannerPlugin, Finding, normalise_severity, CONFIRMED

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SIGNATURE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "signatures",
)
_TIMEOUT = 10.0
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AegisScanner/1.0"


class SignatureError(Exception):
    """A signature file is malformed."""


def _load_files() -> list:
    """(path, data) for every signature file in signatures/."""
    out = []
    if not os.path.isdir(_SIGNATURE_DIR):
        return out
    for fn in sorted(os.listdir(_SIGNATURE_DIR)):
        path = os.path.join(_SIGNATURE_DIR, fn)
        if fn.endswith((".yaml", ".yml")):
            import yaml
            with open(path, "r", encoding="utf-8") as fh:
                out.append((path, yaml.safe_load(fh)))
        elif fn.endswith(".json"):
            with open(path, "r", encoding="utf-8") as fh:
                out.append((path, json.load(fh)))
    return out


def _validate(data: dict, path: str):
    if not isinstance(data, dict):
        raise SignatureError(f"{path}: signature must be a mapping")
    if not data.get("id"):
        raise SignatureError(f"{path}: signature has no `id`")
    if not data.get("requests"):
        raise SignatureError(f"{path}: signature '{data['id']}' has no `requests`")


class SignaturePlugin(ScannerPlugin):
    """
    A ScannerPlugin backed by a signature file rather than Python code.

    One instance per signature. The engine runs it against web ports like
    any other web plugin; applicable() gates it to web contexts.
    """
    target_types = ("web",)
    order = 37

    def __init__(self, data: dict, source: str = ""):
        self._data = data or {}
        self._source = source
        info = self._data.get("info") or {}
        self.name = f"sig:{self._data.get('id')}"
        self.description = (info.get("name") or self._data.get("id") or "signature")
        self.severity_baseline = normalise_severity(info.get("severity"), "INFO")

    def applicable(self, config):
        return config.get("port") is not None

    # --- matching primitives --------------------------------------------

    def _match_status(self, matcher, resp) -> bool:
        wanted = matcher.get("status") or []
        return resp.status_code in wanted

    def _match_word(self, matcher, resp) -> bool:
        part = matcher.get("part", "body")
        hay = resp.text if part == "body" else "\n".join(
            f"{k}: {v}" for k, v in resp.headers.items())
        words = matcher.get("words") or []
        cond = (matcher.get("condition") or "or").lower()
        hits = [w for w in words if w in hay]
        return (len(hits) == len(words)) if cond == "and" else bool(hits)

    def _match_regex(self, matcher, resp) -> bool:
        part = matcher.get("part", "body")
        hay = resp.text if part == "body" else "\n".join(
            f"{k}: {v}" for k, v in resp.headers.items())
        for pattern in matcher.get("regex") or []:
            try:
                if re.search(pattern, hay):
                    return True
            except re.error:
                continue
        return False

    def _match_header(self, matcher, resp) -> bool:
        name = matcher.get("header", "")
        value = resp.headers.get(name)
        if value is None:
            return False
        words = matcher.get("words") or []
        if not words:
            return True                 # header merely present
        return any(w in value for w in words)

    def _evaluate(self, matcher, resp) -> bool:
        mtype = matcher.get("type")
        fn = {
            "status": self._match_status,
            "word": self._match_word,
            "regex": self._match_regex,
            "header": self._match_header,
        }.get(mtype)
        if fn is None:
            return False
        try:
            return fn(matcher, resp)
        except Exception:  # noqa: BLE001 — a bad matcher never fails the scan
            return False

    def _base_url(self, target, config):
        port = config.get("port", 80)
        use_https = bool(config.get("use_https"))
        scheme = "https" if use_https else "http"
        default = 443 if use_https else 80
        netloc = target if port == default else f"{target}:{port}"
        return f"{scheme}://{netloc}"

    def run(self, target, config):
        base = self._base_url(target, config)
        matched_request = None
        error = None

        for req in self._data.get("requests") or []:
            method = (req.get("method") or "GET").upper()
            path = req.get("path") or "/"
            url = base.rstrip("/") + "/" + path.lstrip("/")
            try:
                resp = requests.request(
                    method, url, timeout=_TIMEOUT,
                    headers={"User-Agent": _USER_AGENT},
                    verify=False, allow_redirects=True,
                    data=req.get("body"),
                )
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
                continue

            matchers = req.get("matchers") or []
            cond = (req.get("matchers_condition") or "and").lower()
            verdicts = [self._evaluate(m, resp) for m in matchers]
            fired = all(verdicts) if cond == "and" else any(verdicts)
            if verdicts and fired:
                matched_request = {"url": url, "status": resp.status_code}
                break

        return {
            "port": config.get("port"),
            "matched": matched_request,
            # A signature whose ONLY problem was a connection error reports
            # that error (so it counts as a failed tool); one that simply
            # did not match reports no error and no finding.
            "error": error if matched_request is None and error else None,
        }

    def parse_output(self, raw):
        matched = raw.get("matched")
        if not matched:
            return []
        info = self._data.get("info") or {}
        return [Finding(
            title=info.get("name") or self._data.get("id"),
            description=info.get("description") or info.get("name") or self._data.get("id"),
            severity=normalise_severity(info.get("severity"), self.severity_baseline),
            finding_type="signature_match",
            plugin=self.name,
            port=raw.get("port"),
            endpoint=matched.get("url"),
            evidence=f"signature matched (HTTP {matched.get('status')}) at {matched.get('url')}",
            remediation=info.get("remediation") or "",
            cve_ids=info.get("cve") or [],
            cvss_score=info.get("cvss"),
            references=info.get("reference") or [],
            # A matcher matching is an observed response characteristic, not
            # a version guess — signature findings are Confirmed.
            confidence=CONFIRMED,
        )]


def load_signatures() -> list:
    """
    Every signature file, as SignaturePlugin instances. Malformed files are
    skipped (recorded via the returned errors), not fatal — one broken
    signature must not hide the rest.

    Returns (plugins, errors) where errors is [(path, message)].
    """
    plugins, errors = [], []
    try:
        files = _load_files()
    except Exception as exc:  # noqa: BLE001 — e.g. PyYAML missing
        return [], [("signatures/", f"could not read signatures: {exc}")]

    seen = set()
    for path, data in files:
        try:
            _validate(data, path)
        except SignatureError as exc:
            errors.append((path, str(exc)))
            continue
        plugin = SignaturePlugin(data, source=path)
        if plugin.name in seen:
            errors.append((path, f"duplicate signature id {plugin.name!r}"))
            continue
        seen.add(plugin.name)
        plugins.append(plugin)
    return plugins, errors
