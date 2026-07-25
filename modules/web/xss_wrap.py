"""
modules/web/xss_wrap.py
Dedicated cross-site-scripting (XSS) scanner wrapper for Aegis Scanner (web
layer).

nikto and the general nuclei pass only catch XSS incidentally (a stray
reflected-parameter template, a version-based signature). This module makes
XSS a first-class check: it drives nuclei in DAST mode scoped to the XSS
template tag only (`nuclei -dast -tags xss`) against a specific URL that
carries a query string, so nuclei actually *fuzzes* each parameter with XSS
payloads and reports reflection rather than just fingerprinting.

Why DAST mode
-------------
nuclei's XSS coverage (~1400 templates as of v3.11) lives almost entirely
under `dast/vulnerabilities/xss/` — reflected-XSS, DOM-XSS and CSP-bypass
fuzzing templates that only run when `-dast` is set AND the target URL has
at least one parameter to mutate. Run without `-dast`, or against a bare
path with no query string, those templates never fire and the scan looks
falsely clean. This wrapper therefore refuses a URL with no `?` up front
(same contract as sqlmap_wrap for the same reason) rather than run a scan
that can only ever report nothing.

Evidence capture
----------------
Each match is turned into a finding carrying the exact payload nuclei
injected, the parameter/URL it was injected into, and a truncated snippet
of the response body showing the payload reflected back — the concrete
proof the report's Injection & Scripting section renders. nuclei's DAST
JSON gives all three directly (fuzzing_parameter, matched-at, response), so
nothing is inferred.

Same run_tool() contract as every other wrapper: never raises, always
returns a structured result dict, and propagates the skipped flag.
"""

import json
from urllib.parse import urlparse, parse_qs, unquote

from modules.utils.error_handler import run_tool
from modules.utils.logger import log_finding, log_tool_failure
from modules.utils.display import (
    print_info, print_success, print_warning, print_error,
)

# -dast     : enable the fuzzing templates — nuclei's reflected/DOM XSS
#             coverage is DAST-only and inert without this flag
# -jsonl    : one JSON object per line — the only reliably parseable format
# -silent   : suppress the banner/progress noise ahead of the JSON
# -no-color : no ANSI escapes
_NUCLEI_XSS_ARGS = ["-dast", "-tags", "xss", "-jsonl", "-silent", "-no-color"]

# Cap on the response snippet stored as exploitation evidence. Long enough
# to show the reflected payload in its surrounding markup, short enough that
# a full HTML page is never persisted into a finding.
_EVIDENCE_MAXLEN = 240

# Characters of context to keep on either side of the reflected payload when
# a window can be located inside the response body.
_EVIDENCE_CONTEXT = 60


def _split_body(raw_response: str) -> str:
    """
    Return just the body of a raw HTTP response (headers stripped).

    nuclei stores the whole response — status line, headers, blank line,
    body — in one string. The reflected payload we want as evidence is in
    the body, so the header block is dropped on the first blank-line
    separator (CRLFCRLF, falling back to LFLF).
    """
    if not raw_response:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        idx = raw_response.find(sep)
        if idx != -1:
            return raw_response[idx + len(sep):]
    return raw_response


def _payload_from_matched(matched_at: str, base_url: str, parameter: str) -> str:
    """
    Recover the exact payload nuclei injected, decoded for readability.

    nuclei reports `matched-at` as the fully-built request URL with the
    fuzzed parameter carrying the payload (percent-encoded). The payload is
    that parameter's value; parsing it back out of the query string and URL-
    decoding it gives the human-readable payload to show in the report
    (e.g. `guest'"><8842>`). Falls back to the whole matched-at URL when the
    parameter can't be isolated (DOM/position fuzzing, a malformed URL).
    """
    candidate = matched_at or base_url or ""
    if parameter:
        try:
            query = parse_qs(urlparse(candidate).query, keep_blank_values=True)
            values = query.get(parameter)
            if values:
                return unquote(values[-1])
        except (ValueError, TypeError):
            pass
    return unquote(candidate)


def _evidence_snippet(raw_response: str, payload: str) -> str:
    """
    Build a truncated response snippet proving the payload was reflected.

    Locates the injected payload (or its distinctive marker) inside the
    response body and returns a window of surrounding markup, so the report
    shows the payload landing unescaped in the page. When the payload can't
    be located verbatim, the head of the body is returned instead — still
    useful context, never the whole page.
    """
    body = _split_body(raw_response)
    if not body:
        return ""

    needle = payload or ""
    idx = body.find(needle) if needle else -1
    if idx == -1 and needle:
        # Reflected-XSS templates append a random <NNNNN>-style marker; the
        # angle-bracketed tail is what actually lands in the page, so try
        # the payload's last token before giving up on a verbatim match.
        tail = needle.split(">")[-2] if ">" in needle else needle[-12:]
        idx = body.find(tail) if tail else -1
        if idx != -1:
            needle = tail

    if idx == -1:
        snippet = body[:_EVIDENCE_MAXLEN].strip()
    else:
        start = max(0, idx - _EVIDENCE_CONTEXT)
        end = min(len(body), idx + len(needle) + _EVIDENCE_CONTEXT)
        snippet = body[start:end].strip()

    snippet = " ".join(snippet.split())  # collapse whitespace/newlines
    if len(snippet) > _EVIDENCE_MAXLEN:
        snippet = snippet[:_EVIDENCE_MAXLEN - 3].rstrip() + "..."
    return snippet


def _parse_xss_jsonl(stdout: str) -> list:
    """
    Parse nuclei's DAST -jsonl output into a list of:
        {template_id, name, severity, parameter, method, payload,
         endpoint, matched_at, evidence, reference}

    Each stdout line is an independent JSON object; a malformed line is
    skipped rather than aborting the whole parse (a truncated final line
    from a killed/timed-out process is the common case).
    """
    findings = []

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        # DAST fuzzing matches carry matcher-status True; a non-match line
        # (nuclei can emit progress-style objects) is not a finding.
        if obj.get("matcher-status") is False:
            continue

        info = obj.get("info") or {}
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        base_url = obj.get("url") or ""
        matched_at = obj.get("matched-at") or obj.get("matched_at") or base_url
        parameter = obj.get("fuzzing_parameter") or ""
        payload = _payload_from_matched(matched_at, base_url, parameter)
        evidence = _evidence_snippet(obj.get("response") or "", payload)

        findings.append({
            "template_id": obj.get("template-id") or obj.get("templateID") or "",
            "name": info.get("name") or "Cross-Site Scripting",
            "severity": info.get("severity") or "medium",
            "parameter": parameter,
            "method": obj.get("fuzzing_method") or "GET",
            "payload": payload,
            "endpoint": base_url or matched_at,
            "matched_at": matched_at,
            "evidence": evidence,
            "reference": references[0] if references else "",
        })

    return findings


def run_xss(target: str, url: str) -> dict:
    """
    Fuzz a specific URL's parameters for cross-site scripting with nuclei.

    Parameters
    ----------
    target : str  host / IP the URL belongs to (used only for logging/output
                  routing)
    url    : str  full URL including the query string to fuzz, e.g.
                  "http://target/search.php?q=1" — a URL with no query string
                  is rejected up front (nuclei's DAST XSS templates have no
                  parameter to mutate without one)

    Returns
    -------
    dict:
        target      : str
        url         : str
        vulnerable  : bool        True when nuclei confirmed at least one
                                  reflected/DOM XSS
        findings    : list[dict]  {template_id, name, severity, parameter,
                                   method, payload, endpoint, matched_at,
                                   evidence, reference}
        raw_output  : str         nuclei's stdout
        error       : str | None  human-readable failure reason, if any
        skipped     : bool

    Never raises. A missing nuclei binary, no DAST templates installed, an
    unreachable target or a URL with no query string all come back as error
    set (or vulnerable=False), never an exception.
    """
    result = {
        "tool": "nuclei-xss",
        "target": target,
        "url": url,
        "vulnerable": False,
        "findings": [],
        "raw_output": "",
        "error": None,
        "skipped": False,
    }

    if not url or "?" not in url:
        msg = "no query-string URL supplied; skipping XSS fuzzing (nothing to fuzz)"
        result["error"] = msg
        log_tool_failure(target, "nuclei-xss", msg)
        print_warning(f"[XSS] {target}: {msg}")
        return result

    command = ["nuclei", "-u", url] + _NUCLEI_XSS_ARGS
    print_info(f"[XSS] Fuzzing {url} for cross-site scripting (nuclei -dast -tags xss)")

    # run_tool() logs this call under the "nuclei" tool name (the binary),
    # inheriting nuclei's timeout/skip semantics; the wrapper's own result
    # dict is labelled "nuclei-xss" so a failure is attributed to the XSS
    # pass specifically rather than the general nuclei scan.
    tool_result = run_tool(target, "nuclei", command)
    result["raw_output"] = tool_result.get("stdout", "") or ""
    result["skipped"] = tool_result.get("skipped", False)

    if not tool_result.get("success") and not result["raw_output"].strip():
        # No partial output to salvage — a genuine failure (missing binary,
        # no templates, connection refused before the first match). nuclei
        # exits non-zero on some transport errors even with valid partial
        # output, so any JSON that reached stdout is still parsed below.
        result["error"] = tool_result.get("error") or tool_result.get("stderr") or "nuclei failed"
        print_error(f"[XSS] nuclei failed for {url} — {result['error']}")
        return result

    findings = _parse_xss_jsonl(result["raw_output"])
    result["findings"] = findings
    result["vulnerable"] = bool(findings)

    if findings:
        for f in findings:
            log_finding(target, {
                "type": "xss_finding",
                "template_id": f["template_id"],
                "severity": f["severity"],
                "parameter": f["parameter"],
                "payload": f["payload"],
            })
            print_success(
                f"[XSS] [{f['severity']}] reflected XSS in '{f['parameter']}' "
                f"({f['method']}) — payload {f['payload']}"
            )
        print_info(f"[XSS] {url} — {len(findings)} XSS finding(s)")
    else:
        print_warning(f"[XSS] {url} — fuzzing completed, no XSS confirmed")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print_error("Usage: python -m modules.web.xss_wrap <target> <url-with-query-string>")
        sys.exit(1)

    tgt = sys.argv[1]
    test_url = sys.argv[2]

    print_info(f"Running nuclei DAST XSS against {test_url}...")
    out = run_xss(tgt, test_url)
    print_info(f"Vulnerable: {out['vulnerable']}")
    for item in out["findings"]:
        print_info(f"  {item['parameter']}: {item['payload']}")
        print_info(f"    evidence: {item['evidence']}")
    print_info(f"Error: {out['error'] or 'none'}")
