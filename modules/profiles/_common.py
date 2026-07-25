"""
modules/profiles/_common.py
Shared helper for the profile orchestrators in this package.

Every profile used to carry its own copy of a "warn about configured tools
this profile can't run" check, each with its own hardcoded
_AVAILABLE_TOOLS set. That duplication went stale: a profile's set only
tracked wrappers *that profile* had wired in, so a tool with a real wrapper
elsewhere in the codebase (e.g. zaproxy, wired into deepscan only) was
reported as having "no wrapper module in this codebase yet" — false, and
confusing to anyone trying to tell a real gap apart from a deliberate
scope decision.

GLOBAL_AVAILABLE_TOOLS below is the actual, codebase-wide answer to "does
any wrapper exist for this tool at all". warn_unavailable_tools() checks a
configured tool against the *profile's own* wired set first, then against
this global set, so the two situations get two different, honest messages.
"""

from modules.utils.logger import log_tool_failure
from modules.utils.display import print_info, print_warning, print_error
from modules.reporting.report_txt import generate_txt_report
from modules.reporting.report_pdf import generate_pdf_report
from modules.reporting.retention import retain_reports
from modules.reporting.completion import print_report_summary
from modules.reporting.summary import build_summary

# Every tool with a real wrapper module somewhere in this codebase today,
# regardless of which profile(s) actually call it.
GLOBAL_AVAILABLE_TOOLS = {
    "nslookup", "nmap", "nikto", "gobuster", "dirb", "whatweb", "nuclei",
    "sslyze", "zaproxy", "banner_grab", "subfinder", "amass", "theharvester",
    "wpscan", "sqlmap", "hydra", "enum4linux",
}

# --- Web-parameter candidate discovery (shared by XSS fuzzing) ------------
# gobuster/dirb only brute-force *paths*, never query-string parameters, so
# nuclei's DAST XSS templates (which fuzz a parameter's value) have nothing
# to mutate against a bare discovered path. This heuristic treats any
# discovered script endpoint (.php/.asp/.aspx/.jsp/.cgi) as a candidate and
# appends common reflected-XSS parameter names to build fuzzable URLs — the
# same shape modules/web/xss_wrap.run_xss() expects. webaudit and deepscan
# both feed their gobuster/dirb output through here, so the rule lives once.
SCRIPT_EXTENSIONS = (".php", ".asp", ".aspx", ".jsp", ".cgi")
XSS_PROBE_PARAMS = ("q", "s", "search", "id", "name", "query", "keyword", "page")
_DEFAULT_MAX_XSS_CANDIDATES = 6

# Endpoint basenames that characteristically DO take a reflected
# query-string parameter, and ones that characteristically do not. Used
# only to order candidates within the existing budget — nothing is ever
# excluded on the strength of its name, so a parameterised /index.php is
# still fuzzed, just after the more promising endpoints.
_LIKELY_PARAM_ENDPOINTS = (
    "search", "query", "find", "result", "view", "show", "detail", "product",
    "item", "article", "news", "info", "profile", "user", "list", "cat",
    "category", "page", "xss", "sqli", "test", "id",
)
# Site roots and static-ish landing pages. Almost never the interesting
# target, and — before the ordering fix below — reliably the first thing
# gobuster reports.
_UNLIKELY_PARAM_ENDPOINTS = (
    "index", "home", "default", "main", "about", "contact", "404", "500",
)


def _endpoint_rank(path: str) -> int:
    """
    Sort key for a discovered endpoint: 0 = most promising, 2 = least.

    Deliberately a name-based hint and nothing more. There is no way to
    know from a path alone whether it takes a parameter, so this only
    decides what gets fuzzed *first* inside a fixed budget; it never
    decides what gets fuzzed at all.
    """
    basename = path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    if any(hint in basename for hint in _LIKELY_PARAM_ENDPOINTS):
        return 0
    if basename in _UNLIKELY_PARAM_ENDPOINTS:
        return 2
    return 1


def web_param_candidates(gobuster_results, dirb_results,
                         max_candidates: int = _DEFAULT_MAX_XSS_CANDIDATES) -> list:
    """
    Build a bounded list of fuzzable parameter URLs from discovered script
    endpoints, for the XSS pass to fuzz.

    Returns a list of (url, port) tuples, e.g.
        ("http://host:80/search.php?q=1", 80)
    capped at `max_candidates` so a target with many discovered scripts does
    not spawn an unbounded number of nuclei DAST runs. Only 2xx/3xx script
    endpoints are used (a 404/403 path is not worth fuzzing). Deduplicated.

    Endpoint coverage before parameter depth
    ----------------------------------------
    This used to iterate parameters in the inner loop and return as soon as
    the cap was hit, which meant the FIRST discovered endpoint consumed the
    entire budget: six probes against /index.php, and /xss.php never fuzzed
    at all no matter how many endpoints gobuster found. That is the
    long-standing "discovery order" issue — and it was not really about
    order, since no reordering alone would have helped while one endpoint
    could still take every slot.

    Two changes fix it, both bounded by the same budget as before:
      - parameters are iterated in the OUTER loop, so every endpoint gets
        its first parameter before any endpoint gets its second
      - endpoints are ranked by _endpoint_rank() first, so the promising
        ones are reached first when the budget is smaller than the endpoint
        count

    Nothing is excluded and no new requests are made — this is purely which
    `max_candidates` URLs get chosen.
    """
    endpoints = []
    seen_endpoints = set()

    for result in list(gobuster_results or []) + list(dirb_results or []):
        port = result.get("port")
        host = result.get("target")
        if not host:
            continue
        for entry in result.get("discovered_paths") or []:
            if entry.get("status_code") not in (200, 301, 302):
                continue
            path = entry.get("path", "")
            if not path.lower().endswith(SCRIPT_EXTENSIONS):
                continue
            key = (host, port, path)
            if key in seen_endpoints:
                continue
            seen_endpoints.add(key)
            endpoints.append(key)

    # Stable sort: equally-ranked endpoints keep their discovery order, so
    # the tool's own ordering still breaks ties.
    endpoints.sort(key=lambda e: _endpoint_rank(e[2]))

    candidates = []
    seen_urls = set()
    for param in XSS_PROBE_PARAMS:
        for host, port, path in endpoints:
            url = f"http://{host}:{port}{path}?{param}=1"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            candidates.append((url, port))
            if len(candidates) >= max_candidates:
                return candidates
    return candidates


# --- nuclei finding description ------------------------------------------
# db.py's findings table has no column for a nuclei template's `name`, so a
# name passed through the profile mappers is silently dropped at insert and
# is gone by the time a report reads the row back. The name is nonetheless
# the only short, distinct label a template match carries, and the reports
# need one: nuclei's `description` is upstream prose, and whole families of
# templates share a long identical opening sentence. The four Redis Lua
# templates matched on scan 117 (CVE-2025-46817 / -46818 / -46819 /
# -49844) all begin with the same 160 characters —
#
#   "Redis is an open source, in-memory database that persists on disk.
#    Versions 8.2.1 and below allow an authenticated user to use a
#    specially crafted Lua script to ..."
#
# — so once the report truncated the description for its at-a-glance list,
# four different remote-code-execution bugs rendered as four visually
# identical rows. They were never duplicates; they were four real findings
# the report could not tell apart.
#
# Folding the name into the front of the description puts the distinguishing
# text where it survives the database round-trip, using a column that
# already exists. Nothing is invented — both halves are nuclei's own output.
def named_description(name, description) -> str:
    """
    "<name> — <description>", the project's standard way of keeping a tool's
    short label and its long prose in the single description column.

    db.py has no column for a finding's name, so a name passed through the
    mappers is dropped at insert. Folding it onto the front of the
    description is what makes it survive the round-trip — and it is what
    keeps findings that share a long boilerplate description (the four Redis
    Lua CVEs; ZAP's per-rule prose) distinguishable in a report that
    truncates. See smoke_test7 §2.3 for what happens without it.

    Falls back to whichever half is present, and does not prepend a name the
    description already opens with (some templates and ZAP rules set the two
    to the same string, and "X — X" helps nobody).
    """
    name = str(name or "").strip()
    description = str(description or "").strip()

    if not name:
        return description
    if not description:
        return name
    if description.lower().startswith(name.lower()):
        return description
    return f"{name} — {description}"


def nuclei_description(finding: dict) -> str:
    """"<template name> — <template description>" for one nuclei match."""
    return named_description(finding.get("name"), finding.get("description"))


# nuclei's `type` field is a protocol classification, not a service name.
# "http"/"https" name the service a report should show; "tcp", "javascript",
# "dns", "network" and friends describe *how* the template ran and would be
# a lie in a Service column, so they are deliberately not mapped.
_NUCLEI_SERVICE_PROTOCOLS = {"http", "https"}


def nuclei_service(finding: dict):
    """
    The service name nuclei genuinely determined for a match, or None.

    Returns None — meaning "the tool did not determine this" — rather than
    inferring a service from the port number. Port 6379 is conventionally
    Redis, but a convention is not an observation, and a report that states
    a service should be stating what a tool actually saw. The reports label
    the None case explicitly instead of printing a bare dash.
    """
    scheme = str(finding.get("scheme") or "").strip().lower()
    if scheme in _NUCLEI_SERVICE_PROTOCOLS:
        return scheme

    protocol = str(finding.get("protocol") or "").strip().lower()
    if protocol in _NUCLEI_SERVICE_PROTOCOLS:
        return protocol
    return None


def nuclei_port(finding: dict, probed_port):
    """
    The port a nuclei finding belongs to.

    nuclei's own matched port wins over the port the wrapper was pointed
    at, because a template may pivot to a different service entirely: the
    Redis Lua templates connect to 6379 regardless of the URL they were
    launched against. Scan 117 recorded four Redis RCEs against port 80 for
    exactly this reason. Falls back to the probed port when nuclei did not
    report one.
    """
    matched = finding.get("matched_port")
    return matched if matched is not None else probed_port


def warn_unavailable_tools(target: str, tools, profile_name: str, wired_tools: set) -> None:
    """
    For every tool PROFILES[profile_name]['tools'] lists that this profile
    does not actually call (`wired_tools`), log an accurate reason why:

    - it has a wrapper elsewhere but isn't run by this profile (by design,
      e.g. zaproxy in webaudit) -> an informational note, not a warning —
      nothing is broken, it's a scope decision.
    - no wrapper exists for it anywhere yet -> a real gap, logged as a tool
      failure the same as before.

    No-op for tools == "ALL" (deepscan), which by definition wires in
    everything it lists.
    """
    if not tools or tools == "ALL":
        return

    for tool in tools:
        if tool in wired_tools:
            continue

        if tool in GLOBAL_AVAILABLE_TOOLS:
            msg = (
                f"'{tool}' has a wrapper module but is not run by the "
                f"'{profile_name}' profile (by design — see this profile's docstring)"
            )
            print_info(f"[{profile_name}] {msg}")
        else:
            msg = (
                f"'{tool}' is listed in PROFILES['{profile_name}'] but has no "
                "wrapper module in this codebase yet — skipping"
            )
            log_tool_failure(target, tool, msg)
            print_warning(f"[{profile_name}] {msg}")


def finalise_reports(target: str, profile: str, scan_id,
                     non_interactive: bool = False):
    """
    Write both reports for a finished scan, prune the history, and print
    the end-of-scan banner. Returns (txt_path, pdf_path); either may be
    None if that writer failed.

    Every profile ends the same way, so the sequence lives here once rather
    than five times. The order matters and is deliberate:

      1. generate the reports — the whole point of the run
      2. prune old ones — only ever *after* the new report is safely on
         disk, so a failure in retention can never cost the user the report
         they just waited for
      3. print the banner last, so the paths are the final thing on screen

    Only deepscan used to produce a PDF; the other four wrote a .txt and
    nothing else. They all produce both now, which is what makes the
    retention scheme's .txt/.pdf pairing meaningful for every profile
    rather than for one.

    Never raises. A profile's scan is complete and persisted by the time
    this is called, and no reporting problem should turn a successful scan
    into a failed one — each step reports its own failure and the rest
    carry on.
    """
    txt_path = generate_txt_report(scan_id)
    pdf_path = generate_pdf_report(scan_id)

    try:
        retain_reports(
            target, profile, [txt_path, pdf_path],
            scan_id=scan_id, non_interactive=non_interactive,
        )
    except Exception as exc:
        # retain_reports already swallows its own errors; this is the
        # backstop for anything that escapes it.
        print_warning(f"[{profile}] report retention step failed: {exc}")

    try:
        # quiet=True: the txt and pdf writers have each already built and
        # announced this summary. A third console line saying the same
        # thing adds nothing.
        summary = build_summary(scan_id, quiet=True)
        print_report_summary(
            target, profile, scan_id, summary,
            txt_path=txt_path, pdf_path=pdf_path,
        )
    except Exception as exc:
        print_warning(f"[{profile}] could not print the report summary: {exc}")

    return txt_path, pdf_path


def count_and_report_tool_failures(target: str, tool_results: list) -> int:
    """
    Count the tools that failed AND make every one of them visible.

    All five profiles previously computed their summary panel's
    "Tools failed" number with a bare

        sum(1 for r in tool_results if r.get("error") and not r.get("skipped"))

    which reports *how many* tools failed but never *which* or *why*. A
    scan could therefore finish showing "Tools failed: 1" with no matching
    line anywhere in scan_errors.log and nothing on screen — exactly what
    happened on scan 97 (2026-07-25), where the failing tool was nmap
    reporting zero open ports through a code path that set result['error']
    without ever logging it.

    Counting and reporting are deliberately the same function so the two
    cannot drift apart again: a failure that is counted is, by
    construction, also logged and printed. Applies to every profile rather
    than being patched into the one place the problem was noticed.

    Returns the failed-tool count, so this is a drop-in replacement for
    the sum() it supersedes.
    """
    failures = [
        r for r in (tool_results or [])
        if isinstance(r, dict) and r.get("error") and not r.get("skipped")
    ]

    for r in failures:
        tool = r.get("tool") or r.get("tool_name") or r.get("name") or "unknown tool"
        port = r.get("port")
        where = f"{tool} (port {port})" if port else str(tool)
        print_error(f"[Failed] {where}: {r.get('error')}")

    if failures:
        print_warning(
            f"[Failed] {len(failures)} tool failure(s) above — see "
            f"scan_errors.log for the full record"
        )

    return len(failures)
