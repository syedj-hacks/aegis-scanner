# Aegis Scanner — Backend Structure (Admin Notes)

Internal map of the codebase: what calls what, what every function returns, where state lives,
and what's a known gap vs. a bug. Written for whoever picks this repo up next — read this
before modifying a module you didn't write.

---

## 1. High-level data flow

```
aegis.py (CLI)
  │
  ├─ target/--profile omitted? -> interactive prompt (_prompt_target/_prompt_profile)
  ├─ validate target (is_valid_target)
  ├─ init_db()                                   [database/db.py]
  ├─ dispatch to PROFILE_DISPATCH[args.profile]   [modules/profiles/*.py]
  │     │
  │     ├─ recon      [modules/recon/*.py]        -> dns / subdomains / osint dicts
  │     ├─ scanning    [modules/scanning/*.py]      -> open_ports / scripts / services / banners / hydra / enum4linux dicts
  │     ├─ web         [modules/web/*.py]           -> headers / nikto / gobuster / dirb / whatweb / nuclei / zap / wpscan / sqlmap / xss / sslyze dicts
  │     ├─ enrichment  [modules/enrichment/*.py]    -> cves / severity / remediation
  │     ├─ insert_findings_bulk(scan_id, findings)  [database/db.py] — called incrementally,
  │     │     per scanning phase / per port, not once at the end (see §5.7)
  │     ├─ persist_tool_run(scan_id, tool_results)  [_common.py -> db.record_scan_tools()] —
  │     │     one scan_tools_run row per (tool, port) with its ran/skipped/failed outcome
  │     └─ finalise_reports(target, profile, scan_id) [_common.py]
  │             ├─ generate_txt_report() + generate_pdf_report()  [modules/reporting/*.py]
  │             ├─ retain_reports()   [modules/reporting/retention.py] — cap the history
  │             └─ print_report_summary()  [modules/reporting/completion.py] — the banner
  │
  └─ build_summary(scan_id) -> summary_stats() -> stats.update(profile_stats) -> print_summary()
                                                    [modules/reporting/summary.py, aegis.py]
```

Every profile orchestrator (`modules/profiles/*.py`) follows the same shape: resolve its config
from `PROFILES[name]`, call the shared `warn_unavailable_tools()` helper (§2, `_common.py`) to
report any configured tool this profile doesn't wire in, call its modules in sequence (inserting
findings as they become final, not all at once), record which tools actually ran
(`persist_tool_run()`), finish through the shared `finalise_reports()`, and return
`(scan_id, report_path, stats)` — deepscan returns `(scan_id, txt_path, pdf_path, stats)`.
`stats` is `{tools_run, tools_failed, tools_skipped}`; `aegis.py` merges it into the final
summary panel because `summary_stats()` alone only knows DB-derived severity counts, never which
tools actually ran.

**All five profiles now write both a `.txt` and a `.pdf`** (via `finalise_reports()`), not just
deepscan — that is what makes retention's `.txt`/`.pdf` pairing meaningful for every profile.
deepscan's 4-tuple return shape is kept for backward compatibility, not because it is the only
profile with a PDF.

---

## 2. Shared foundation (`modules/utils/` + `modules/profiles/_common.py`)

Nothing in `modules/` should call `subprocess` or `print()` directly — it goes through here.

| File | Purpose |
|---|---|
| `error_handler.py` | `run_tool(target, tool_name, command, timeout=None)` — the **only** sanctioned way to shell out to an external CLI tool. Always returns `{success, skipped, stdout, stderr, error, duration, ...}`, never raises except on a deliberate double Ctrl+C (§7). `safe_call(func, *args, target=, label=, **kwargs)` — same contract for pure-Python calls (raw sockets, `requests`). Built on `subprocess.Popen`, not `subprocess.run`, specifically so a timeout, a skip keypress, or Ctrl+C can kill the child mid-flight instead of only being noticed after it exits on its own. |
| `logger.py` | `get_logger(target)` — one logger per target, writing to `output/<target>/scan_errors.log`. Also: `log_tool_start/success/failure/skip`, `log_finding`, `log_scan_start/end`. |
| `display.py` | All terminal output (Rich-based): `print_banner/panel/phase/info/success/warning/error`, `print_table` (now includes a Description column), `print_tree`, `scan_progress_bar`, `print_summary(target, stats, show_tool_counts=True)`. |
| `config.py` | Gitignored — `NVD_API_KEY`, `PROFILES`, `TOOL_TIMEOUTS`, `NMAP_TIMEOUTS`, `PROFILE_TIME_BUDGET_SECONDS`, `COMPULSORY_TOOLS`, `SKIP_KEY`, `CONDITIONAL_TOOLS`, `output_dir()`. Mirrored by `config.example.py` (tracked) — **keep both in sync when adding a config key**. `config.example.py` auto-loads a gitignored `.env` and ships a shared default `NVD_API_KEY` (§7). |
| `modules/profiles/_common.py` | Shared profile-layer helpers — everything five orchestrators would otherwise each carry a copy of. `GLOBAL_AVAILABLE_TOOLS` (every tool with a real wrapper anywhere in the codebase) + `warn_unavailable_tools(target, tools, profile_name, wired_tools)`; `web_param_candidates()`, `classify_tool_outcome()`, `count_and_report_tool_failures()`, `persist_tool_run()`, `finalise_reports()`, and the `nuclei_*`/`named_description()` finding-shaping helpers. See §2.1. |

### 2.1 What lives in `_common.py` and why

| Function | What it does / why it is shared |
|---|---|
| `GLOBAL_AVAILABLE_TOOLS` / `warn_unavailable_tools(target, tools, profile_name, wired_tools)` | Replaces five separate, easily-stale profile-local `_AVAILABLE_TOOLS` copies — see §5.7. Distinguishes "has a wrapper, this profile doesn't call it (by design)" from "no wrapper anywhere" (a real gap). |
| `web_param_candidates(gobuster_results, dirb_results, ...)` | gobuster/dirb brute-force *paths*, never query-string parameters, so nuclei's DAST XSS templates have nothing to mutate against a bare discovered path. This builds fuzzable `?param=` URLs from discovered script endpoints (`.php/.asp/.aspx/.jsp/.cgi`) × `XSS_PROBE_PARAMS`, capped at 6 candidates. **Candidate ordering is load-bearing**: `_endpoint_rank()` sorts likely-parameterised endpoints (`search`, `view`, `id`, `xss`, ...) ahead of site roots (`index`, `home`) — without it six probes against `/index.php` consumed the whole budget and `/xss.php` was never fuzzed. Nothing is ever *excluded* by name, only ordered. |
| `classify_tool_outcome(result)` | The single `'ran'`/`'skipped'`/`'failed'` predicate. Both the on-screen counts and the persisted `scan_tools_run` record go through it, so the database record cannot drift from the summary panel. |
| `count_and_report_tool_failures(target, tool_results)` | Counts failed tools **and** prints/logs each one. Counting and reporting are deliberately the same function so they cannot drift apart — scan 97 finished showing "Tools failed: 1" with no matching line anywhere in the log or on screen. |
| `persist_tool_run(scan_id, tool_results)` | Writes the per-scan tools-run record (one row per tool-port) from the same `tool_results` the stats panel is built from. Never raises — a scan is already complete and persisted by the time it runs. |
| `finalise_reports(target, profile, scan_id, non_interactive=False)` | The shared end-of-scan sequence, in a deliberate order: generate both reports → prune old ones (only ever *after* the new report is safely on disk) → print the banner last, so the paths are the final thing on screen. Returns `(txt_path, pdf_path)`; never raises. |
| `named_description()`, `nuclei_description()`, `nuclei_service()`, `nuclei_port()` | Finding-shaping rules that must be identical wherever a nuclei finding is persisted (quickscan, webaudit, deepscan) — including the `matched_at`-derived port, which is why a nuclei hit on `:80` is no longer filed under whichever port the loop happened to be on. |

**The one rule that matters most:** nothing in this codebase raises an uncaught exception from
a tool call. `run_tool()`/`safe_call()` catch everything and hand back a structured failure.
This is why a scan against a dead host, a missing binary, or a mid-scan Ctrl+C still completes
(or degrades to a clean partial result) instead of crashing.

---

## 3. Module-by-module map

### `modules/recon/` — Phase 3
| File | Entry point | Tool(s) | Returns |
|---|---|---|---|
| `dns.py` | `resolve_dns(target)` | `nslookup`, socket fallback | resolved IP(s) |
| `subdomain.py` | `enumerate_subdomains(target)` | `subfinder`, `amass` | discovered hostnames |
| `osint.py` | `harvest_osint(target, source="crtsh", limit=500)` | `theharvester` | OSINT hits |

### `modules/scanning/` — Phase 4
| File | Entry point | Tool(s) | Returns |
|---|---|---|---|
| `port_scanner.py` | `scan_ports(target, profile=None)` | `nmap` (profile-aware `nmap_args`) | `{open_ports: [{port, protocol, service, state}], scripts: [{port, protocol, script_id, output}], profile_used, raw_output, error, skipped}` |
| `service_detect.py` | `detect_services(target, ports)` | `nmap -sV -sC` on given ports | `{services: [{port, service, version, product}], scripts: [{port, protocol, script_id, output}], error, skipped}` — **now also runs -sC** (default NSE script set), not just -sV; see below for why |
| `banner.py` | `grab_banners(target, ports)` | raw TCP socket via `safe_call()` | `banners: [{port, banner_text}]` — wired into `deepscan`/`webaudit`, but only against ports that aren't already known web ports (an HTTP(S) server never sends an unsolicited banner, so probing it here just times out) |
| `enum4linux_wrap.py` | `run_enum4linux(target)` | `enum4linux -a` | `{shares: [{name, type, comment}], users: [{user, rid}], os_info, raw_output, error, skipped}` |
| `hydra_wrap.py` | `run_hydra(target, service, port=None, userlist=None, passlist=None)` | `hydra -L -P -t 4 -f` | `{credentials_found: [{port, service, login, password}], raw_output, error, skipped}` |

**`port_scanner.py` is now a chunked, dynamically-timed-out sweep, not a single `nmap -oX -`
call.** Key pieces:
- `_compute_nmap_timeout(nmap_args)` — picks `NMAP_TIMEOUTS['full_fast']` (19200s = 32 × 600s)
  when the args contain `-p-`, else the plain `TOOL_TIMEOUTS['nmap']` (300s).
- `_run_nmap_xml()` — runs one nmap invocation with `-oX` pointed at a real temp file (not
  stdout) and reads it back; used uniformly whether this is a single call or one chunk of many.
- For a `-p-` sweep specifically: `_split_full_range(32)` divides 1–65535 into 32 contiguous
  ranges (`_FULL_RANGE_CHUNKS`), and `scan_ports()` runs each as its own complete, independently
  timed-out nmap call, accumulating `open_ports`/`scripts` across chunks and stopping (with
  whatever was already found) the moment one chunk fails/times out/is skipped. This exists
  because **a killed nmap process does not reliably flush a partial `-oX` document** — verified
  empirically (SIGTERM/SIGINT sent at 6s/20s/90s into a live full-range sweep all produced XML
  with nothing past `<scaninfo>`) — so a chunk boundary, not "wherever the process happened to
  be," is the real recovery unit. Only `deepscan`'s bare-`-T4` discovery pass uses `-p-` now;
  `stealthscan` was redesigned onto a curated ~20-port list instead (see §4) because no quiet
  timing template could finish a real full sweep in bounded time (measured ~0.29 ports/sec at
  `-T2` against a filtered target — 60+ hours extrapolated, an architectural dead end).

**`service_detect.py` runs `-sV -sC` combined now, and this is where deepscan's nmap-script
findings come from.** `deepscan`'s own discovery sweep deliberately does NOT run `-sV`/`-sC` any
more — combining either with a 65535-port sweep is nmap's slowest possible shape, and even
chunked it routinely blew every chunk's budget and came back with zero ports (confirmed live).
`-sV -sC` is safe to add here because this call only ever targets the small set `scan_ports()`
already narrowed down to. `service_detect.py`'s own `_parse_sc_scripts()` produces the same
`{port, protocol, script_id, output}` shape `port_scanner.py`'s script parser does (independent
implementations, same data shape) — `compliance`, which passes `--script` directly to its own
`scan_ports()` call rather than through `service_detect.py`, still gets its script findings from
`port_scanner.py` as before; that path is unchanged.

### `modules/web/` — Phase 5
| File | Entry point | Tool(s) | Returns |
|---|---|---|---|
| `header_check.py` | `check_headers(target, port=80, use_https=False)` | `requests` via `safe_call()` | `missing_headers[]`, `present_headers{}`, `server_banner`, `powered_by` |
| `nikto_wrap.py` | `run_nikto(target, port=80, use_https=False)` | `nikto` | `{findings: [{description, reference, test_id, path}], base_url, server, product, version, error, skipped}` — nikto exits 0 even on connection failure, so failure is detected from report text. `test_id`/`path` are nikto's own per-finding id and URI (both `""` on tests that print neither, e.g. `"Apache/2.4.25 appears to be outdated"` has no URI); `server`/`product`/`version` come from its `Server:` banner line, with `"No banner retrieved"` treated as no banner |
| `gobuster_wrap.py` | `run_gobuster(target, port=80, use_https=False, wordlist=None)` | `gobuster dir` | `{discovered_paths: [{path, status_code, size, redirect, url}], base_url, wordpress_fingerprinted: bool, error, skipped}`; auto-retries with `--exclude-length` on SPA wildcard responses. `size`/`redirect` are gobuster's own `[Size: n]` / `[--> target]` and are `None` where it printed neither — a 0-byte page and an unreported size are different facts |
| `dirb_wrap.py` | `run_dirb(target, port=80, use_https=False, wordlist=None)` | `dirb -S -w -r` | `{discovered_paths: [{path, status_code, size, redirect, url}], raw_output, error, skipped}` — see below for the wordlist/failure-detection fix. `size` is dirb's own `SIZE:` (captured by the regex since the module was written, previously discarded when the dict was built); `redirect` is always `None` — dirb does not report redirect targets |
| `whatweb_wrap.py` | `run_whatweb(target, port=80, use_https=False)` | `whatweb -a 3` | `{technologies: [{name, value}], cms_detected: str\|None, raw_output, error, skipped}` — `cms_detected` still has no consumer (§5.6) |
| `nuclei_wrap.py` | `run_nuclei(target, port=80, use_https=False, severity=None)` | `nuclei -jsonl -silent` | `{findings: [{template_id, name, severity, description, matched_at, reference, cve_id}], raw_output, error, skipped}` — `cve_id` (new) is comma-joined from `info.classification.cve-id`, threaded through by every profile that persists nuclei findings |
| `sqlmap_wrap.py` | `run_sqlmap(target, url)` | `sqlmap --batch --random-agent --level 1 --risk 1 --banner --current-db --dbs` | `{injectable: bool, findings: [{parameter, method, type, title, payload, techniques}], metadata: {dbms, banner, current_db, databases}, raw_output, error, skipped}` — see below |
| `xss_wrap.py` | `run_xss(target, url)` | `nuclei -dast -tags xss -jsonl -silent` | `{vulnerable: bool, findings: [{template_id, name, severity, parameter, method, payload, endpoint, matched_at, evidence, reference}], raw_output, error, skipped}` — records itself in `tool_results` under the name **`nuclei-xss`**. Rejects a URL with no `?` up front (see below) |
| `sslyze_wrap.py` | `run_sslyze(target, port=443)` | `sslyze --json_out=<tmpfile>` | `{findings: [{issue, detail}], raw_output, error, skipped}` |
| `wpscan_wrap.py` | `run_wpscan(target, port=80, use_https=False, api_token=None)` | `wpscan --format json` | `{findings: [{component, title, reference}], raw_output, error, skipped}` |
| `zap_wrap.py` | `run_zap_baseline(target, port=80, use_https=False)` | ZAP daemon + `zapv2` REST client (see below) | `{findings: [{rule_id, name, status, severity, confidence, description, solution, reference, url, param, evidence, attack, method, cwe, url_count}], raw_output, error, skipped}` — all ZAP's own fields; `attack` is `""` on every alert of a passive baseline scan, `param`/`evidence` on the rules that report neither. `cwe` drops ZAP's `-1`/`0` "not applicable" sentinel rather than rendering `CWE--1`. ZAP emits one alert per matching URL, so alerts are collapsed per `(pluginId, alert)` with `url_count` recording how many URLs matched |

**`xss_wrap.py` — XSS is a first-class check, not an incidental one.** nikto and the general
nuclei pass only catch XSS by accident (a stray reflected-parameter template, a version
signature). nuclei's real XSS coverage (~1400 templates) lives under
`dast/vulnerabilities/xss/` and only runs when `-dast` is set **and** the URL carries at least
one parameter to mutate — run without either, those templates never fire and the scan looks
falsely clean. So this module refuses a URL with no query string up front (same contract as
`sqlmap_wrap.py`, for the same reason) rather than running a scan that can only ever report
nothing. Each match carries the exact payload nuclei injected, the parameter it went into, and a
truncated snippet of the response body showing it reflected back — all three come straight from
nuclei's DAST JSON (`fuzzing_parameter`, `matched-at`, `response`), nothing is inferred. That
evidence is what the reports' **Injection & Scripting Vulnerabilities** section renders.
`webaudit` and `deepscan` both feed their gobuster/dirb output through
`_common.web_param_candidates()` (§2.1) to build the URLs.

**`sqlmap_wrap.py` does read-only enumeration on a confirmed injection.** On top of the
confirmation pass it requests three safe metadata enumerations — `--banner --current-db --dbs` —
so a confirmed finding carries real extracted evidence (DBMS engine/version, the current database
name, the database list, and the technique: boolean-blind / error-based / time-based / UNION)
instead of a bare `vulnerable: true`. It deliberately never requests `--dump`, `--os-shell`,
`--sql-shell`, `--file-read`/`--file-write` or any other exfiltration/write/execution action:
metadata only. `--random-agent` is there so a static UA doesn't get WAF-blocked mid-confirmation.

**`dirb_wrap.py` — root-caused and fixed this pass (previously only guessed at).** dirb is
single-threaded, one connection per request, and a full `common.txt` (4614 words) run reliably
died with `"(!) FATAL: Too many errors connecting to host"` at the same word count
(1711/4614) whether or not a flood-delay was added — that rules out simple rate-limiting and
points at a target-side cumulative connection-count threshold instead, which dirb has no flag to
work around. Fix: `_DEFAULT_WORDLISTS` now tries dirb's own bundled `small.txt` (959 words)
first, falling back to `common.txt` only if `small.txt` is missing (`gobuster` is unaffected —
its concurrency finishes fast enough that this threshold was never observed to trip, so it still
uses the full list). A second, compounding bug: dirb writes its actual abort reason to **stdout**,
not stderr, so the old failure branch (stderr-only) fell through to a generic "exit 255" with no
real cause logged — `_extract_fatal_reason()` now pulls dirb's `"(!) ..."` line out of stdout as
a fallback. `dirb_wrap.py` also gained the same wildcard/soft-404 flood guard `gobuster_wrap.py`
already had (`_looks_like_wildcard_flood()`).

**`zap_wrap.py` was rewritten.** apt's `zaproxy` package on Kali ships the ZAP daemon/GUI
(`zap.sh`) but not `zap-baseline.py` (that script ships with ZAP's official Docker image, not a
bare apt install, and assumes ZAP's own bundled directory layout). This module now starts the
ZAP daemon itself (`zap.sh -daemon`, autoupdate disabled — a startup auto-update that gets
killed mid-download corrupts the on-disk add-on and breaks every subsequent start), drives it
over its REST API via the official `zapv2` client (`requirements.txt`: spider the target, wait
for the passive scanner to drain, pull alerts via `zap.core.alerts()`, shut the daemon down), and
does **not** go through `run_tool()` — that models "one subprocess, wait for it to exit," but
this needs a long-lived daemon talked to over HTTP. It follows the same never-raises contract by
hand (including its own `KeyboardInterrupt` handling matching `error_handler.py`'s). Findings now
derive from ZAP's own Risk rating (High/Medium/Low/Informational → this project's severity
scale) instead of parsing zap-baseline.py's plain-text summary lines. ZAP's "Passive scanner
rules" add-on (`pscanrules` — the real ~60-rule detection set; without it ZAP scans complete
cleanly but silently return 0 findings, forever) isn't installed by default on a fresh apt
`zaproxy` package — `install.sh` now bootstraps it once, automatically, on a fresh `~/.ZAP`
profile during install, so this shouldn't come up in normal use. See §5 for the recovery
procedure if it ever does.

### `modules/enrichment/` — Phase 6
| File | Entry point | Returns |
|---|---|---|
| `cve_lookup.py` | `lookup_cves(product, version=None, target="nvd", limit=10)` and **`lookup_cves_from_banner(banner, target="nvd", limit=10)`** (new — splits a raw `Server:`/`X-Powered-By` header like `"Apache/2.4.7 (Ubuntu)"` into product/version first, dropping a non-version-looking second half rather than sending it to NVD as a bogus filter) | `cves: [{cve_id, product, version, description, cvss_score, cvss_severity, cvss_version, published_date, references[]}]`. Both now run a **product-disambiguation pass** (`_PRODUCT_ALIASES`: apache, nginx, iis, tomcat, openssh, vsftpd, proftpd, mysql, postgresql, lighttpd) that maps a bare vendor token to a more specific NVD keyword phrase *and* a CPE-product allowlist, then drops any CVE hit whose own CPE configuration data names a different product — found live: a bare `"Apache"` banner was returning an Apache **Groovy** RCE as a top match, same vendor, wrong product entirely. A CVE with no CPE data at all is kept (can't verify, don't assume wrong), only dropped when NVD *does* attach CPE data and none of it matches. |
| `severity.py` | `score_finding(finding)` | shallow copy + `severity` (CRITICAL/HIGH/MEDIUM/LOW), `severity_source`, `cvss`. Keyword matching (`_match_keywords`) now uses a cached word-boundary regex instead of plain substring containment — the old check let short real keywords match inside unrelated words (`"rce"` matched inside `"brute-*f*orce*"`, silently inflating a routine nikto brute-force finding to CRITICAL). |
| `remediation.py` | `get_remediation(finding)` | copy + `remediation` string, branches per finding kind (`nmap_script`, `nuclei_finding`, `zap_finding`, `sslyze_finding`, `wpscan_finding`, `sqlmap_finding`, `weak_credentials`, `smb_share`/`smb_user`, `technology_fingerprint`, ...). |

### `modules/reporting/` — Phase 7
| File | Entry point | Notes |
|---|---|---|
| `summary.py` | `build_summary(scan_id, top_n=10, quiet=False)` → `{scan_id, scan_metadata, total_findings, by_severity, findings, top_findings, error}`, worst-first. `summary_stats()` adapts it to `display.print_summary()`'s shape — only DB-derived severity counts; `aegis.py` layers the profile's own real tool-run stats on top afterward (§1). | The shared vocabulary both report writers read from, so the TXT and the PDF cannot describe the same row differently — see §3.2. |
| `report_txt.py` | `generate_txt_report(scan_id, output_path=None)` | Blocks: header → scope note → severity summary → top findings → **Injection & Scripting Vulnerabilities** → detail. `preview_report()` calls `print_summary(..., show_tool_counts=False)` — see `display.py` below for why. |
| `report_pdf.py` | `generate_pdf_report(scan_id, output_path=None)` | WeasyPrint, imported lazily. All interpolated values are HTML-escaped. Same block order as the TXT report, plus an inline **severity-distribution donut SVG** on the cover, generated from the same `by_severity` counts the summary block prints (no chart library, no external asset — the CSS/SVG is written inline so the PDF has no network dependency). |
| `retention.py` | `retain_reports(target, profile, paths, scan_id=, non_interactive=)`, `report_filename()`, `prune_reports()`, `list_stored_reports()` | Capped, indexed report history — see §3.3. |
| `completion.py` | `print_report_summary(target, profile, scan_id, summary, txt_path=, pdf_path=)` | The `+- REPORT GENERATED -+` block printed last: severity line, `notable_types()` (e.g. "2 CVEs, 7 ZAP alerts, 13 discovered paths"), the profile's scope note, and both file paths as OSC 8 terminal hyperlinks over a `file://` URI. Terminals without OSC 8 support just show the plain path, which is why the full path is always written out rather than hidden behind link text. |
| `attribution.py` | `check_finding(finding, profile, ran_tools=None)`, `check_scan(scan_id, profile, findings)` | Attribution correctness for stored findings — see §3.4. Not called during a scan; it is the audit layer `tests/db_sweep.py` runs. |

Both writers return the path or `None` — they never raise.

### 3.2 `summary.py` is the shared report vocabulary

Everything both writers need to *say* about a finding lives here once, because the two files
rendering the same row differently is a defect class this project has actually shipped:

- `field_display(finding, field)` / `service_display()` / `cvss_display()` — how a field is
  rendered when it is empty. A blank cell is ambiguous ("nothing found" vs "never looked"), so
  a field that is inapplicable *by nature* for a finding type prints a qualifier
  (`_NOT_APPLICABLE`, e.g. a `sslyze_finding` has no CVE because it is a TLS-configuration
  finding), and one that is applicable-but-unpopulated is reported as a genuine gap naming the
  tool that would have filled it (`FINDING_TYPE_TOOL`, e.g. "not determined by nuclei").
- `FINDING_TYPE_TOOL` maps a finding type to the tool that **produced** it, not the tool it is
  advice to run next: `wordpress_fingerprinted` is credited to **gobuster** (which hits the
  `/wp-*` marker path), not wpscan (which that flag *triggers*, and which `webaudit` never runs
  at all).
- `finding_identifier()` / `distinct_identifiers()` — falls back to a truncated `description`
  when both `service` and `cve_id` are empty (a nuclei/CVE-shaped finding with no service used
  to render as a bare `"unknown"`), and disambiguates identifiers that share a long common
  prefix so two different findings never render as the same line.
- `deduplicate_findings()` — collapses rows identical across
  `(finding_type, port, cve_id, severity, description)` at render time. A safety net only: the
  duplicate CVE path was fixed at *collection* time in `deepscan` (§5.8), which is where a
  duplicate should be stopped.
- `injection_findings()` + `INJECTION_FINDING_TYPES` — the single definition of what counts as
  an injection finding (`sqlmap_finding`, `xss_finding`), read by both writers.
- `profile_scope_note(profile, labelled=False)` — one source of truth for a profile's scope
  statement, read by the TXT report, the PDF cover and the CLI banner. Currently only `webaudit`
  has one: it runs nuclei in DAST/XSS mode but **not** the severity template pass, so a
  quickscan or deepscan of the same host can surface findings a webaudit report does not. Saying
  "webaudit does not run nuclei" would have been false; saying nothing left a real gap
  unexplained.

### 3.3 `retention.py` — capped, indexed report history

Both writers used to write one fixed filename per target (`report.txt` / `report.pdf`), so every
scan silently overwrote the previous one. That destroyed evidence once already (scan 112's report
was gone by the time anyone looked, overwritten by scan 116 an hour later), with nothing warning
and nothing recording it. Unlimited accumulation is not the answer either, so:

```
output/<target>/report_<profile>_<target>_<scan_id>.txt
output/<target>/report_<profile>_<target>_<scan_id>.pdf
```

- The profile is in the filename deliberately: a directory listing says what each report **is**
  without opening it.
- Retention is **per profile+target**, `_DEFAULT_KEEP = 5`. A burst of quickscans therefore
  cannot evict the one deepscan report of that host — which a flat per-target cap would do, and
  which is exactly the evidence loss this module exists to prevent.
- The `.txt` and `.pdf` of one scan are listed, counted and deleted as a unit — half a report is
  not a report.
- Deletion is never silent and never automatic in an interactive session: the run asks what to
  drop. A non-TTY run (or `--non-interactive`) drops the oldest and logs that it did — hanging a
  scripted run on stdin is worse than the pruning.
- Pruning always happens *after* the new report is on disk, and a failure here can never cost the
  report the user just waited for.

### 3.4 `attribution.py` — "did the tool this finding is credited to actually run?"

Added after a defect that 317 unit assertions and a whole-database render sweep both passed
straight through: adding the `reference` column made every SQLite row satisfy a classifier branch
keyed on that column merely being *present*, so a stealthscan open-port finding was rendered with
nikto's remediation — naming a tool that never ran. A human reading one report caught it. The
sweep that missed it checks for crashes, ambiguous cells and duplicate lines; none of those is
the question "is this finding attributed to the right tool", which nobody's code was asking.

Three checks over every row of every scan:

1. **Tool plausibility** — classify the row exactly as a report will (`remediation.finding_kind()`,
   the same call the renderer makes), map that kind to the tool(s) that can produce it
   (`FINDING_TYPE_PRODUCERS`), and check at least one of them actually ran.
2. **Classifier agreement** — `severity.py` and `remediation.py` document their classifiers as the
   same contract; this checks it rather than trusting it. A row the two disagree about is graded
   by one set of rules and remediated by another.
3. **Field signature** — a declared `finding_type` must still fit the columns the row carries:
   nothing may populate a field `summary._NOT_APPLICABLE` declares inapplicable for that type, and
   a type's own identity field may not be missing (a `cve` with no `cve_id`). **This is the check
   the next shared column has to get past.**

Check 1 answers on one of two bases, and every issue it raises is stamped with which:

- **`per-scan`** (preferred) — the `scan_tools_run` record says which tools actually ran on *that*
  scan, so a finding credited to a tool the profile wires in but that was **skipped, failed, or
  never reached on this run** is caught.
- **`profile`** (fallback) — scans written before the table existed carry no record; for those the
  cross-reference falls back to the set of tools the scan's `PROFILE` runs. That is the honest
  strongest answer available for a historical scan, and it still catches the whole class the
  `reference`-column bug belonged to. **No historical scan is backfilled with a record it never
  captured.**

Two normalisation rules keep this honest rather than noisy: `_PRODUCER_ALIASES` maps the wrapper
names `nmap_service_detect` → `nmap` and `nuclei-xss` → `nuclei`, and `UNTRACKED_PRODUCERS`
grants `nvd` per-scan whenever the profile does CVE enrichment at all — the NVD lookup is an
in-process REST call, never a subprocess in `tool_results`, so it can never be recorded as "ran"
and every stored `cve` row would otherwise be flagged the moment its scan gained a record.

`display.py:print_summary(target, stats, show_tool_counts=True)` gained `show_tool_counts` —
`report_txt.py`'s mid-run preview panel used to show a permanently-stale "Tools run: 0" (the
real stats dict doesn't exist yet at that point in a profile run), so the preview now passes
`show_tool_counts=False` and drops the line entirely rather than showing a misleading number;
the real final SCAN SUMMARY panel that follows immediately after has the correct counts.

### `modules/profiles/` — Phase 8 (orchestration layer)
See §4 for per-profile behavior. All five now share `modules/profiles/_common.py`'s
`warn_unavailable_tools()` (§2) instead of a hand-rolled per-profile copy, and all five persist
findings incrementally (per phase/port) rather than in one batch at the end (§5.7).

- **`quickscan.py`** — **now actually runs `whatweb` + `nuclei`** against the first detected web
  port (nuclei scoped to `nuclei_severity: ["critical", "high"]` to stay fast). This closes what
  used to be quickscan's biggest gap: `PROFILES['quickscan']['tools']` listed `whatweb`/`nuclei`
  since early on, but nothing ever called them, so quickscan and stealthscan used to come back
  near-identical.
- **`stealth.py`** — unchanged in scope (nslookup + nmap only), migrated onto the shared
  `warn_unavailable_tools()` helper. See §4 for its port-list redesign.
- **`webaudit.py`** — per-port loop bounded by `PROFILE_TIME_BUDGET_SECONDS['webaudit']` (30
  min); `banner_grab` now skips ports already known to be web ports (they don't send an
  unsolicited banner). Runs the **XSS pass** (`xss_wrap.run_xss()` over
  `_common.web_param_candidates()`), which is nuclei in DAST mode — so `webaudit` *does* invoke
  nuclei, but only for XSS fuzzing and never for the severity template pass. That distinction is
  why it carries a scope note (§3.2), and why its `_WIRED_TOOLS` set (which answers "which
  config-listed tools does this profile call") omits nuclei while
  `attribution.PROFILE_PRODUCERS['webaudit']` includes it. `zaproxy` still deliberately not
  called (too heavy for this profile's scope).
- **`deepscan.py`** — web-module per-port loop bounded by `PROFILE_TIME_BUDGET_SECONDS['deepscan']`
  (60 min; the separate full-port discovery sweep has its own, much larger `NMAP_TIMEOUTS`
  budget). All four `CONDITIONAL_TOOLS` dispatch for real, and a condition that ISN'T met is now
  logged explicitly (`condition '<flag>' not met — skipping <tool>`) instead of silently doing
  nothing. Runs the same XSS pass as `webaudit` on top of its full nuclei template pass.
  `sslyze` still deliberately not called (reserved for compliance/webaudit).
- **`compliance.py`** — **now also runs `whatweb`** alongside `sslyze`, both targeting whichever
  port(s) `ssl-enum-ciphers` identified as TLS-speaking (443 fallback if open). Persists per-TLS-
  port rather than batched across all of them.

### `database/db.py`
SQLite at `database/aegis.db`. Three tables:

```sql
scans (id, target, timestamp, profile)
findings (id, scan_id, port, service, version, cve_id, cvss, severity,
          description, remediation, finding_type, product,
          parameter, payload, evidence, endpoint, reference)
scan_tools_run (id, scan_id, tool_name, port, outcome)   -- outcome: ran|skipped|failed
```

`init_db()` runs an idempotent migration (`PRAGMA table_info(findings)` → `ALTER TABLE ... ADD
COLUMN` for any of `description`/`remediation`/`finding_type`/`product`/`parameter`/`payload`/
`evidence`/`endpoint`/`reference` not already present) plus a `CREATE TABLE IF NOT EXISTS` for
`scan_tools_run` — safe to call on every process start. `insert_finding()` derives `finding_type`
from `finding.get("type") or finding.get("finding_type")`, defaulting to `"cve"` when a `cve_id`
is present and no type was given.

Column groups and why they exist:
- `parameter`/`payload`/`evidence`/`endpoint` — the injection & scripting evidence (the exact
  payload sent, what it was sent against, and a response snippet proving it). Every other finding
  shape leaves these NULL; only the report's injection section reads them.
- `reference` — a *citation* for a finding rather than evidence of it (nikto's `See:` URL, ZAP's
  `reference`, wpscan's advisory link). All three were parsed and then silently dropped at insert
  because there was no column to put them in. Its own column rather than being folded into
  `evidence`/`remediation` — and note that adding it is what caused the classifier regression
  §3.4 exists to catch.

**`scan_tools_run` is a separate table, not a JSON blob on `scans`** — matching this schema's
existing convention (findings hang off `scans` by `scan_id`), and because a tool that runs
per-port emits one row per `(tool, port)`, a shape a relational table holds naturally and a JSON
summary would flatten. It is collected **going forward only**: scans predating the table simply
have no rows, and `attribution.py` falls back to the profile-level check for those. No historical
backfill — the data was never captured, so it is not invented.

CRUD: `init_db()`, `insert_scan(target, profile) -> scan_id`, `insert_finding(scan_id, finding)`,
`insert_findings_bulk(scan_id, findings)`, `record_scan_tools(scan_id, records)`,
`get_scan_tools_run(scan_id)` (defensive against the table being absent on a pre-migration
database), `get_scan_history(target=None)`, `get_findings_for_scan(scan_id)`,
`get_latest_scan(target)`.

Concurrency: each insert function opens its own fresh connection and commits+closes within the
call — no shared/global connection. SQLite's 5s default busy-timeout gives concurrent writers
serialization room; confirmed live (a tooling-caused mid-scan kill left a clean scan row with
zero orphaned finding rows, no corruption to concurrently-completing runs).

### `aegis.py` — CLI entry point
`build_parser()` (argparse), `is_valid_target()` (RFC-1123 hostname regex + `ipaddress`
fallback), `PROFILE_DISPATCH` (name → orchestrator function), `_normalize_result()` (flattens
the 3-tuple/4-tuple return shapes from profiles — detects the trailing `stats` dict rather than
assuming a fixed length), `main()`.

**Target and `--profile` are optional.** If the target is omitted entirely (bare
`python3 aegis.py`), the CLI drops into interactive mode via `_prompt_target()`/
`_prompt_profile()`. If a target *is* supplied but `--profile` isn't, it silently defaults to
`quickscan`, no menu — unchanged, fully backward compatible.

Flags: `[target] [--profile ...] [-v/--verbose] [--non-interactive] [--version]`.
**`--non-interactive`** never prompts — when the stored-report cap (§3.3) is reached it deletes
the oldest report automatically instead of asking. It is implied whenever stdin/stdout is not a
terminal, so piped runs, cron and the smoke-test harness get that behavior without passing it.

The "Scan Configuration" panel now also explains the skip keybind (`config.SKIP_KEY`) and the
Ctrl+C double-tap-to-abort behavior (see §7) before the scan starts. After the scan, `main()`
does `stats = summary_stats(summary); stats.update(profile_stats)` — the orchestrator's own
real-time tool counts override `summary_stats()`'s DB-only placeholders, which is what actually
makes the final "Tools run/failed/skipped" line correct.

---

## 4. Profile behavior cheat sheet

Every profile writes **both** a TXT and a PDF report (§1), named per scan and capped per
profile+target (§3.3).

| Profile | Tools it actually runs | Ports scanned | 2nd nmap `-sV -sC` pass? | CVE/severity enrichment |
|---|---|---|---|---|
| `quickscan` | nslookup, nmap, nmap -sV -sC, **whatweb + nuclei on the first open web port** | top ports (`-T4 -F`) | yes | web findings scored; raw port/service persisted unscored (LOW default) |
| `stealthscan` | nslookup, nmap | curated ~20-port list (`-T2 -Pn --randomize-hosts`) | **no** (deliberately, to avoid doubling probe traffic) | no |
| `webaudit` | nslookup, nmap, header check, nikto, gobuster, dirb, whatweb, banner grab (non-web ports only), sslyze (if https), **XSS pass (nuclei `-dast -tags xss`)** | 80/443/8080/8443 only | no | web findings + nmap-script findings + `Server` banner CVE lookup |
| `deepscan` | nslookup, subfinder, amass, theharvester, nmap (bare discovery sweep, **no** -sV/-sC), nmap -sV -sC (2nd targeted pass — nmap-script findings come from here now), banner grab (non-web ports only), header check, nikto, gobuster, dirb, whatweb, nuclei, **XSS pass**, ZAP baseline, + conditionally sqlmap, hydra, wpscan, enum4linux | discovery: all ports; web module on any detected web port | yes | yes, on every finding |
| `compliance` | nmap (`--script ssl-enum-ciphers,http-headers`), **sslyze + whatweb** (on the port(s) ssl-enum-ciphers identified) | 80/443/8443 (script-targeted) | no | nmap-script + sslyze + whatweb findings, scored/remediated |

`compliance` is the only profile that skips DNS resolution — `"nslookup"` isn't in
`PROFILES['compliance']['tools']`, and the orchestrator follows that config literally.

**`stealthscan`'s port list was redesigned this pass** (previously a full `-p- -T1` sweep).
Live measurement showed a full 65535-port sweep at any quiet timing template is an architectural
dead end (~0.29 ports/sec at `-T2` against a real filtered target → 60+ hours extrapolated) — no
amount of chunk/timeout tuning fixes that, the fix is to stop sweeping the whole range. It now
targets a fixed 20-port list (`21,22,23,25,53,80,110,139,143,443,445,993,995,1723,3306,3389,
5432,5900,8080,8443`) at `-T2` ("Polite," genuinely quiet unlike every other profile's `-T4`) —
measured live at 22.5–96.0s against two real targets, comfortably inside a 5-minute budget.

**`webaudit`/`deepscan`'s per-port web loops are wall-clock-bounded**
(`PROFILE_TIME_BUDGET_SECONDS`: webaudit 1800s, deepscan 3600s — deepscan's covers only the web
loop, not the separate full-port discovery sweep, which has its own much larger
`NMAP_TIMEOUTS['full_fast']` budget). Once exhausted mid-loop, the orchestrator logs it, stops
starting new ports, and finishes with whatever it already found — nothing already found is lost,
because findings are inserted per-port as soon as that port's tools finish, not batched to the
end.

**The XSS pass (`webaudit`, `deepscan`)** runs after gobuster/dirb, over the URLs
`_common.web_param_candidates()` builds from their discovered paths (§2.1) — capped at 6
candidates, ordered so the endpoints most likely to take a reflected parameter are fuzzed first.
Each candidate is one `run_xss()` call, recorded in `tool_results` as `nuclei-xss`, and its
findings are persisted as `finding_type = "xss_finding"` carrying `parameter`/`payload`/
`evidence`/`endpoint` for the report's injection section.

`deepscan`'s conditional tools (all four now real and dispatched):
- **sqlmap** — `_detect_injectable_candidates()` finds a gobuster/dirb path with a script
  extension (`.php/.asp/.aspx/.jsp/.cgi`) at status 200/301/302; appends `?id=1`. A confirmed
  injection then gets the read-only `--banner --current-db --dbs` enumeration (§3).
- **hydra** — `_detect_login_services()` maps an open port's nmap service name
  (ssh/ftp/telnet/ms-wbt-server→rdp) via `_LOGIN_SERVICE_MAP`.
- **wpscan** — gobuster's pre-existing `wordpress_fingerprinted` flag.
- **enum4linux** — dispatches unconditionally once `_detect_smb_services()` sees ports 139/445 open.

A condition that ISN'T met is now logged (`condition '<flag>' not met — skipping <tool>`, INFO
level) rather than silently producing no log line at all.

---

## 5. Known gaps (intentional — read before "fixing")

1. **ZAP baseline can return few/no real findings if its passive-scan ruleset add-on
   (`pscanrules`) isn't installed.** `install.sh` bootstraps this automatically now (once, on a
   fresh `~/.ZAP` profile, before any scan ever runs) — see install.sh's "One-time ZAP
   passive-scan-rules bootstrap" block. If it's already missing on a machine that skipped that
   step, or the add-on somehow gets uninstalled later (see below), recover it by: back up
   `~/.ZAP`, delete it, then either re-run `install.sh` or manually start `zap.sh -daemon` with
   the same flags `zap_wrap.py` uses and let the "N newer addons" download run to full
   completion (don't kill it mid-download — a half-written add-on breaks every subsequent ZAP
   start) before shutting it down cleanly via the API (`core/action/shutdown/`) so the
   newly-installed state actually persists to `add-ons-state.xml`.
   **Do not run `zap.sh -addonupdate` or `-addoninstall <id>` against this profile to try to fix
   a findings gap** — that specific action sequence is the confirmed leading suspect for how
   `pscanrules` got silently uninstalled during this project's own development (an add-on update
   reconciliation uninstalled the old version while updating unrelated add-ons, then failed to
   reinstall the replacement because the marketplace catalog lookup for that id was failing,
   with no error logged against it specifically).
2. **`webaudit` never calls `zaproxy`; `deepscan` never calls `sslyze`.** Both deliberate scoping
   decisions in each profile's own docstring / `_WIRED_TOOLS` set, not oversights.
3. **`whatweb`'s `cms_detected` flag has no consumer.** `whatweb_wrap.py` detects WordPress/
   Joomla/Drupal independently of gobuster, but nothing branches on it — deepscan's `wpscan`
   dispatch still only checks gobuster's `wordpress_fingerprinted`.
4. **`CONDITIONAL_TOOLS` firing has mainly been verified against purpose-built targets**, not
   this project's two default smoke-test targets (scanme.nmap.org, pentest-ground.com — neither
   meets any of the four trigger conditions on its own). Correct target-dependent behavior.
5. **`deepscan`'s full-port discovery phase has wide, target-dependent runtime** even with
   chunking (§3) — not a "2-minute demo" profile against a filtered target.
6. **`requirements.txt` has no `python-nmap`** (confirmed unused — `port_scanner.py`/
   `service_detect.py` shell out to the `nmap` binary directly and parse XML with the stdlib).
   `requirements.txt` does now include `python-owasp-zap-v2.4` (the `zapv2` client `zap_wrap.py`
   needs — see §3).
7. **Findings are persisted incrementally, and tool-availability lives in one place.** Both are
   deliberate and referenced throughout this file: every profile inserts each phase's/port's
   findings as soon as they are final, so a timeout, skip, budget cutoff or crash costs only what
   had not been found yet; and `_common.GLOBAL_AVAILABLE_TOOLS` is the single codebase-wide
   answer to "does a wrapper exist", replacing five profile-local copies that each only knew
   about their own profile's wrappers and therefore reported deliberate scope decisions as
   missing code.
8. **The duplicate-CVE path is fixed at collection time, not at render time.** `deepscan`
   enriches CVEs down two independent paths — nmap's detected service product and the `Server`
   header's product — and on a host where both name the same software, both used to insert the
   same CVE. `_findings_from_cves()` now takes a scan-wide `(cve_id, port)` `seen` set shared by
   both call sites (mirroring the `(template_id, matched_port)` guard nuclei already had). Keyed
   on the **CVE id**, not product+version, because the two paths legitimately name the product
   differently (`"Apache httpd"` vs `"Apache"`); keyed **per port**, so the same CVE on two ports
   still counts twice. The second NVD lookup is still made — it returned two CVEs the first one
   missed, so skipping it would cost real findings. `summary.deduplicate_findings()` stays as a
   render-time safety net; it no longer fires on this path.
9. **Attribution: two historical mismatches are allowlisted, not rewritten.** The whole-database
   sweep reports them; nobody has edited old rows to make the audit quiet.
10. **Live coverage of the tools-run record is deepscan + quickscan only.** `stealthscan`,
    `compliance` and `webaudit` were verified to import and wire `persist_tool_run()` identically
    (the same one line after the same stats block) and to compile cleanly, but were not exercised
    live in the pass that added it. Low risk, not the same thing as a live run.
11. **ZAP is not reliably interruptible mid-scan.** Two attempts to skip ZAP via SIGINT (an
    out-of-band `kill -INT` and a real Ctrl+C written to the PTY) did **not** skip it — ZAP
    completed both times. Its ~7-minute phase is dominated by daemon startup/shutdown, so an
    interrupt can simply land outside `zap_wrap`'s poll loop. A property of how interruptible ZAP
    is, not of the skip machinery (which is covered by unit tests and verified live on nuclei).
12. **The per-scan attribution check can only see producers that flow through `tool_results`.**
    That is every subprocess tool plus `header_check`/`banner_grab`; the one that cannot (`nvd`)
    is handled by the `UNTRACKED_PRODUCERS` grant (§3.4). Any future finding type produced by
    another in-process, non-`tool_results` producer needs the same treatment — noted here so the
    next such addition is deliberate rather than a silent false positive.
13. **`venv/` must have `zapv2` installed, and this bit once.** `requirements.txt` has listed
    `python-owasp-zap-v2.4` for a while, but the project's own `venv/` did not have it — so every
    deepscan/webaudit run through `venv/bin/python` silently lost ZAP and reported "tools failed:
    1", while the same scan through the system Python was fine. It is installed now, and
    `setup.py`'s `REQUIRED_MODULES` verifies `zapv2` (the real end state past the packaging shim)
    so a fresh clone is caught at install time instead of at scan time. The pinless requirement
    resolves to the 0.1.0 shim, which pulls in the renamed `zaproxy` 0.6.0 — verified to still
    provide `zapv2`/`ZAPv2` with the exact surface `zap_wrap.py` uses.

---

## 6. Where things live on disk

```
aegis-scanner/
├── aegis.py                    CLI entry point (target/--profile optional; interactive mode)
├── setup.py                    post-install bootstrap (deps incl. zapv2, dirs, config.py
│                                bootstrap, .env key prompt)
├── install.sh                  apt tools + venv + requirements.txt + setup.py; falls back to
│                                `go install` for nuclei if apt's package is stale/missing; checks
│                                for a JRE + zap.sh, and bootstraps ZAP's pscanrules add-on once
│                                on a fresh ~/.ZAP (needed by the rewritten zap_wrap.py)
├── requirements.txt            rich, requests, scapy, weasyprint, python-owasp-zap-v2.4
├── .env                        gitignored — AEGIS_NVD_API_KEY overrides the shared default
├── database/
│   ├── db.py                   SQLite CRUD + idempotent findings migration + scan_tools_run
│   └── aegis.db                the actual database file (tracked — scan history persists across clones)
├── modules/
│   ├── utils/                  logger, error_handler (Popen-based, skip-key + Ctrl+C handling),
│   │                            display, config (+ config.example.py, .env loading)
│   ├── profiles/                _common.py (warn_unavailable_tools/GLOBAL_AVAILABLE_TOOLS,
│   │                            web_param_candidates, classify_tool_outcome, persist_tool_run,
│   │                            finalise_reports), quickscan, stealth, webaudit, deepscan,
│   │                            compliance
│   ├── recon/                  dns, subdomain, osint
│   ├── scanning/                port_scanner (chunked full-range sweep), service_detect
│   │                            (now -sV -sC, parses scripts too), banner, enum4linux_wrap,
│   │                            hydra_wrap
│   ├── web/                    header_check, nikto_wrap, gobuster_wrap, dirb_wrap (fixed
│   │                            wordlist/failure-detection), whatweb_wrap, nuclei_wrap (cve_id),
│   │                            sqlmap_wrap (read-only enumeration), xss_wrap (nuclei DAST),
│   │                            sslyze_wrap, wpscan_wrap, zap_wrap (rewritten — drives ZAP's
│   │                            daemon API directly)
│   ├── enrichment/              cve_lookup (product disambiguation + lookup_cves_from_banner),
│   │                            severity (word-boundary keyword matching), remediation
│   └── reporting/               summary (the shared report vocabulary), report_txt, report_pdf
│                                (donut cover), retention (capped history), completion (the
│                                end-of-scan banner), attribution (the audit layer)
├── tests/                      t_phase2/3/4/8/9/10.py (unit assertions, stdlib only),
│   │                            t_pty.py (skip-key/Ctrl+C under a real PTY),
│   │                            db_sweep.py (whole-database audit gate)
│   └── fixtures/               real captured tool output the parsers are tested against
├── tools/                      backfill_nuclei_identity.py — standalone, explicitly invoked,
│                                dry-run unless --apply. Nothing in the scanner calls it.
├── smoke_test/                 smoke_test1-10.txt — the evidence log for each pass
└── output/
    └── <target>/                scan_errors.log,
                                 report_<profile>_<target>_<scan_id>.txt / .pdf (per target)
```

### 6.1 Verification assets

| Path | What it is |
|---|---|
| `tests/t_phase*.py` | Plain-stdlib assertion scripts, one per work pass, run as `python3 tests/t_phaseN.py`. No pytest dependency — they exit non-zero on failure. |
| `tests/fixtures/` | Real captured output from gobuster/nikto/nuclei/ZAP, committed so parser changes are tested against what the tools actually print, not against invented strings. |
| `tests/t_pty.py` | The skip-key and Ctrl+C paths under a real PTY — the listener is inert on a non-TTY, so nothing else can exercise them. |
| `tests/db_sweep.py` | The gate: renders **every** scan in `database/aegis.db` and checks crashes, ambiguous cells, duplicate rendered lines, **and** attribution (§3.4). Exits 0 only when everything passes. `python3 tests/db_sweep.py` for all scans, `python3 tests/db_sweep.py 138 139` for specific ids. Attribution lives here rather than in a separate script for a specific reason: the regression it exists to catch was missed because that question was nobody's job — run as one command, it cannot be the step someone forgets. |
| `smoke_test/smoke_testN.txt` | The written evidence for pass N: what was run, against what, what it produced, and — the part that matters — what is still open. Each pass opens by resolving the previous pass's open items. |
| `tools/backfill_nuclei_identity.py` | A one-off historical repair, kept for the record. Dry-run unless `--apply`, writes a before/after dump before any write, supports `--revert`, and only writes a row when two independent derivations of its template id agree (2 rows were skipped rather than guessed). It deliberately did **not** correct `port`: that value was never recorded for those runs, so writing it in would insert an inferred value into a historical record rather than restore an observed one. |

---

## 7. Config / env / interrupt-handling notes

`modules/utils/config.py` (gitignored; template is `config.example.py`, tracked) holds, beyond
`NVD_API_KEY`/`PROFILES`/`TOOL_TIMEOUTS`:

- **`NMAP_TIMEOUTS = {"full_fast": 19200}`** — the chunked `-p-` sweep's total budget (32 × 600s),
  calibrated from a live measurement (~9.4 ports/sec worst case against a partially-filtered
  target) rather than a guess.
- **`PROFILE_TIME_BUDGET_SECONDS = {"webaudit": 1800, "deepscan": 3600}`** — wall-clock ceilings
  for the per-port web-module loop specifically (§4), not the whole profile.
- **`COMPULSORY_TOOLS`** — `{tool_name: reason}` for tools the skip keybind refuses to skip
  (`nmap`, `nmap-sv`, `nslookup`, `dns_resolve`) because downstream modules depend on their output.
- **`SKIP_KEY = "s"`** — while a tool is running, pressing this key terminates just that
  subprocess (SIGTERM, then SIGKILL if it doesn't exit) and moves to the next tool. Implemented
  via a background cbreak-mode listener thread in `error_handler.py` (`_SkipKeyListener`) that
  only activates when stdin is a real TTY — inert on any non-interactive run (piped input, CI,
  the smoke-test harness).
- **Ctrl+C** now skips just the current tool on a single press (same as the skip key) unless it's
  the second press within 2 seconds, which aborts the whole scan (`KeyboardInterrupt` propagates
  up to `aegis.py`) — previously a single Ctrl+C always aborted the entire scan regardless of
  intent.

`config.example.py` also:
- Loads a gitignored `.env` at the repo root automatically at import time (`_load_dotenv()`).
- Ships `_DEFAULT_NVD_API_KEY`, a real, working, project-shared NVD API key, used unless
  `AEGIS_NVD_API_KEY`/`NVD_API_KEY` is set. A personal key always overrides.

`setup.py`'s `ensure_local_config()` copies `config.example.py` → `config.py` automatically on
first run (never overwrites an existing file).

---

## 8. Conventions to follow when extending this codebase

- New external tool call → wrap it in `run_tool()` (subprocess) or `safe_call()` (pure Python).
  Never call `subprocess` directly. **Set `result["skipped"] = tool_result.get("skipped",
  False)`** in the wrapper's return dict — every wrapper module was found to be dropping this
  (a real, live-discovered bug that made every profile's skip count show up as a failure count
  instead), so this is now a hard requirement for any new wrapper, not optional polish.
- New log line → go through `get_logger(target)`, not `print()`.
- New terminal output → add a `print_*` helper to `display.py` if one doesn't already fit.
- New config key → add it to **both** `modules/utils/config.py` and
  `modules/utils/config.example.py`.
- New module's return dict → always a plain dict, never raise, always degrade gracefully.
- New profile → follow the existing five as a template: resolve `PROFILES[name]`, call
  `modules.profiles._common.warn_unavailable_tools()` with this profile's own `_WIRED_TOOLS` set,
  wrap steps in `scan_progress_bar()`, persist findings incrementally as they're produced (not
  batched at the end), call `persist_tool_run(scan_id, tool_results)` right after computing the
  stats dict, finish through `finalise_reports()`, and return `(scan_id, report_path, stats)`.
  Also add the profile to `attribution.PROFILE_PRODUCERS` — a drift guard asserts every
  `_WIRED_TOOLS` entry appears there, so a profile missing from it fails the test suite.
- New finding kind → this is now a five-place change, and the checks will tell you if you miss
  one:
  1. Give it a stable `finding_type` and set `description`/`remediation`/`type`/`product` (plus
     `parameter`/`payload`/`evidence`/`endpoint`/`reference` where they apply) directly on the
     finding dict **at insert time** — never leave a row untyped for a report to classify by
     shape. Classifying by shape is the machinery the `reference`-column regression lived in.
  2. Branch on it in `severity.py` **and** `remediation.py` — attribution check 2 fails if the
     two classifiers disagree about it.
  3. Add it to `summary.FINDING_TYPE_TOOL` naming the tool that **produces** it (not the tool it
     triggers), and to `summary._NOT_APPLICABLE` for every field it can never carry.
  4. Add it to `attribution.FINDING_TYPE_PRODUCERS`, and to `REQUIRED_FIELDS` only if its
     identity column is genuinely certain.
  5. If it is an injection/scripting class, add it to `summary.INJECTION_FINDING_TYPES` so both
     report writers pick it up from the one definition.
- **Never key a classifier on a column merely being present.** SQLite rows carry every column, so
  `"reference" in finding` became true of every stored row the moment that column was added and
  silently reclassified every untyped finding as nikto's. Honour the persisted `finding_type`
  first and require the field to be **truthy**.
- New tool that produces findings → give its wrapper result a `tool` name, make sure it reaches
  `tool_results` (that is what gets recorded in `scan_tools_run`), and if the wrapper name differs
  from the producer name, add the mapping to `attribution._PRODUCER_ALIASES` (as `nuclei-xss` →
  `nuclei` does). A producer that never flows through `tool_results` at all needs an entry in
  `UNTRACKED_PRODUCERS` with a reason, or every finding it produces will be flagged.
- Fixing a duplicate → fix it at **collection** time, where the two paths that produce it can
  share a `seen` set. A render-time guard is a safety net, not the fix (§5.8).
- Repairing historical data → only from what was actually recorded. If a value was never
  captured, leave it NULL rather than inferring it; write a dry-run-by-default, revertible
  standalone script under `tools/` that nothing in the scanner calls, and dump before/after
  before any write.
- Wiring a tool into `PROFILES[...]['tools']` does **not** make it run — you must also add it to
  that profile orchestrator's own `_WIRED_TOOLS` set (or `deepscan`'s alias of
  `GLOBAL_AVAILABLE_TOOLS`) and call its wrapper. See §6.2/§3.1 of OVERVIEW_CONTEXT.md.
- A long-running or interruptible operation belongs behind `run_tool()`/`safe_call()`, which
  already implement timeout, skip-keybind, and Ctrl+C double-tap handling (§7) — don't hand-roll
  a second interrupt path (`zap_wrap.py`'s hand-rolled version exists only because it isn't a
  single subprocess call to begin with, and even it matches the same contract by hand).
