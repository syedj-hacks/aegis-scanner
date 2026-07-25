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
  │     ├─ web         [modules/web/*.py]           -> headers / nikto / gobuster / dirb / whatweb / nuclei / zap / wpscan / sqlmap / sslyze dicts
  │     ├─ enrichment  [modules/enrichment/*.py]    -> cves / severity / remediation
  │     ├─ insert_findings_bulk(scan_id, findings)  [database/db.py] — called incrementally,
  │     │     per scanning phase / per port, not once at the end (see §5.7)
  │     └─ generate_txt_report() / generate_pdf_report()  [modules/reporting/*.py]
  │
  └─ build_summary(scan_id) -> summary_stats() -> stats.update(profile_stats) -> print_summary()
                                                    [modules/reporting/summary.py, aegis.py]
```

Every profile orchestrator (`modules/profiles/*.py`) follows the same shape: resolve its config
from `PROFILES[name]`, call the shared `warn_unavailable_tools()` helper (§2, `_common.py`) to
report any configured tool this profile doesn't wire in, call its modules in sequence (inserting
findings as they become final, not all at once), generate a report, and return
`(scan_id, report_path, stats)` — deepscan returns `(scan_id, txt_path, pdf_path, stats)`.
`stats` is `{tools_run, tools_failed, tools_skipped}`; `aegis.py` merges it into the final
summary panel because `summary_stats()` alone only knows DB-derived severity counts, never which
tools actually ran.

---

## 2. Shared foundation (`modules/utils/` + `modules/profiles/_common.py`)

Nothing in `modules/` should call `subprocess` or `print()` directly — it goes through here.

| File | Purpose |
|---|---|
| `error_handler.py` | `run_tool(target, tool_name, command, timeout=None)` — the **only** sanctioned way to shell out to an external CLI tool. Always returns `{success, skipped, stdout, stderr, error, duration, ...}`, never raises except on a deliberate double Ctrl+C (§7). `safe_call(func, *args, target=, label=, **kwargs)` — same contract for pure-Python calls (raw sockets, `requests`). Built on `subprocess.Popen`, not `subprocess.run`, specifically so a timeout, a skip keypress, or Ctrl+C can kill the child mid-flight instead of only being noticed after it exits on its own. |
| `logger.py` | `get_logger(target)` — one logger per target, writing to `output/<target>/scan_errors.log`. Also: `log_tool_start/success/failure/skip`, `log_finding`, `log_scan_start/end`. |
| `display.py` | All terminal output (Rich-based): `print_banner/panel/phase/info/success/warning/error`, `print_table` (now includes a Description column), `print_tree`, `scan_progress_bar`, `print_summary(target, stats, show_tool_counts=True)`. |
| `config.py` | Gitignored — `NVD_API_KEY`, `PROFILES`, `TOOL_TIMEOUTS`, `NMAP_TIMEOUTS`, `PROFILE_TIME_BUDGET_SECONDS`, `COMPULSORY_TOOLS`, `SKIP_KEY`, `CONDITIONAL_TOOLS`, `output_dir()`. Mirrored by `config.example.py` (tracked) — **keep both in sync when adding a config key**. `config.example.py` auto-loads a gitignored `.env` and ships a shared default `NVD_API_KEY` (§7). |
| `modules/profiles/_common.py` | **New shared module.** `GLOBAL_AVAILABLE_TOOLS` (every tool with a real wrapper anywhere in the codebase) + `warn_unavailable_tools(target, tools, profile_name, wired_tools)`. Replaces five separate, easily-stale profile-local `_AVAILABLE_TOOLS` copies — see §5.7. |

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
| `nikto_wrap.py` | `run_nikto(target, port=80, use_https=False)` | `nikto` | `{findings: [{description, reference}], error, skipped}` — nikto exits 0 even on connection failure, so failure is detected from report text |
| `gobuster_wrap.py` | `run_gobuster(target, port=80, use_https=False, wordlist=None)` | `gobuster dir` | `{discovered_paths: [{path, status_code}], wordpress_fingerprinted: bool, error, skipped}`; auto-retries with `--exclude-length` on SPA wildcard responses |
| `dirb_wrap.py` | `run_dirb(target, port=80, use_https=False, wordlist=None)` | `dirb -S -w -r` | `{discovered_paths: [{path, status_code}], raw_output, error, skipped}` — see below for the wordlist/failure-detection fix |
| `whatweb_wrap.py` | `run_whatweb(target, port=80, use_https=False)` | `whatweb -a 3` | `{technologies: [{name, value}], cms_detected: str\|None, raw_output, error, skipped}` — `cms_detected` still has no consumer (§5.6) |
| `nuclei_wrap.py` | `run_nuclei(target, port=80, use_https=False, severity=None)` | `nuclei -jsonl -silent` | `{findings: [{template_id, name, severity, description, matched_at, reference, cve_id}], raw_output, error, skipped}` — `cve_id` (new) is comma-joined from `info.classification.cve-id`, threaded through by every profile that persists nuclei findings |
| `sqlmap_wrap.py` | `run_sqlmap(target, url)` | `sqlmap --batch --level 1 --risk 1` | `{injectable: bool, findings: [{parameter, method, type, title}], raw_output, error, skipped}` |
| `sslyze_wrap.py` | `run_sslyze(target, port=443)` | `sslyze --json_out=<tmpfile>` | `{findings: [{issue, detail}], raw_output, error, skipped}` |
| `wpscan_wrap.py` | `run_wpscan(target, port=80, use_https=False, api_token=None)` | `wpscan --format json` | `{findings: [{component, title, reference}], raw_output, error, skipped}` |
| `zap_wrap.py` | `run_zap_baseline(target, port=80, use_https=False)` | ZAP daemon + `zapv2` REST client (see below) | `{findings: [{rule_id, name, status, severity}], raw_output, error, skipped}` |

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
| `summary.py` | `build_summary(scan_id, top_n=10)` → `{scan_id, scan_metadata, total_findings, by_severity, findings, top_findings, error}`, worst-first. `summary_stats()` adapts it to `display.print_summary()`'s shape — only DB-derived severity counts; `aegis.py` layers the profile's own real tool-run stats on top afterward (§1). | Trusts the stored `severity` column; prefers stored `description`/`remediation` DB columns, falling back to derived text for pre-migration rows where those are `NULL`. |
| `report_txt.py` | `generate_txt_report(scan_id, output_path=None)` | `_finding_identifier()` (renamed from `_top_finding_identifier()`) falls back to a truncated `description` when both `service` and `cve_id` are empty — fixes a real bug where a nuclei/CVE-shaped finding with no `service` field rendered as a bare `"unknown"` in both the top-findings list and the detailed-findings header. `preview_report()` calls `print_summary(..., show_tool_counts=False)` — see `display.py` below for why. |
| `report_pdf.py` | `generate_pdf_report(scan_id, output_path=None)` | WeasyPrint, imported lazily. All interpolated values are HTML-escaped. |

Both writers default to `config.output_dir(target)/report.{txt,pdf}` and return the path or
`None` — they never raise.

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
  unsolicited banner). `zaproxy` still deliberately not called (too heavy for this profile's
  scope).
- **`deepscan.py`** — web-module per-port loop bounded by `PROFILE_TIME_BUDGET_SECONDS['deepscan']`
  (60 min; the separate full-port discovery sweep has its own, much larger `NMAP_TIMEOUTS`
  budget). All four `CONDITIONAL_TOOLS` dispatch for real, and a condition that ISN'T met is now
  logged explicitly (`condition '<flag>' not met — skipping <tool>`) instead of silently doing
  nothing. `sslyze` still deliberately not called (reserved for compliance/webaudit).
- **`compliance.py`** — **now also runs `whatweb`** alongside `sslyze`, both targeting whichever
  port(s) `ssl-enum-ciphers` identified as TLS-speaking (443 fallback if open). Persists per-TLS-
  port rather than batched across all of them.

### `database/db.py`
SQLite at `database/aegis.db`. `findings` has four nullable columns beyond the original six:

```sql
scans (id, target, timestamp, profile)
findings (id, scan_id, port, service, version, cve_id, cvss, severity,
          description, remediation, finding_type, product)
```

`init_db()` runs an idempotent migration (`PRAGMA table_info(findings)` → `ALTER TABLE ... ADD
COLUMN` for any of `description`/`remediation`/`finding_type`/`product` not already present) —
safe to call on every process start. `insert_finding()` derives `finding_type` from
`finding.get("type") or finding.get("finding_type")`, defaulting to `"cve"` when a `cve_id` is
present and no type was given.

CRUD: `init_db()`, `insert_scan(target, profile) -> scan_id`, `insert_finding(scan_id, finding)`,
`insert_findings_bulk(scan_id, findings)`, `get_scan_history(target=None)`,
`get_findings_for_scan(scan_id)`, `get_latest_scan(target)`.

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

The "Scan Configuration" panel now also explains the skip keybind (`config.SKIP_KEY`) and the
Ctrl+C double-tap-to-abort behavior (see §7) before the scan starts. After the scan, `main()`
does `stats = summary_stats(summary); stats.update(profile_stats)` — the orchestrator's own
real-time tool counts override `summary_stats()`'s DB-only placeholders, which is what actually
makes the final "Tools run/failed/skipped" line correct.

---

## 4. Profile behavior cheat sheet

| Profile | Tools it actually runs | Ports scanned | 2nd nmap `-sV -sC` pass? | CVE/severity enrichment | Report |
|---|---|---|---|---|---|
| `quickscan` | nslookup, nmap, nmap -sV -sC, **whatweb + nuclei on the first open web port** | top ports (`-T4 -F`) | yes | web findings scored; raw port/service persisted unscored (LOW default) | TXT |
| `stealthscan` | nslookup, nmap | curated ~20-port list (`-T2 -Pn --randomize-hosts`) | **no** (deliberately, to avoid doubling probe traffic) | no | TXT |
| `webaudit` | nslookup, nmap, header check, nikto, gobuster, dirb, whatweb, banner grab (non-web ports only), sslyze (if https) | 80/443/8080/8443 only | no | web findings + nmap-script findings + `Server` banner CVE lookup | TXT |
| `deepscan` | nslookup, subfinder, amass, theharvester, nmap (bare discovery sweep, **no** -sV/-sC), nmap -sV -sC (2nd targeted pass — nmap-script findings come from here now), banner grab (non-web ports only), header check, nikto, gobuster, dirb, whatweb, nuclei, ZAP baseline, + conditionally sqlmap, hydra, wpscan, enum4linux | discovery: all ports; web module on any detected web port | yes | yes, on every finding | TXT + PDF |
| `compliance` | nmap (`--script ssl-enum-ciphers,http-headers`), **sslyze + whatweb** (on the port(s) ssl-enum-ciphers identified) | 80/443/8443 (script-targeted) | no | nmap-script + sslyze + whatweb findings, scored/remediated | TXT |

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

`deepscan`'s conditional tools (all four now real and dispatched):
- **sqlmap** — `_detect_injectable_candidates()` finds a gobuster/dirb path with a script
  extension (`.php/.asp/.aspx/.jsp/.cgi`) at status 200/301/302; appends `?id=1`.
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

---

## 6. Where things live on disk

```
aegis-scanner/
├── aegis.py                    CLI entry point (target/--profile optional; interactive mode)
├── setup.py                    post-install bootstrap (deps, dirs, config.py bootstrap, .env key prompt)
├── install.sh                  apt tools + venv + requirements.txt + setup.py; falls back to
│                                `go install` for nuclei if apt's package is stale/missing; checks
│                                for a JRE + zap.sh (needed by the rewritten zap_wrap.py)
├── requirements.txt            rich, requests, scapy, weasyprint, python-owasp-zap-v2.4
├── .env                        gitignored — AEGIS_NVD_API_KEY overrides the shared default
├── database/
│   ├── db.py                   SQLite CRUD (+ description/remediation/finding_type/product migration)
│   └── aegis.db                the actual database file (tracked — scan history persists across clones)
├── modules/
│   ├── utils/                  logger, error_handler (Popen-based, skip-key + Ctrl+C handling),
│   │                            display, config (+ config.example.py, .env loading)
│   ├── profiles/                _common.py (shared warn_unavailable_tools/GLOBAL_AVAILABLE_TOOLS),
│   │                            quickscan, stealth, webaudit, deepscan, compliance
│   ├── recon/                  dns, subdomain, osint
│   ├── scanning/                port_scanner (chunked full-range sweep), service_detect
│   │                            (now -sV -sC, parses scripts too), banner, enum4linux_wrap,
│   │                            hydra_wrap
│   ├── web/                    header_check, nikto_wrap, gobuster_wrap, dirb_wrap (fixed
│   │                            wordlist/failure-detection), whatweb_wrap, nuclei_wrap (cve_id),
│   │                            sqlmap_wrap, sslyze_wrap, wpscan_wrap, zap_wrap (rewritten —
│   │                            drives ZAP's daemon API directly)
│   ├── enrichment/              cve_lookup (product disambiguation + lookup_cves_from_banner),
│   │                            severity (word-boundary keyword matching), remediation
│   └── reporting/               summary, report_txt (fixed "unknown" fallback), report_pdf
└── output/
    └── <target>/                scan_errors.log, report.txt, report.pdf (per target)
```

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
  batched at the end), generate a report, return `(scan_id, report_path, stats)`.
- New finding kind → give it a stable duck-typed marker key, branch on it in
  `severity.py`/`remediation.py`, and set `description`/`remediation`/`type`/`product` directly
  on the finding dict at insert time.
- Wiring a tool into `PROFILES[...]['tools']` does **not** make it run — you must also add it to
  that profile orchestrator's own `_WIRED_TOOLS` set (or `deepscan`'s alias of
  `GLOBAL_AVAILABLE_TOOLS`) and call its wrapper. See §5.2/§3.1 of CLAUDE_CONTEXT.md.
- A long-running or interruptible operation belongs behind `run_tool()`/`safe_call()`, which
  already implement timeout, skip-keybind, and Ctrl+C double-tap handling (§7) — don't hand-roll
  a second interrupt path (`zap_wrap.py`'s hand-rolled version exists only because it isn't a
  single subprocess call to begin with, and even it matches the same contract by hand).
