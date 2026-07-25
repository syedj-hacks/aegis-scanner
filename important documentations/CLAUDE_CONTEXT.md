# Aegis Scanner — Context Reference (attach this file to any Claude session)

Purpose: give Claude full structural knowledge of this repo without pasting source. Attach
this alone before asking for a change. Everything below reflects the actual code, not
aspirational design — if this file and the code disagree, trust the code and flag the drift.

Project: Kali Linux modular vulnerability-assessment CLI. Target in → recon → port scan → web
audit → conditional exploitation checks (sqlmap/hydra/wpscan/enum4linux) → CVE/severity/
remediation enrichment → SQLite persistence → TXT/PDF report out. Fully implemented
end-to-end; no stub modules remain. Every tool named anywhere in `PROFILES` has a real wrapper
module — see §3 for which profile actually calls which (that's still not the same question).

---

## 0. Non-negotiable conventions (violating these is the #1 review flag)

- Never call `subprocess` directly. External CLI tools go through
  `modules/utils/error_handler.py:run_tool(target, tool_name, command, timeout=None)`. Pure-Python
  I/O (sockets, `requests`) goes through `safe_call(func, *args, target=, label=, **kwargs)`.
  Both **always** return a structured dict and **never raise** (a deliberate second Ctrl+C within
  2s of the first is the sole exception — see §9). Every wrapper module follows this without
  exception.
- **Every tool-wrapper module's result dict must set `"skipped": tool_result.get("skipped",
  False)`** from whatever `run_tool()`/`safe_call()` returned. This was a real, live-discovered
  bug: all 15+ wrapper modules were silently dropping the skip flag, so a user-initiated skip
  (see §9) was miscounted as a tool *failure* in every profile's summary panel. Fixed across the
  board; any new wrapper module must include this line or the bug reappears.
- Never call `print()` in a module. All terminal output goes through
  `modules/utils/display.py` (Rich-based `print_*` helpers, `scan_progress_bar`, `print_table`,
  `print_summary`).
- Never log ad hoc. Use `modules/utils/logger.py:get_logger(target)` (or its
  `log_tool_start/success/failure/skip`, `log_finding`, `log_scan_start/end` wrappers) — writes
  to `output/<target>/scan_errors.log`.
- Every module function returns a plain dict, degrades gracefully on tool failure (empty
  list/`None` fields), and never raises — even on unreachable host / missing binary / timeout /
  user interrupt.
- New config key → add to **both** `modules/utils/config.py` (gitignored, real values) and
  `modules/utils/config.example.py` (tracked template), or teammates get `AttributeError`.
- `modules/utils/config.py` is gitignored — real per-user overrides go there or in `.env`.
  `config.example.py` (tracked) ships a shared, working default `AEGIS_NVD_API_KEY` fallback —
  see §7.1, a deliberate policy change from "never commit a real key."
- Wiring a tool into `PROFILES[name]['tools']` is not the same as that profile running it —
  each profile orchestrator has its own `_WIRED_TOOLS` set (or, for `deepscan`, an alias of the
  codebase-wide `GLOBAL_AVAILABLE_TOOLS` set) and must explicitly call the wrapper. All five
  orchestrators now share `modules/profiles/_common.py:warn_unavailable_tools()` instead of each
  carrying its own hand-rolled copy — see §3.1.
- A tool wrapper's failure branch should prefer capturing the tool's own stdout/stderr text over
  a generic "non-zero exit code" message — some tools (dirb, confirmed) write their real abort
  reason to stdout, not stderr, so checking only stderr silently loses the diagnostic.
- Findings are persisted **incrementally** (per scanning phase / per port) in `quickscan`,
  `webaudit`, `deepscan`, and `compliance` — not batched into one `insert_findings_bulk()` call
  at the very end. This means an interrupt (timeout, skip, budget cutoff, crash) partway through
  a scan keeps whatever was already found, rather than losing the whole run's findings. Follow
  this pattern in new profile code — insert as soon as a batch of findings is final, don't hold
  them in memory "to be tidy."

---

## 1. Directory tree (annotated)

```
aegis.py                        CLI entry point (argparse) — target/--profile optional, see §4
setup.py                        post-install: python/dep check, mkdir output+database,
                                 config.py bootstrap (ensure_local_config), .env key prompt
install.sh                      apt tools + venv + pip install + setup.py; falls back to
                                 `go install` for nuclei if apt's package is stale/missing;
                                 checks for a JRE + zap.sh (ZAP now driven via its daemon API,
                                 not a bundled baseline script — see §3's zaproxy note)
requirements.txt                rich, requests, scapy, weasyprint, python-owasp-zap-v2.4 (zapv2
                                 client) — no python-nmap (never imported)
.env                             gitignored — AEGIS_NVD_API_KEY=... (overrides shared default)
database/
  db.py                          SQLite CRUD, schema in §5 (description/remediation/
                                  finding_type/product, all nullable, migrated in idempotently)
  aegis.db                       tracked db file — scan history persists across clones
modules/
  utils/
    error_handler.py             run_tool(), safe_call() — the only I/O gateway. Popen-based
                                  (not subprocess.run) so a timeout, a skip keypress, or Ctrl+C
                                  can kill the child mid-flight; SIGTERM-then-SIGKILL so nmap gets
                                  a chance to flush a partial -oX document. See §9.
    logger.py                    get_logger(), log_* helpers incl. log_tool_skip()
    display.py                   all Rich terminal output; print_summary(show_tool_counts=)
    config.py                    gitignored: NVD_API_KEY, PROFILES, TOOL_TIMEOUTS, NMAP_TIMEOUTS,
                                  PROFILE_TIME_BUDGET_SECONDS, COMPULSORY_TOOLS, SKIP_KEY,
                                  CONDITIONAL_TOOLS — see §7
    config.example.py            tracked template; auto-loads .env + ships shared NVD key
  profiles/
    _common.py                   [NEW] shared warn_unavailable_tools() + GLOBAL_AVAILABLE_TOOLS
                                  set — see §3.1. All five orchestrators use this now instead of
                                  a profile-local, easily-stale copy.
  recon/
    dns.py                       resolve_dns(target) -> dns result dict
    subdomain.py                 enumerate_subdomains(target) -> subdomains dict
    osint.py                     harvest_osint(target, source="crtsh", limit=500) -> osint dict
  scanning/
    port_scanner.py              scan_ports(target, profile=None) -> {open_ports, scripts, skipped}
                                  A '-p-' (full 65535-port) sweep is transparently split into 32
                                  sequential sub-range nmap calls (_split_full_range,
                                  _FULL_RANGE_CHUNKS) — a killed nmap process does NOT reliably
                                  flush partial -oX output (verified empirically), so a chunk
                                  boundary is the real recovery unit, not "however far this one
                                  nmap process got." Only deepscan's bare -T4 discovery pass uses
                                  '-p-' now; stealthscan was redesigned onto a curated port list.
                                  Timeout is picked dynamically (_compute_nmap_timeout) —
                                  NMAP_TIMEOUTS['full_fast'] for a full-range sweep, the plain
                                  per-tool timeout otherwise.
    service_detect.py            detect_services(target, ports) -> {services, scripts, skipped}
                                  Runs nmap -sV **-sC** (default NSE script set) now, not just
                                  -sV — deepscan's own discovery sweep no longer carries -sV/-sC
                                  at all (too slow combined with a full-range sweep, confirmed
                                  live), so this targeted second pass is now also where deepscan's
                                  nmap-script findings come from.
    banner.py                    grab_banners(target, ports) -> {banners:[...]}. Wired into
                                  deepscan/webaudit, but only against ports that AREN'T already
                                  known web ports — an HTTP(S) server doesn't send an unsolicited
                                  banner, so probing it here just times out for nothing.
    enum4linux_wrap.py           run_enum4linux(target) -> {shares:[...], users:[...], os_info, error}
    hydra_wrap.py                run_hydra(target, service, port=None, userlist=None, passlist=None)
                                  -> {credentials_found:[...], error}
  web/
    header_check.py              check_headers(target, port=80, use_https=False) -> header dict
    nikto_wrap.py                run_nikto(target, port=80, use_https=False) -> {findings:[...]}
    gobuster_wrap.py             run_gobuster(target, port=80, use_https=False, wordlist=None) -> {discovered_paths:[...], wordpress_fingerprinted}
    dirb_wrap.py                 run_dirb(target, port=80, use_https=False, wordlist=None)
                                  -> {discovered_paths:[...], error}. Now tries dirb's own bundled
                                  small.txt (959 words) before common.txt — a full common.txt run
                                  reliably trips a target-side cumulative connection threshold on
                                  dirb specifically (it's single-threaded, one connection/request);
                                  root-caused live, not guessed at. Also pulls dirb's real abort
                                  reason out of stdout (dirb writes it there, not stderr) as a
                                  fallback, and discards results that look like a wildcard/soft-404
                                  flood (same guard gobuster_wrap.py already had).
    whatweb_wrap.py               run_whatweb(target, port=80, use_https=False)
                                  -> {technologies:[...], cms_detected, error}
    nuclei_wrap.py                run_nuclei(target, port=80, use_https=False, severity=None)
                                  -> {findings:[...], error} — each finding now also carries
                                  cve_id (comma-joined from nuclei's info.classification.cve-id
                                  list, per its documented JSON schema), threaded through to the
                                  DB by every profile that persists nuclei findings.
    sqlmap_wrap.py                run_sqlmap(target, url) -> {injectable: bool, findings:[...], error}
    sslyze_wrap.py                run_sslyze(target, port=443) -> {findings:[...], error}
    wpscan_wrap.py                run_wpscan(target, port=80, use_https=False, api_token=None)
                                  -> {findings:[...], error}
    zap_wrap.py                   run_zap_baseline(target, port=80, use_https=False)
                                  -> {findings:[...], error}. REWRITTEN: apt's zaproxy package on
                                  Kali doesn't ship zap-baseline.py (that's Docker-image-only), so
                                  this now starts the ZAP daemon itself (zap.sh -daemon), drives it
                                  over its REST API via the official zapv2 client (spider, wait for
                                  the passive scanner to drain, pull alerts, shut the daemon down),
                                  and does NOT go through run_tool() (it needs a long-lived process
                                  it talks HTTP to, not one subprocess it waits on) — but follows
                                  the same never-raises/always-a-dict contract by hand. Known
                                  residual gap: still produces few/no findings on a fresh ZAP
                                  install because the "Passive scanner rules" add-on (pscanrules)
                                  isn't installed by default — a one-time manual fix via ZAP's
                                  desktop GUI, not a code problem. See §6.
  enrichment/
    cve_lookup.py                lookup_cves(product, version=None, target="nvd", limit=10) -> {cves:[...], error}
                                  lookup_cves_from_banner(banner, target="nvd", limit=10) -> same
                                  shape — splits a raw Server/X-Powered-By header
                                  ("Apache/2.4.7 (Ubuntu)") into product/version first. Both now
                                  disambiguate a handful of common vendor tokens (apache, nginx,
                                  iis, tomcat, openssh, vsftpd, proftpd, mysql, postgresql,
                                  lighttpd — see _PRODUCT_ALIASES) into a more specific NVD
                                  keyword AND a CPE-product allowlist, dropping CVE hits whose own
                                  CPE data names a different product — found live: a bare "Apache"
                                  banner was returning an Apache Groovy RCE as a top match, wrong
                                  product entirely, just the same vendor name.
    severity.py                  score_finding(finding) -> finding copy + severity/severity_source/cvss.
                                  Keyword matching is now word-boundary regex, not substring
                                  containment — "rce" used to match inside "brute-*f*orce*" and
                                  silently inflated a routine nikto brute-force finding to CRITICAL.
    remediation.py                get_remediation(finding) -> finding copy + remediation
  reporting/
    summary.py                   build_summary(scan_id, top_n=10) -> summary dict; summary_stats(summary)
    report_txt.py                generate_txt_report(scan_id, output_path=None) -> path|None.
                                  _finding_identifier() (renamed from _top_finding_identifier())
                                  now falls back to a truncated description when both service and
                                  cve_id are empty — a nuclei/CVE-shaped finding with no service
                                  field used to render as a bare "unknown" everywhere (top-findings
                                  list AND the detailed-findings header, both fixed).
    report_pdf.py                generate_pdf_report(scan_id, output_path=None) -> path|None (WeasyPrint)
  profiles/                      orchestrators, one per scan profile — see §3
    quickscan.py   run_quickscan(target)   -> (scan_id, report_path, stats)
    stealth.py     run_stealthscan(target) -> (scan_id, report_path, stats)
    webaudit.py    run_webaudit(target)    -> (scan_id, report_path, stats)
    deepscan.py    run_deepscan(target)    -> (scan_id, txt_path, pdf_path, stats)
    compliance.py  run_compliance(target)  -> (scan_id, report_path, stats)
output/<target>/                scan_errors.log, report.txt, report.pdf (created per target)
important documentations/       human + AI docs (this file, WRITEUP.md, TUTORIAL.md, COMMANDS.txt, BACKEND_STRUCTURE.md)
```

Every profile now returns a trailing `stats` dict (`{tools_run, tools_failed, tools_skipped}`)
as its last tuple element — `aegis.py:_normalize_result()` detects it and merges it into the
final summary panel, which previously always showed "Tools run: 0" because `build_summary()`/
`summary_stats()` only ever knew DB-derived severity counts, never which tools actually ran.

---

## 2. Function contracts (return shapes)

```
resolve_dns(target) -> {success, resolved_ips: [...], error, ...}
enumerate_subdomains(target) -> {success, subdomains: [...], error, ...}
harvest_osint(target, source="crtsh", limit=500) -> {success, hosts/emails/..., error, ...}

scan_ports(target, profile=None)
  -> {open_ports: [{port, protocol, service, state}],
      scripts: [{port, protocol, script_id, output}],
      profile_used, raw_output, error, skipped}
      # a '-p-' sweep is chunked (see §1) — a failed/timed-out/skipped chunk stops the sweep
      # there and returns whatever prior chunks already found, with `error` naming which chunk
detect_services(target, ports)
  -> {services: [{port, service, version, product}],
      scripts: [{port, protocol, script_id, output}],   # from the -sC pass, see §1
      error, skipped}
grab_banners(target, ports) -> {banners: [{port, banner_text}], error}
run_enum4linux(target)
  -> {shares: [{name, type, comment}], users: [{user, rid}], os_info, raw_output, error, skipped}
run_hydra(target, service, port=None, userlist=None, passlist=None)
  -> {credentials_found: [{port, service, login, password}], raw_output, error, skipped}

check_headers(target, port=80, use_https=False)
  -> {missing_headers: [...], present_headers: {...}, server_banner, powered_by, error}
run_nikto(target, port=80, use_https=False)
  -> {findings: [{description, reference}], error, skipped}
run_gobuster(target, port=80, use_https=False, wordlist=None)
  -> {discovered_paths: [{path, status_code}], wordpress_fingerprinted: bool, error, skipped}
run_dirb(target, port=80, use_https=False, wordlist=None)
  -> {discovered_paths: [{path, status_code}], raw_output, error, skipped}
run_whatweb(target, port=80, use_https=False)
  -> {technologies: [{name, value}], cms_detected: str|None, raw_output, error, skipped}
run_nuclei(target, port=80, use_https=False, severity=None)
  -> {findings: [{template_id, name, severity, description, matched_at, reference, cve_id}], error, skipped}
run_sqlmap(target, url)
  -> {injectable: bool, findings: [{parameter, method, type, title}], error, skipped}
run_sslyze(target, port=443)
  -> {findings: [{issue, detail}], raw_output, error, skipped}
run_wpscan(target, port=80, use_https=False, api_token=None)
  -> {findings: [{component, title, reference}], raw_output, error, skipped}
run_zap_baseline(target, port=80, use_https=False)
  -> {findings: [{rule_id, name, status, severity}], raw_output, error, skipped}
      # rule_id/status/severity now derived from ZAP's own Risk rating (High/Medium/Low/
      # Informational) via its REST API, not parsed from zap-baseline.py's plain-text output —
      # see §1's zap_wrap.py note.

lookup_cves(product, version=None, target="nvd", limit=10)
  -> {cves: [{cve_id, product, version, description, cvss_score, cvss_severity,
              cvss_version, published_date, references: [{url, source, tags}]}], error}
  # error=None + empty cves == "NVD knows nothing"; error set == "lookup itself broke"
lookup_cves_from_banner(banner, target="nvd", limit=10) -> same shape as lookup_cves()
  # splits a raw Server/X-Powered-By string into (product, version) first — see §1

score_finding(finding) -> shallow copy of finding + {severity: CRITICAL|HIGH|MEDIUM|LOW,
              severity_source: "cvss"|"heuristic", cvss}
  # 4 tiers only, no INFO — informational findings floor to LOW

get_remediation(finding) -> copy of finding + {remediation: str}

build_summary(scan_id, top_n=10)
  -> {scan_id, scan_metadata, total_findings, by_severity, findings, top_findings, error}
summary_stats(summary) -> dict shaped for display.print_summary()

generate_txt_report(scan_id, output_path=None) -> path str | None   # never raises
generate_pdf_report(scan_id, output_path=None) -> path str | None   # WeasyPrint, lazy-imported

run_tool(target, tool_name, command, timeout=None)
  -> {tool, success, skipped, returncode, stdout, stderr, error, duration}
  # timeout overrides config.get_timeout(tool_name) when given (port_scanner.py uses this to
  # scale nmap's budget to how heavy its actual args are). skipped is True only when the user
  # pressed the skip key on a skippable (non-compulsory) tool. Never raises except on a
  # deliberate double Ctrl+C (see §9), which re-raises KeyboardInterrupt to abort the whole scan.
safe_call(func, *args, target="unknown", label="operation", **kwargs)
  -> {success, data, error}   # same KeyboardInterrupt handling as run_tool()
```

All five profile orchestrators share this internal skeleton:

```
run_<profile>(target):
    log_scan_start(target, PROFILE_NAME)
    profile_cfg = get_profile(PROFILE_NAME)         # from config.PROFILES
    warn_unavailable_tools(target, profile_cfg.get("tools"), PROFILE_NAME, _WIRED_TOOLS)
                                                       # shared helper, modules/profiles/_common.py
                                                       # — see §3.1
    scan_id = insert_scan(target, PROFILE_NAME)
    ... call recon/scanning/web/enrichment modules, wrapped in scan_progress_bar(...) ...
    insert_findings_bulk(scan_id, findings)          # incrementally, per phase/port — see §0
    stats = {"tools_run": ..., "tools_failed": ..., "tools_skipped": ...}
    log_scan_end(target, stats)
    report_path = generate_txt_report(scan_id)       # + generate_pdf_report() for deepscan only
    return (scan_id, report_path, stats)             # deepscan: (scan_id, txt_path, pdf_path, stats)
```

`deepscan.py`'s `_check_conditional_tools(target, flags, context) -> (raw_findings,
tool_results)` carries whatever the three detector functions produced (`injectable_url`,
`login_service`, `wordpress_port`, plus the unconditional `smb_service_found` check) so the
right wrapper gets called with the right argument. A trigger condition that ISN'T met is now
logged explicitly (`condition '<flag>' not met — skipping <tool>`, INFO level) instead of
silently doing nothing — added because deepscan's conditional-tool absence used to have zero
audit trail.

---

## 3. Profile behavior matrix

| Profile | Tools called | Ports | 2nd nmap `-sV -sC` pass? | Enrichment | Report |
|---|---|---|---|---|---|
| `quickscan` (default) | nslookup, nmap, nmap -sV -sC, **whatweb + nuclei (critical/high) on the first open web port** | top ports `-T4 -F` | yes | web findings scored; raw port/service persisted unscored (defaults LOW) | TXT |
| `stealthscan` | nslookup, nmap | curated ~20-port list, `-T2 -Pn --randomize-hosts` | **no** (avoids doubling probe traffic) | none | TXT |
| `webaudit` | nslookup, nmap, header_check (+CVE lookup on `Server` banner), nikto, gobuster, dirb, whatweb, sslyze (only if `use_https`), banner_grab (non-web ports only) | 80/443/8080/8443 | no | web findings + nmap-script findings, per-port CVE lookup | TXT |
| `deepscan` | nslookup, subfinder, amass, theharvester, nmap (bare `-T4 -p-`, chunked, **no** -sV/-sC), nmap -sV -sC (targeted 2nd pass, this is where nmap-script findings come from now), banner grab (non-web ports only), header_check (+CVE lookup), nikto, gobuster, dirb, whatweb, nuclei, ZAP, + conditional **sqlmap/hydra/wpscan/enum4linux** | discovery: all 65535 ports; web module: any detected web port | yes | every finding (CVE + severity + remediation) | TXT + PDF |
| `compliance` | nmap (`--script ssl-enum-ciphers,http-headers`, ports 80/443/8443 only — no DNS, no nikto/gobuster), **sslyze + whatweb** on whichever port(s) `ssl-enum-ciphers` identified as TLS (falls back to 443 if open) | script-targeted (80/443/8443) | no | nmap-script + sslyze + whatweb findings, scored/remediated | TXT |

`compliance` is the only profile with no DNS step — `"nslookup"` isn't in
`PROFILES['compliance']['tools']`, and the orchestrator follows that config literally.

**`webaudit`/`deepscan` are also bounded by a profile-level wall-clock budget**
(`config.PROFILE_TIME_BUDGET_SECONDS`: `webaudit`=1800s, `deepscan`=3600s — deepscan's covers
only its web-module per-port loop, not the separate, much larger full-port discovery sweep,
which uses `NMAP_TIMEOUTS['full_fast']` instead). `TOOL_TIMEOUTS` bounds one subprocess call,
not "6-7 tools per open web port, repeated for every open web port," which has no ceiling of
its own otherwise. Once the budget is exhausted mid-loop, the orchestrator logs it, stops
starting new tools/ports, and finishes with whatever partial-but-real findings it already has —
findings already found are never lost, because they were persisted per-port as they were found
(§0), not held until the loop finished.

### 3.1 How tool-availability warnings actually work (`modules/profiles/_common.py`)

Every profile used to carry its own hand-rolled `_AVAILABLE_TOOLS` set and warning function,
each independently tracking only the wrappers *that profile itself* called — so a tool with a
real wrapper elsewhere (e.g. `zaproxy`, called only by `deepscan`) was reported by `webaudit` as
having "no wrapper module in this codebase yet," which is false and confusing.

`_common.py` now provides:
- `GLOBAL_AVAILABLE_TOOLS` — every tool with a real wrapper module *anywhere* in the codebase.
- `warn_unavailable_tools(target, tools, profile_name, wired_tools)` — for each tool
  `PROFILES[profile_name]['tools']` lists that this profile doesn't itself call (`wired_tools`
  is that profile's own set), logs one of two honest messages: an **info** note ("has a wrapper
  module but is not run by this profile — by design") if it's in `GLOBAL_AVAILABLE_TOOLS`, or a
  real **warning** ("no wrapper module in this codebase yet") if it genuinely has none anywhere.

Per-profile `_WIRED_TOOLS`:
- `quickscan`: `{nslookup, nmap, whatweb, nuclei}` — **whatweb/nuclei are now actually called**
  (previously listed in `PROFILES['quickscan']['tools']` but never run — this was the reason
  quickscan and stealthscan used to come back near-identical). Scoped to nuclei's fast
  critical/high severity filter to keep quickscan's whole point — speed — intact.
- `stealth`: `{nslookup, nmap}`.
- `webaudit`: `{nslookup, nmap, nikto, gobuster, dirb, whatweb, sslyze, banner_grab}`. `zaproxy`
  has a real wrapper but is deliberately excluded — too heavy for webaudit's fast-audit scope.
- `compliance`: `{nmap, sslyze, whatweb}` — **whatweb is now actually called too** (a compliance
  TLS baseline benefits from knowing what's actually serving that endpoint, not just its
  ciphers), targeting the same port(s) sslyze does.
- `deepscan`: aliased directly to `GLOBAL_AVAILABLE_TOOLS` (kept as an alias rather than its own
  copy specifically so it can't drift out of sync the way the others used to).

---

## 4. CLI entry point (`aegis.py`)

```
python3 aegis.py [target] [--profile quickscan|stealthscan|webaudit|deepscan|compliance] [-v] [--version]
```
- `target` and `--profile` are optional. Omitting the target entirely (bare
  `python3 aegis.py`) triggers interactive mode: `_prompt_target()` (validated,
  re-prompting loop) then, if `--profile` was also omitted, `_prompt_profile()` (numbered
  menu of `PROFILES`, accepts number or name, defaults `quickscan`).
- `python3 aegis.py <target>` with no `--profile` is unchanged — silently defaults to
  `quickscan`, no menu.
- `is_valid_target(target)` — RFC-1123 hostname regex or `ipaddress.ip_address()`.
- `PROFILE_DISPATCH` dict maps profile name → orchestrator function.
- `_normalize_result(result)` flattens the 3-tuple/4-tuple profile return shapes (see §1/§2) to
  `(scan_id, [report_paths...], stats)`. Detects the trailing `stats` dict (rather than assuming
  a fixed tuple length) so both `(scan_id, path, stats)` and `(scan_id, txt, pdf, stats)` flatten
  correctly.
- The "Scan Configuration" panel now names the skip keybind and the Ctrl+C double-tap-to-abort
  behavior up front (`config.SKIP_KEY`) — see §9.
- Flow: (interactive prompts if needed) → validate target → `init_db()` → dispatch →
  `build_summary()` → `summary_stats()`, then **`stats.update(profile_stats)`** — the
  orchestrator's own real-time tool counts override `summary_stats()`'s always-zero
  tools_run/tools_failed placeholders (it only knows DB-derived severity counts, not which
  tools ran) — → print final panel + summary table.

---

## 5. Database schema (`database/db.py`, SQLite at `database/aegis.db`)

```sql
CREATE TABLE scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  profile TEXT NOT NULL
);

CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  port INTEGER,
  service TEXT,
  version TEXT,
  cve_id TEXT,
  cvss REAL,
  severity TEXT,
  description TEXT,     -- nullable
  remediation TEXT,      -- nullable
  finding_type TEXT,     -- nullable; defaults to "cve" if a cve_id is present and no type given
  product TEXT           -- nullable; NEW — service_detect.py's {product} field, previously discarded
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

`init_db()` runs this migration idempotently (checks `PRAGMA table_info(findings)` first, only
`ALTER TABLE ADD COLUMN`s what's missing) — safe on every process start, including against the
already-tracked `database/aegis.db` with pre-existing rows (those rows have `NULL` in whichever
of these columns didn't exist yet when they were inserted).

CRUD: `init_db()`, `insert_scan(target, profile) -> scan_id`, `insert_finding(scan_id, finding)`,
`insert_findings_bulk(scan_id, findings)`, `get_scan_history(target=None)`,
`get_findings_for_scan(scan_id)`, `get_latest_scan(target)`.

Concurrency: every insert function opens a fresh `get_connection()` per call (no shared/global
connection), commits and closes within the call. SQLite's 5s default busy-timeout provides
serialization room for concurrent writers — confirmed safe live (a mid-scan kill left a clean
scan row with zero orphaned finding rows, no corruption to concurrently-completing runs).

---

## 6. Known gaps — intentional, do not "fix" without understanding why first

1. **ZAP baseline still produces few/no real findings on a fresh install** — the daemon/spider/
   API pipeline (`modules/web/zap_wrap.py`) works correctly end-to-end (rewritten to talk to
   ZAP's own REST API directly, see §1), but the "Passive scanner rules" add-on (`pscanrules`,
   ~60+ checks) is not installed in a stock ZAP profile — only ~3 trivial built-in rules are
   active, so passive scanning returns near-zero alerts regardless of target. Multiple headless
   install attempts were tried and each failed for a distinct, confirmed reason (marketplace-by-
   id lookup fails; local-file-install API call rejected; a promising-sounding config flag
   doesn't do what its name implies). Fix requires a one-time manual install via ZAP's desktop
   GUI, not a code change.
2. **`webaudit` never calls `zaproxy`** and **`deepscan` never calls `sslyze`** — both
   deliberate scoping decisions (documented in each profile's own docstring / §3.1's
   `_WIRED_TOOLS`), not oversights. Don't "complete" these without checking the reasoning first.
3. **`whatweb`'s `cms_detected` flag has no consumer.** Nothing ORs it with gobuster's
   `wordpress_fingerprinted` before the `wpscan` conditional check fires — only gobuster's flag
   currently triggers `wpscan`.
4. **`CONDITIONAL_TOOLS` (wpscan/sqlmap/hydra/enum4linux) firing has only been reproduced against
   targets purpose-built to trigger them** (a real WordPress install, a target with SMB open,
   etc.) — neither of this project's two go-to smoke-test targets (scanme.nmap.org,
   pentest-ground.com) meets any of the four trigger conditions on their own, so this path's
   correctness rests on targeted testing, not everyday smoke-test runs. Correct target-dependent
   behavior, not a bug.
5. **`deepscan`'s full 65535-port discovery phase has wide, target-dependent runtime** — chunked
   into 32 sub-scans specifically so a slow/filtered target still yields partial real results
   instead of every chunk timing out before completing once (this failure mode was reproduced and
   fixed live — see `port_scanner.py`'s `_FULL_RANGE_CHUNKS` comment). Still not a "2-minute
   demo" profile against a heavily filtered target; lead with quickscan/stealthscan/webaudit/
   compliance for time-boxed demos.
6. **`requirements.txt` has no `python-nmap`** (removed, confirmed unused) — `port_scanner.py`/
   `service_detect.py` shell out to the `nmap` binary and parse XML with the stdlib.

---

## 7. Config / env keys

| Key | Where | Purpose |
|---|---|---|
| `AEGIS_NVD_API_KEY` (or legacy `NVD_API_KEY`) | `.env` or shell env, overriding `config.example.py`'s shared default | NVD rate limit 5→50 req/30s. Optional — a shared default key already ships. |
| `PROFILES` | `config.py` | per-profile `tools` list + `nmap_args` (+ `nuclei_severity`/`gobuster_wordlist` where relevant). Listing a tool here does **not** make a profile run it — see §0 and §3.1. |
| `TOOL_TIMEOUTS` | `config.py` | per-tool timeout seconds, `get_timeout(tool_name)` falls back to `"default"` (120s). Includes `"dirb": 300`, `"zaproxy": 900`. |
| `NMAP_TIMEOUTS` | `config.py` | `{"full_fast": 19200}` (32 chunks × 600s) — the budget for a chunked `-p-` full-range sweep, calibrated live against a real partially-filtered target (~9.4 ports/sec worst case). `port_scanner.py:_compute_nmap_timeout()` picks this over the plain `TOOL_TIMEOUTS['nmap']` when the args contain `-p-`. |
| `PROFILE_TIME_BUDGET_SECONDS` | `config.py` | `{"webaudit": 1800, "deepscan": 3600}` — profile-level wall-clock ceilings for the per-port web-module loop (not the whole profile, not the nmap discovery phase). See §3. |
| `COMPULSORY_TOOLS` | `config.py` | `{tool_name: reason}` — tools the skip keybind (§9) refuses to skip because downstream modules depend on their output (`nmap`, `nmap-sv`, `nslookup`, `dns_resolve`). |
| `SKIP_KEY` | `config.py` | `"s"` — the keybind that terminates just the currently-running tool. See §9. |
| `CONDITIONAL_TOOLS` | `config.py` | tool → flag-name mapping (see §3) — all four have real producers + dispatch. |
| `MAX_THREADS` | `config.py` | = 10, not currently referenced by any module found in this map — verify before relying on it |
| `OUTPUT_ROOT` | `config.py` | `"output"`; `output_dir(target)` creates+returns `output/<target>/` |

### 7.1 `.env` auto-loading

`config.py` parses a gitignored `.env` at the repo root automatically at import time
(`_load_dotenv()`), populating `os.environ` for any key not already exported — stdlib only. A
real shell `export` always takes priority over `.env`.

---

## 8. When asked to implement a change here

- Identify which layer owns it (recon/scanning/web/enrichment/reporting/profiles/utils) and
  match that layer's existing function signature style (target-first, dict-return, no raise).
- If it's a new external tool: add a wrapper module following the `run_tool()` pattern (use any
  existing `modules/web/*_wrap.py` as a template — remember `result["skipped"] =
  tool_result.get("skipped", False)`, see §0), add its timeout to `TOOL_TIMEOUTS`, add it to the
  relevant profile's `_WIRED_TOOLS` set (via `_common.warn_unavailable_tools()`, §3.1), and wire
  the profile orchestrator to call it. Adding it to `PROFILES[...]['tools']` alone does nothing.
- If it touches findings persistence: set `description`/`remediation`/`finding_type`/`product`
  directly on the finding dict, and persist incrementally as soon as a batch of findings is
  final (§0) rather than holding everything until the very end.
- If it's config: update `config.py` **and** `config.example.py` together.
- Don't reintroduce `print()`/raw `subprocess`/raw logging — grep for the existing helper first.
- Before assuming a tool "isn't wired in yet," check the specific profile's own `_WIRED_TOOLS`
  set and docstring — several tool/profile pairings are deliberately unwired (§6.2), not
  oversights.
- A long-running or interruptible operation should go through `run_tool()`/`safe_call()`, which
  already handle timeout, skip-keybind, and Ctrl+C — don't hand-roll a second interrupt path.

---

## 9. Interrupt handling & the skip keybind

A long-running tool (nikto's 600s timeout, a full-port nmap sweep chunk, ...) has three distinct
ways to end early, all handled inside `error_handler.py`:

- **Timeout** — the tool's own configured/dynamic timeout expires; SIGTERM then SIGKILL if it
  doesn't exit within a grace period; `result["error"]` names the timeout.
- **Skip keybind** — pressing `config.SKIP_KEY` (default `'s'`) while a tool is running
  terminates just that subprocess (same SIGTERM/SIGKILL path) and lets the profile orchestrator
  move on to the next tool, without arming the Ctrl+C abort window at all. Only active when
  stdin is a real interactive TTY (`_SkipKeyListener`, cbreak-mode background thread) — a
  non-interactive run (piped input, cron, CI, this project's own smoke-test harness) never sees
  it and the feature is simply inert. Tools in `COMPULSORY_TOOLS` (nmap, nmap-sv, nslookup,
  dns_resolve — things every downstream module depends on) refuse the skip with a message
  naming why, and keep running.
- **Ctrl+C** — a single press has the same effect as the skip key (kills the current tool,
  continues the scan) UNLESS it's the second press within 2 seconds of the first
  (`_ABORT_WINDOW`), in which case it's treated as deliberate and `KeyboardInterrupt` propagates
  all the way up to `aegis.py`, aborting the whole scan. This is the one case where `run_tool()`/
  `safe_call()` raise instead of returning a structured failure.

SIGTERM is always tried before SIGKILL (`_terminate_then_kill()`) — nmap in particular treats
SIGTERM as "wrap up now" and writes a valid, if incomplete, `-oX` document when it gets one,
so a timeout/skip on a long nmap sweep doesn't have to mean losing every port found so far.

`zap_wrap.py` implements this same contract by hand (see §1) since it isn't a single subprocess
call `run_tool()` can wrap — it manages a long-lived daemon it talks HTTP to instead.
