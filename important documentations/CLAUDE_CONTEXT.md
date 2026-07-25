# Aegis Scanner — Context Reference (attach this file to any Claude session)

Purpose: give Claude full structural knowledge of this repo without pasting source. Attach
this alone before asking for a change. Everything below reflects the actual code, not
aspirational design — if this file and the code disagree, trust the code and flag the drift.

Project: Kali Linux modular vulnerability-assessment CLI. Target in → recon → port scan → web
audit → injection & scripting checks (sqlmap SQLi, nuclei-DAST XSS) → conditional exploitation
checks (sqlmap/hydra/wpscan/enum4linux) → CVE/severity/remediation enrichment → SQLite
persistence → TXT + PDF report out. Fully implemented end-to-end; no stub modules remain. Every
tool named anywhere in `PROFILES` has a real wrapper module — see §3 for which profile actually
calls which (that's still not the same question).

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
- **Every finding row must be typed at insert time.** Set `finding_type` (via `type`) on the
  finding dict where it is produced. A row left untyped forces a report to classify it by *shape*,
  and that is exactly the machinery a live regression lived in: `_finding_kind()` sniffed nikto by
  `"reference" in finding`, and since SQLite rows carry every column, adding a `reference` column
  reclassified every stored untyped finding as nikto's — a stealthscan open-port finding was told
  to "review this nikto finding", naming a tool that never ran. **Never key a classifier on a
  column merely being present**: honour the persisted `finding_type` and require the value to be
  truthy.
- **`severity.py` and `remediation.py` must classify a finding identically.** They document the
  same contract; `modules/reporting/attribution.py` check 2 now verifies it instead of trusting
  it. A row the two disagree about is graded by one set of rules and remediated by another.
- **A finding is credited to the tool that PRODUCED it**, never to the tool it is advice to run
  next. `wordpress_fingerprinted` is a **gobuster** finding (gobuster hits the `/wp-*` marker
  path); it is the *trigger* for wpscan, and crediting it to wpscan made `webaudit` — which never
  runs wpscan — name a tool that had not run, in every report containing it.
- Every profile ends the same way: `persist_tool_run(scan_id, tool_results)` right after the stats
  dict, then `finalise_reports(...)`. Both live in `_common.py` (§3.1) — don't hand-roll either.
- Fix a duplicate at **collection** time (a shared `seen` set across the paths that produce it),
  not at render time. A render-time guard is a safety net, not the fix.

---

## 1. Directory tree (annotated)

```
aegis.py                        CLI entry point (argparse) — target/--profile optional, see §4
setup.py                        post-install: python/dep check (REQUIRED_MODULES includes zapv2 —
                                 its omission is how a missing ZAP client passed verification
                                 silently), mkdir output+database, config.py bootstrap
                                 (ensure_local_config), .env key prompt
install.sh                      apt tools + venv + pip install + setup.py; falls back to
                                 `go install` for nuclei if apt's package is stale/missing;
                                 checks for a JRE + zap.sh and bootstraps ZAP's pscanrules add-on
                                 once on a fresh ~/.ZAP (ZAP is driven via its daemon API, not a
                                 bundled baseline script — see §1's zaproxy note and §6.1)
requirements.txt                rich, requests, scapy, weasyprint, python-owasp-zap-v2.4 (zapv2
                                 client) — no python-nmap (never imported)
.env                             gitignored — AEGIS_NVD_API_KEY=... (overrides shared default)
database/
  db.py                          SQLite CRUD, schema in §5 (nine nullable findings columns,
                                  migrated in idempotently, + the scan_tools_run table)
  aegis.db                       tracked db file — scan history persists across clones
tests/                           t_phase2/3/4/8/9/10.py (stdlib assertion scripts, no pytest),
  t_pty.py                        the skip-key/Ctrl+C paths under a real PTY
  db_sweep.py                     whole-database audit gate: renders EVERY scan and checks
                                   crashes / ambiguous cells / duplicate lines / attribution.
                                   Exits 0 only when all pass. `python3 tests/db_sweep.py`
  fixtures/                       real captured gobuster/nikto/nuclei/ZAP output, so parser
                                   changes are tested against what the tools actually print
tools/
  backfill_nuclei_identity.py    one-off historical repair. Standalone, dry-run unless --apply,
                                  --revert supported, nothing in the scanner calls it
smoke_test/                      smoke_test1-10.txt — per-pass evidence log, each one ending in
                                  an explicit "what remains open" section the next pass opens with
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
    _common.py                   shared profile-layer helpers — all five orchestrators use these
                                  instead of five profile-local, easily-stale copies:
                                  warn_unavailable_tools() + GLOBAL_AVAILABLE_TOOLS (§3.1);
                                  web_param_candidates() (builds fuzzable ?param= URLs from
                                  gobuster/dirb paths for the XSS pass — candidate ORDERING
                                  matters, see §3.2); classify_tool_outcome() (the one
                                  ran/skipped/failed predicate); count_and_report_tool_failures()
                                  (counting and reporting are the same function on purpose);
                                  persist_tool_run(); finalise_reports() (report → prune →
                                  banner, in that order); the nuclei_* finding-shaping helpers
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
    sqlmap_wrap.py                run_sqlmap(target, url) -> {injectable, findings:[...],
                                  metadata:{dbms, banner, current_db, databases}, error}.
                                  --batch --random-agent --level 1 --risk 1 plus three SAFE
                                  read-only enumerations (--banner --current-db --dbs) so a
                                  confirmed finding carries real evidence instead of a bare
                                  boolean. NEVER --dump/--os-shell/--sql-shell/--file-read/
                                  --file-write: metadata only. Rejects a URL with no query string.
    xss_wrap.py                   run_xss(target, url) -> {vulnerable, findings:[...], error}.
                                  [NEW] XSS as a first-class check: nuclei in DAST mode scoped to
                                  the xss tag (`-dast -tags xss`). nuclei's ~1400 XSS templates
                                  live under dast/vulnerabilities/xss/ and only fire when -dast is
                                  set AND the URL has a parameter to mutate — without both, the
                                  scan looks falsely clean, so a URL with no '?' is rejected up
                                  front rather than scanned. Records itself in tool_results as
                                  "nuclei-xss". Each finding carries the exact payload, the
                                  parameter, and a response snippet showing the reflection — all
                                  three straight from nuclei's DAST JSON, nothing inferred.
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
                                  the same never-raises/always-a-dict contract by hand. Findings
                                  carry ZAP's own description/solution/reference/url/evidence/
                                  param/cwe/confidence; alerts are collapsed per (pluginId, alert)
                                  with url_count, and ZAP's cweid -1/0 "not applicable" sentinel is
                                  dropped rather than rendered as CWE--1. The pscanrules add-on
                                  (which ZAP needs to return anything at all) is now bootstrapped
                                  by install.sh — see §6.1.
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
    summary.py                   build_summary(scan_id, top_n=10, quiet=False) -> summary dict;
                                  summary_stats(summary). ALSO the shared report vocabulary both
                                  writers read from so the two can never describe the same row
                                  differently: field_display/service_display/cvss_display,
                                  FINDING_TYPE_TOOL (producer, not trigger), _NOT_APPLICABLE
                                  (inapplicable-by-nature vs a genuine gap), finding_identifier/
                                  distinct_identifiers, deduplicate_findings, injection_findings +
                                  INJECTION_FINDING_TYPES, profile_scope_note. See §3.2.
    report_txt.py                generate_txt_report(scan_id, output_path=None) -> path|None.
                                  Blocks: header -> scope note -> severity summary -> top findings
                                  -> Injection & Scripting Vulnerabilities -> detail.
    report_pdf.py                generate_pdf_report(scan_id, output_path=None) -> path|None
                                  (WeasyPrint, lazy-imported, everything HTML-escaped). Same block
                                  order, plus an inline severity-distribution donut SVG on the
                                  cover built from the same by_severity counts — no chart library
                                  and no external asset, so the PDF has no network dependency.
    retention.py                 retain_reports(target, profile, paths, scan_id=,
                                  non_interactive=), report_filename(), prune_reports(),
                                  list_stored_reports(). [NEW] Reports are named per scan
                                  (report_<profile>_<target>_<scan_id>.txt/.pdf) instead of one
                                  fixed report.txt per target, which silently overwrote the
                                  previous scan (this destroyed scan 112's report for real).
                                  History is capped at 5 PER PROFILE+TARGET, so a burst of
                                  quickscans cannot evict the one deepscan report of that host.
                                  The .txt and .pdf of a scan are one unit. Interactive runs are
                                  asked what to drop; non-interactive runs drop the oldest and log
                                  it. Pruning always happens AFTER the new report is on disk.
    completion.py                print_report_summary(target, profile, scan_id, summary,
                                  txt_path=, pdf_path=). [NEW] The "+- REPORT GENERATED -+" block
                                  printed last: severity line, notable_types() ("2 CVEs, 7 ZAP
                                  alerts, 13 discovered paths"), the profile's scope note, and both
                                  paths as OSC 8 terminal hyperlinks over file:// (terminals
                                  without OSC 8 show the plain path, which is why the full path is
                                  always written out rather than hidden behind link text).
    attribution.py               check_finding(finding, profile, ran_tools=None),
                                  check_scan(scan_id, profile, findings). [NEW] The audit layer —
                                  not called during a scan; tests/db_sweep.py runs it. See §3.3.
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
  -> {findings: [{description, reference, test_id, path}], base_url, server, product, version,
      error, skipped}
      # test_id/path are nikto's own per-finding id and URI, "" on tests that print neither
      # ("Apache/2.4.25 appears to be outdated" has no URI). server/product/version come from its
      # Server: banner line; "No banner retrieved" is treated as no banner. A finding with no URI
      # stays without one rather than having the banner recorded as a path.
run_gobuster(target, port=80, use_https=False, wordlist=None)
  -> {discovered_paths: [{path, status_code, size, redirect, url}], base_url,
      wordpress_fingerprinted: bool, error, skipped}
      # size/redirect are gobuster's own [Size: n] / [--> target] and are None where it printed
      # neither — a 0-byte page and an unreported size are different facts.
run_dirb(target, port=80, use_https=False, wordlist=None)
  -> {discovered_paths: [{path, status_code, size, redirect, url}], raw_output, error, skipped}
      # redirect is always None: dirb does not report redirect targets.
run_whatweb(target, port=80, use_https=False)
  -> {technologies: [{name, value}], cms_detected: str|None, raw_output, error, skipped}
run_nuclei(target, port=80, use_https=False, severity=None)
  -> {findings: [{template_id, name, severity, description, matched_at, reference, cve_id}], error, skipped}
run_sqlmap(target, url)
  -> {injectable: bool, findings: [{parameter, method, type, title, payload, techniques}],
      metadata: {dbms, banner, current_db, databases}, raw_output, error, skipped}
      # read-only enumeration only — see §1. A URL with no query string is rejected up front.
run_xss(target, url)
  -> {vulnerable: bool, findings: [{template_id, name, severity, parameter, method, payload,
      endpoint, matched_at, evidence, reference}], raw_output, error, skipped}
      # tool name in tool_results is "nuclei-xss". A URL with no '?' is rejected up front.
run_sslyze(target, port=443)
  -> {findings: [{issue, detail}], raw_output, error, skipped}
run_wpscan(target, port=80, use_https=False, api_token=None)
  -> {findings: [{component, title, reference}], raw_output, error, skipped}
run_zap_baseline(target, port=80, use_https=False)
  -> {findings: [{rule_id, name, status, severity, confidence, description, solution, reference,
      url, param, evidence, attack, method, cwe, url_count}], raw_output, error, skipped}
      # severity derived from ZAP's own Risk rating (High/Medium/Low/Informational) via its REST
      # API, not parsed from zap-baseline.py's plain text. `attack` is "" on every alert of a
      # passive baseline scan; param/evidence are "" on rules that report neither. ZAP emits one
      # alert per matching URL, so alerts are collapsed per (pluginId, alert) and url_count
      # records how many URLs matched. See §1's zap_wrap.py note.

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

build_summary(scan_id, top_n=10, quiet=False)
  -> {scan_id, scan_metadata, total_findings, by_severity, findings, top_findings, error}
summary_stats(summary) -> dict shaped for display.print_summary()
injection_findings(summary) -> [findings whose finding_type is in INJECTION_FINDING_TYPES]
profile_scope_note(profile, labelled=False) -> str   # "" when the profile has no scope caveat
field_display(finding, field) -> str        # inapplicable-by-nature vs a genuine gap
finding_identifier(finding) -> str          # falls back to a truncated description

generate_txt_report(scan_id, output_path=None) -> path str | None   # never raises
generate_pdf_report(scan_id, output_path=None) -> path str | None   # WeasyPrint, lazy-imported
retain_reports(target, profile, paths, scan_id=None, non_interactive=False) -> None  # never raises
print_report_summary(target, profile, scan_id, summary, txt_path=, pdf_path=) -> None

check_finding(finding, profile, ran_tools=None) -> [issue dicts]   # each stamped basis=per-scan|profile
check_scan(scan_id, profile, findings) -> [issue dicts]

record_scan_tools(scan_id, [{tool_name, port, outcome}, ...]) -> None
get_scan_tools_run(scan_id) -> [{tool_name, port, outcome}, ...]   # [] when the table is absent

classify_tool_outcome(result) -> "ran" | "skipped" | "failed"
persist_tool_run(scan_id, tool_results) -> None                    # never raises
count_and_report_tool_failures(target, tool_results) -> int        # counts AND prints/logs each
finalise_reports(target, profile, scan_id, non_interactive=False) -> (txt_path, pdf_path)
web_param_candidates(gobuster_results, dirb_results, ...) -> [(url, port), ...]  # max 6, ranked

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
    stats = {"tools_run": ...,
             "tools_failed": count_and_report_tool_failures(target, tool_results),
             "tools_skipped": ...}
    persist_tool_run(scan_id, tool_results)          # the scan_tools_run record — see §5
    log_scan_end(target, stats)
    txt_path, pdf_path = finalise_reports(target, PROFILE_NAME, scan_id,
                                          non_interactive=non_interactive)
    return (scan_id, txt_path, stats)                # deepscan: (scan_id, txt_path, pdf_path, stats)
```

**All five profiles produce both a .txt and a .pdf now**, through `finalise_reports()`. deepscan's
4-tuple return shape is kept for backward compatibility, not because it is the only profile with a
PDF. `finalise_reports()`'s order is deliberate: generate → prune (only ever *after* the new report
is safely on disk, so a retention failure can never cost the report just waited for) → print the
banner last, so the paths are the final thing on screen.

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
| `quickscan` (default) | nslookup, nmap, nmap -sV -sC, **whatweb + nuclei (critical/high) on the first open web port** | top ports `-T4 -F` | yes | web findings scored; raw port/service persisted unscored (defaults LOW) | TXT + PDF |
| `stealthscan` | nslookup, nmap | curated ~20-port list, `-T2 -Pn --randomize-hosts` | **no** (avoids doubling probe traffic) | none | TXT + PDF |
| `webaudit` | nslookup, nmap, header_check (+CVE lookup on `Server` banner), nikto, gobuster, dirb, whatweb, sslyze (only if `use_https`), banner_grab (non-web ports only), **XSS pass (nuclei `-dast -tags xss`)** | 80/443/8080/8443 | no | web findings + nmap-script findings, per-port CVE lookup | TXT + PDF |
| `deepscan` | nslookup, subfinder, amass, theharvester, nmap (bare `-T4 -p-`, chunked, **no** -sV/-sC), nmap -sV -sC (targeted 2nd pass, this is where nmap-script findings come from now), banner grab (non-web ports only), header_check (+CVE lookup), nikto, gobuster, dirb, whatweb, nuclei, **XSS pass**, ZAP, + conditional **sqlmap/hydra/wpscan/enum4linux** | discovery: all 65535 ports; web module: any detected web port | yes | every finding (CVE + severity + remediation) | TXT + PDF |
| `compliance` | nmap (`--script ssl-enum-ciphers,http-headers`, ports 80/443/8443 only — no DNS, no nikto/gobuster), **sslyze + whatweb** on whichever port(s) `ssl-enum-ciphers` identified as TLS (falls back to 443 if open) | script-targeted (80/443/8443) | no | nmap-script + sslyze + whatweb findings, scored/remediated | TXT + PDF |

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
  **Note the deliberate asymmetry:** this set answers "which config-listed tools does this profile
  call", so it omits `nuclei` — yet webaudit *does* invoke nuclei, in DAST/XSS mode only. That is
  why `attribution.PROFILE_PRODUCERS['webaudit']` includes `nuclei` and why webaudit carries a
  scope note (§3.2). Saying "webaudit does not run nuclei" would have been false.
- `compliance`: `{nmap, sslyze, whatweb}` — **whatweb is now actually called too** (a compliance
  TLS baseline benefits from knowing what's actually serving that endpoint, not just its
  ciphers), targeting the same port(s) sslyze does.
- `deepscan`: aliased directly to `GLOBAL_AVAILABLE_TOOLS` (kept as an alias rather than its own
  copy specifically so it can't drift out of sync the way the others used to).

A drift guard in the test suite asserts every `_WIRED_TOOLS` entry (minus `NON_FINDING_TOOLS`:
nslookup/subfinder/amass/theharvester, which write to the report's recon section and the log, not
to the findings table) appears in `attribution.PROFILE_PRODUCERS`, so the two sets cannot silently
diverge.

### 3.2 Report vocabulary and scope notes (`modules/reporting/summary.py`)

Both report writers read their wording from `summary.py`, because the two files describing the
same row differently is a defect class this project has shipped:

- **A blank cell is ambiguous** ("nothing found" vs "never looked"), so `field_display()` prints a
  qualifier for a field inapplicable *by nature* to that finding type (`_NOT_APPLICABLE` — an
  `sslyze_finding` has no CVE because it is a TLS-configuration finding) and reports an
  applicable-but-unpopulated field as a genuine gap naming the tool that would have filled it
  (`FINDING_TYPE_TOOL` — "not determined by nuclei").
- `finding_identifier()`/`distinct_identifiers()` fall back to a truncated `description` when both
  `service` and `cve_id` are empty (a nuclei/CVE-shaped finding used to render as a bare
  `"unknown"`), and disambiguate identifiers sharing a long common prefix.
- `deduplicate_findings()` collapses rows identical across
  `(finding_type, port, cve_id, severity, description)` — a **safety net**, since the duplicate
  CVE path was fixed at collection time in deepscan (§6.7).
- `INJECTION_FINDING_TYPES`/`injection_findings()` — the single definition of what the reports'
  **Injection & Scripting Vulnerabilities** section shows (`sqlmap_finding`, `xss_finding`).
- `profile_scope_note(profile)` — one source of truth for a profile's scope caveat, read by the
  TXT report, the PDF cover and the CLI banner. Only `webaudit` has one today (see §3.1).

### 3.3 Attribution checks (`modules/reporting/attribution.py`)

Answers "did the tool this finding is credited to actually run?" for every row of every scan. It
exists because 317 unit assertions and a whole-database render sweep all passed the
`reference`-column regression (§0) — that sweep checks crashes, ambiguous cells and duplicate
lines, none of which is the attribution question. Three checks:

1. **Tool plausibility** — classify the row exactly as a report will (`remediation.finding_kind()`,
   the same call the renderer makes) → map to `FINDING_TYPE_PRODUCERS` → check at least one of
   those tools actually ran.
2. **Classifier agreement** — `severity.py` vs `remediation.py` (§0).
3. **Field signature** — the declared type must still fit the columns the row carries. **This is
   the check the next shared column has to get past.**

Check 1 has two bases and stamps every issue with which one it used:
- **`per-scan`** — from the `scan_tools_run` record (§5): catches a tool the profile wires in but
  that was *skipped, failed, or never reached on this run*.
- **`profile`** — the fallback for scans written before that table existed. The honest strongest
  answer available for a historical scan; no scan is ever backfilled with a record it never
  captured.

`_PRODUCER_ALIASES` normalises wrapper names to producer names (`nmap_service_detect` → `nmap`,
`nuclei-xss` → `nuclei`). `UNTRACKED_PRODUCERS` grants `nvd` per-scan when the profile does CVE
enrichment at all — the NVD lookup is an in-process REST call, never a subprocess in
`tool_results`, so without this every stored `cve` row would be flagged the moment its scan gained
a record. **Any future in-process producer needs the same treatment.**

---

## 4. CLI entry point (`aegis.py`)

```
python3 aegis.py [target] [--profile quickscan|stealthscan|webaudit|deepscan|compliance]
                 [-v|--verbose] [--non-interactive] [--version]
```
- `--non-interactive` never prompts: when the stored-report cap (§1's `retention.py`) is reached
  it deletes the oldest report automatically instead of asking. **Implied whenever stdin/stdout is
  not a terminal**, so piped runs, cron and the smoke-test harness get it for free. It is threaded
  through the dispatch call (`dispatch(target, non_interactive=...)`) to `finalise_reports()`.
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
  -- all of the below are nullable and were added by the idempotent migration
  description TEXT,
  remediation TEXT,
  finding_type TEXT,     -- defaults to "cve" if a cve_id is present and no type given
  product TEXT,          -- service_detect.py's {product} field
  parameter TEXT,        -- ┐ injection & scripting evidence: the exact payload sent, what it
  payload TEXT,          -- │ was sent against, and a response snippet proving it. NULL on every
  evidence TEXT,         -- │ other finding shape; only the report's injection section reads
  endpoint TEXT,         -- ┘ them (it filters on finding_type)
  reference TEXT         -- a CITATION for a finding, not evidence of it (nikto's "See:" URL,
                         -- ZAP's reference, wpscan's advisory link) — all three were parsed and
                         -- then dropped at insert because there was no column. Adding it is what
                         -- caused the classifier regression in §0.
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE scan_tools_run (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  tool_name TEXT NOT NULL,   -- as the wrapper stamps it, e.g. "nuclei-xss", "nmap_service_detect"
  port INTEGER,              -- one row per (tool, port) for tools that run per-port
  outcome TEXT NOT NULL,     -- 'ran' | 'skipped' | 'failed', from _common.classify_tool_outcome()
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

`init_db()` runs this migration idempotently (checks `PRAGMA table_info(findings)` first, only
`ALTER TABLE ADD COLUMN`s what's missing, plus `CREATE TABLE IF NOT EXISTS scan_tools_run`) — safe
on every process start, including against the already-tracked `database/aegis.db` with pre-existing
rows (those rows have `NULL` in whichever of these columns didn't exist yet when they were
inserted).

**Why `scan_tools_run` is a separate table, not a JSON column on `scans`:** it matches this
schema's existing convention (findings hang off `scans` by `scan_id` rather than being folded into
a blob), and a per-port tool emits one row per `(tool, port)` — a shape a relational table holds
naturally and a JSON summary would flatten. It is **collected going forward only**: scans that
predate it have no rows, and `attribution.py` falls back to the profile-level check for those. No
historical backfill — same principle as the `cve_id`/`port`/`finding_type` passes: data that was
never captured is not invented.

`outcome` comes from the **same** `tool_results` dicts the summary panel counts, through the same
`classify_tool_outcome()` predicate, so the persisted record cannot drift from the "Tools
run/failed/skipped" numbers the same scan prints.

CRUD: `init_db()`, `insert_scan(target, profile) -> scan_id`, `insert_finding(scan_id, finding)`,
`insert_findings_bulk(scan_id, findings)`, `record_scan_tools(scan_id, records)`,
`get_scan_tools_run(scan_id)` (defensive against the table being absent on a pre-migration
database — returns `[]`), `get_scan_history(target=None)`, `get_findings_for_scan(scan_id)`,
`get_latest_scan(target)`.

Concurrency: every insert function opens a fresh `get_connection()` per call (no shared/global
connection), commits and closes within the call. SQLite's 5s default busy-timeout provides
serialization room for concurrent writers — confirmed safe live (a mid-scan kill left a clean
scan row with zero orphaned finding rows, no corruption to concurrently-completing runs).

---

## 6. Known gaps — intentional, do not "fix" without understanding why first

### 6.1 ZAP's passive-scan rules — handled by `install.sh`, with one trap

ZAP returns near-zero alerts without the "Passive scanner rules" add-on (`pscanrules`, the real
~60-rule detection set); a stock profile has only ~3 trivial built-in rules, so scans complete
cleanly and silently find nothing, forever. `install.sh` now bootstraps this **once, automatically,
on a fresh `~/.ZAP`**, before any scan runs, so it shouldn't come up in normal use.

**If ZAP findings ever drop to zero after previously working, do NOT run `zap.sh -addonupdate` or
`-addoninstall <id>` against that profile.** That specific sequence is the confirmed leading
suspect for how `pscanrules` got silently uninstalled during this project's own development: an
add-on update reconciliation uninstalled the old version while updating unrelated add-ons, then
failed to reinstall the replacement because the marketplace catalog lookup for that id was failing
— with no error logged against it. The recovery is: back up and delete `~/.ZAP`, then re-run
`install.sh` (or its bootstrap block by hand) and let the download run to **full** completion — a
half-written add-on breaks every subsequent ZAP start — shutting the daemon down cleanly via the
API so the new state persists to `add-ons-state.xml`.

### 6.2 The rest

1. **`venv/` needs `zapv2`, and once didn't.** `requirements.txt` had listed
   `python-owasp-zap-v2.4` for a while but the project's own `venv/` never had it installed, so
   every deepscan/webaudit run through `venv/bin/python` silently lost ZAP and reported "tools
   failed: 1" — while the same scan through the system Python was fine. Installed now, and
   `setup.py`'s `REQUIRED_MODULES` verifies `zapv2` (the real end state past the packaging shim,
   which resolves to the renamed `zaproxy` 0.6.0) so a fresh clone is caught at install time
   rather than at scan time.
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
7. **The duplicate-CVE fix is at collection time, deliberately.** deepscan enriches CVEs down two
   independent paths (nmap's detected service product, and the `Server` header's product); on a
   host where both name the same software, both used to insert the same CVE.
   `_findings_from_cves()` now shares a scan-wide `(cve_id, port)` `seen` set across both call
   sites. Keyed on the **CVE id** rather than product+version, because the two paths legitimately
   name the product differently (`"Apache httpd"` vs `"Apache"`), and **per port**, so the same CVE
   on two ports still counts twice. The second NVD lookup is still made — it returned two CVEs the
   first missed, so skipping it would cost real findings.
8. **Two historical attribution mismatches are allowlisted, not rewritten.** `db_sweep.py` reports
   them; nobody has edited old rows to make the audit quiet.
9. **Live coverage of the tools-run record is deepscan + quickscan only.** stealthscan, compliance
   and webaudit were verified to wire `persist_tool_run()` identically and compile cleanly, but
   were not run live in the pass that added it.
10. **ZAP is not reliably interruptible mid-scan.** Two attempts to skip it via SIGINT (an
    out-of-band `kill -INT`, and a real Ctrl+C written to the PTY) did not skip it — ZAP completed
    both times with 9 alerts. Its ~7-minute phase is dominated by daemon startup/shutdown, so an
    interrupt can land outside `zap_wrap`'s poll loop. A property of ZAP, not of the skip
    machinery (unit-tested, and verified live on nuclei).
11. **`whatweb`'s `cms_detected`, `dirb`'s `redirect`, and ZAP's `attack` field are all
    permanently empty-by-nature or unconsumed** — don't read a blank one as a parsing bug. See
    §2's per-tool notes.

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
  (plus `parameter`/`payload`/`evidence`/`endpoint`/`reference` where they apply) directly on the
  finding dict, and persist incrementally as soon as a batch of findings is final (§0) rather than
  holding everything until the very end.
- **A new finding type is a five-place change**, and the checks will tell you if you miss one:
  1. set its `finding_type` at insert time (§0) — never leave a row untyped;
  2. branch on it in `severity.py` **and** `remediation.py` (attribution check 2 fails otherwise);
  3. add it to `summary.FINDING_TYPE_TOOL` naming the tool that **produces** it, and to
     `summary._NOT_APPLICABLE` for every field it can never carry;
  4. add it to `attribution.FINDING_TYPE_PRODUCERS` (and `REQUIRED_FIELDS` only if its identity
     column is genuinely certain);
  5. if it is an injection/scripting class, add it to `summary.INJECTION_FINDING_TYPES`.
- **A new tool that produces findings** needs a `tool` name on its result dict that reaches
  `tool_results` (that is what `scan_tools_run` records), and — if the wrapper name differs from
  the producer name — a mapping in `attribution._PRODUCER_ALIASES` (as `nuclei-xss` → `nuclei`
  does). A producer that never flows through `tool_results` at all needs an entry in
  `UNTRACKED_PRODUCERS` with a reason, or every finding it produces gets flagged.
- **Before you claim a change is done, run the gate:** `python3 tests/db_sweep.py` (every scan in
  the database: crashes, ambiguous cells, duplicate lines, attribution) plus the relevant
  `tests/t_phase*.py`. Both are stdlib-only and exit non-zero on failure.
- Repairing historical data: only from what was actually recorded. If a value was never captured,
  leave it NULL rather than inferring it. Write a dry-run-by-default, revertible standalone script
  under `tools/` that nothing in the scanner calls, and dump before/after before any write — see
  `tools/backfill_nuclei_identity.py`, which deliberately did **not** correct `port` for exactly
  this reason.
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

---

## 10. Verification assets — what to run and what each one proves

```bash
python3 tests/db_sweep.py          # the gate: every scan in the database
python3 tests/db_sweep.py 138 139  # or specific scan ids
python3 tests/t_phase10.py         # (and t_phase2/3/4/8/9) — stdlib assertions, no pytest
python3 tests/t_pty.py             # the skip-key / Ctrl+C paths under a real PTY
```

| Asset | What it actually proves |
|---|---|
| `tests/db_sweep.py` | Renders **every** scan and checks four defect classes: crashes, ambiguous cells, duplicate rendered lines, and attribution (§3.3). Exits 0 only when all pass, so it works as a CI gate. Attribution lives here rather than in its own script deliberately: the regression it catches was missed because that question was nobody's job — run as one command, it cannot be the step someone forgets. |
| `tests/t_phase*.py` | One assertion script per work pass. Stdlib only, exit non-zero on failure. |
| `tests/fixtures/` | Real captured gobuster/nikto/nuclei/ZAP output. Parser changes are tested against what the tools actually print, not against invented strings. |
| `tests/t_pty.py` | The skip-key/Ctrl+C listener is inert on a non-TTY by design, so nothing else can exercise it. |
| `smoke_test/smoke_testN.txt` | The written evidence for pass N — what was run, against what, what it produced, and explicitly **what is still open**. Each pass opens by resolving the previous pass's open items; that is the mechanism this project uses instead of a bug tracker, so read the latest one before starting work. |

**Interpreting an empty result before assuming a bug:** a scan reporting zero open ports against a
healthy host is far more often target-side rate limiting than a scanner defect —
`config.KNOWN_GOOD_TARGETS` exists for exactly this and makes `port_scanner.py` flag loudly when a
host whose open ports are an established fact comes back empty. Check that flag and re-run against
a second target before touching code.
