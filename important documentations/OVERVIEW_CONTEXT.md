# Aegis Scanner — Context Reference (attach this file to any Claude session)

Purpose: give Claude full structural knowledge of this repo without pasting source. Attach
this alone before asking for a change. Everything below reflects the actual code, not
aspirational design — if this file and the code disagree, trust the code and flag the drift.

Project: Kali Linux modular vulnerability-assessment CLI. Target in → recon → port scan → web
audit → conditional exploitation checks (sqlmap/hydra/wpscan/enum4linux) → CVE/severity/
remediation enrichment → SQLite persistence → TXT/PDF report out. Fully implemented
end-to-end; no stub modules remain. As of the latest change, all eight tools previously named
in `PROFILES` with no wrapper (`sqlmap`, `hydra`, `wpscan`, `enum4linux`, `nuclei`, `zaproxy`,
`sslyze`, `whatweb`) have wrapper modules — see §3 for which profile actually calls which.

---

## 0. Non-negotiable conventions (violating these is the #1 review flag)

- Never call `subprocess` directly. External CLI tools go through
  `modules/utils/error_handler.py:run_tool(target, tool_name, command)`. Pure-Python I/O
  (sockets, `requests`) goes through `safe_call(func, *args, target=, label=, **kwargs)`.
  Both **always** return a structured dict and **never raise**. All 9 new wrapper modules
  (§3) follow this without exception.
- Never call `print()` in a module. All terminal output goes through
  `modules/utils/display.py` (Rich-based `print_*` helpers, `scan_progress_bar`, `print_table`,
  `print_summary`).
- Never log ad hoc. Use `modules/utils/logger.py:get_logger(target)` (or its
  `log_tool_start/success/failure`, `log_finding`, `log_scan_start/end` wrappers) — writes to
  `output/<target>/scan_errors.log`.
- Every module function returns a plain dict, degrades gracefully on tool failure (empty
  list/`None` fields), and never raises — even on unreachable host / missing binary / timeout.
- New config key → add to **both** `modules/utils/config.py` (gitignored, real values) and
  `modules/utils/config.example.py` (tracked template), or teammates get `AttributeError`.
- `modules/utils/config.py` is gitignored — real per-user overrides go there or in `.env`.
  Note: `config.example.py` (tracked) now ships a shared, working default
  `AEGIS_NVD_API_KEY` fallback — see §7.1, this is a deliberate policy change from "never
  commit a real key," confirm intent before assuming it's still off-limits elsewhere.
- Wiring a tool into `PROFILES[name]['tools']` is not the same as that profile running it —
  each profile orchestrator has its own `_AVAILABLE_TOOLS` set and must explicitly call the
  wrapper. See §3's per-profile notes; `quickscan`/`stealthscan` currently list tools
  (`whatweb`, `nuclei`) they still don't call, despite wrappers existing.

---

## 1. Directory tree (annotated)

```
aegis.py                        CLI entry point (argparse) — target/--profile now optional, see §4
setup.py                        post-install: python/dep check, mkdir output+database,
                                 config.py bootstrap (ensure_local_config), .env key prompt
install.sh                      apt tools (+8 new: whatweb nuclei zaproxy sslyze wpscan
                                 sqlmap hydra enum4linux) + venv + pip install + setup.py
requirements.txt                rich, requests, scapy, weasyprint (python-nmap line removed)
.env                             gitignored — AEGIS_NVD_API_KEY=... (overrides shared default)
database/
  db.py                          SQLite CRUD, schema in §5 (now has description/remediation/finding_type)
  aegis.db                       tracked db file — scan history persists across clones
modules/
  utils/
    error_handler.py             run_tool(), safe_call() — the only I/O gateway
    logger.py                    get_logger(), log_* helpers
    display.py                   all Rich terminal output
    config.py                    gitignored: NVD_API_KEY, PROFILES, TOOL_TIMEOUTS, CONDITIONAL_TOOLS
    config.example.py            tracked template; now auto-loads .env + ships shared NVD key
  recon/
    dns.py                       resolve_dns(target) -> dns result dict
    subdomain.py                 enumerate_subdomains(target) -> subdomains dict
    osint.py                     harvest_osint(target, source="crtsh", limit=500) -> osint dict
  scanning/
    port_scanner.py              scan_ports(target, profile=None) -> {open_ports:[...], scripts:[...]}
    service_detect.py            detect_services(target, ports) -> {services:[...]}
    banner.py                    grab_banners(target, ports) -> {banners:[...]}  NOW WIRED (deepscan, webaudit)
    enum4linux_wrap.py           run_enum4linux(target) -> {shares:[...], users:[...], os_info, error}  [NEW]
    hydra_wrap.py                run_hydra(target, service, port=None, userlist=None, passlist=None)
                                  -> {credentials_found:[...], error}  [NEW]
  web/
    header_check.py              check_headers(target, port=80, use_https=False) -> header dict
    nikto_wrap.py                run_nikto(target, port=80, use_https=False) -> {findings:[...]}
    gobuster_wrap.py             run_gobuster(target, port=80, use_https=False, wordlist=None) -> {discovered_paths:[...], wordpress_fingerprinted}
    dirb_wrap.py                 run_dirb(target, port=80, use_https=False, wordlist=None)
                                  -> {discovered_paths:[...], error}  [NEW, supplements gobuster]
    whatweb_wrap.py               run_whatweb(target, port=80, use_https=False)
                                  -> {technologies:[...], cms_detected, error}  [NEW]
    nuclei_wrap.py                run_nuclei(target, port=80, use_https=False, severity=None)
                                  -> {findings:[...], error}  [NEW]
    sqlmap_wrap.py                run_sqlmap(target, url) -> {injectable: bool, findings:[...], error}  [NEW]
    sslyze_wrap.py                run_sslyze(target, port=443) -> {findings:[...], error}  [NEW]
    wpscan_wrap.py                run_wpscan(target, port=80, use_https=False, api_token=None)
                                  -> {findings:[...], error}  [NEW]
    zap_wrap.py                   run_zap_baseline(target, port=80, use_https=False)
                                  -> {findings:[...], error}  [NEW, passive baseline only]
  enrichment/
    cve_lookup.py                lookup_cves(product, version=None, target="nvd", limit=10) -> {cves:[...], error}
    severity.py                  score_finding(finding) -> finding copy + severity/severity_source/cvss
                                  (now also grades nmap_script + technology_fingerprint kinds)
    remediation.py                get_remediation(finding) -> finding copy + remediation
                                  (now has branches for every new finding kind, see §3)
  reporting/
    summary.py                   build_summary(scan_id, top_n=10) -> summary dict; summary_stats(summary)
                                  (description/remediation now prefer stored DB columns)
    report_txt.py                generate_txt_report(scan_id, output_path=None) -> path|None
    report_pdf.py                generate_pdf_report(scan_id, output_path=None) -> path|None (WeasyPrint)
  profiles/                      orchestrators, one per scan profile — see §3
    quickscan.py   run_quickscan(target)   -> (scan_id, report_path)   [unchanged this round]
    stealth.py     run_stealthscan(target) -> (scan_id, report_path)   [unchanged this round]
    webaudit.py    run_webaudit(target)    -> (scan_id, report_path)   [+dirb, whatweb, sslyze, banners]
    deepscan.py    run_deepscan(target)    -> (scan_id, txt_path, pdf_path)  [largest change, see §3]
    compliance.py  run_compliance(target)  -> (scan_id, report_path)   [+nmap-script findings, sslyze]
output/<target>/                scan_errors.log, report.txt, report.pdf (created per target)
important documentations/       human + AI docs (this file, WRITEUP.md, TUTORIAL.md, COMMANDS.txt, BACKEND_STRUCTURE.md)
```

---

## 2. Function contracts (return shapes)

```
resolve_dns(target) -> {success, resolved_ips: [...], error, ...}
enumerate_subdomains(target) -> {success, subdomains: [...], error, ...}
harvest_osint(target, source="crtsh", limit=500) -> {success, hosts/emails/..., error, ...}

scan_ports(target, profile=None)
  -> {open_ports: [{port, protocol, service, state}],
      scripts: [{port, protocol, script_id, output}],   # NEW — was discarded before
      profile_used, raw_output, error}
detect_services(target, ports) -> {services: [{port, service, version, product}], error}
grab_banners(target, ports) -> {banners: [{port, banner_text}], error}   # now called by deepscan + webaudit
run_enum4linux(target)
  -> {shares: [{name, type, comment}], users: [{user, rid}], os_info, raw_output, error}  # NEW
run_hydra(target, service, port=None, userlist=None, passlist=None)
  -> {credentials_found: [{port, service, login, password}], raw_output, error}  # NEW

check_headers(target, port=80, use_https=False)
  -> {missing_headers: [...], present_headers: {...}, server_banner, powered_by, error}
run_nikto(target, port=80, use_https=False)
  -> {findings: [{description, reference}], error}
run_gobuster(target, port=80, use_https=False, wordlist=None)
  -> {discovered_paths: [{path, status_code}], wordpress_fingerprinted: bool, error}
run_dirb(target, port=80, use_https=False, wordlist=None)
  -> {discovered_paths: [{path, status_code}], raw_output, error}   # NEW, separate list from gobuster's
run_whatweb(target, port=80, use_https=False)
  -> {technologies: [{name, value}], cms_detected: str|None, raw_output, error}   # NEW
run_nuclei(target, port=80, use_https=False, severity=None)
  -> {findings: [{template_id, name, severity, description, matched_at, reference}], error}  # NEW
run_sqlmap(target, url)
  -> {injectable: bool, findings: [{parameter, method, type, title}], error}   # NEW, requires ?-URL
run_sslyze(target, port=443)
  -> {findings: [{issue, detail}], raw_output, error}   # NEW, JSON read from a tempfile
run_wpscan(target, port=80, use_https=False, api_token=None)
  -> {findings: [{component, title, reference}], raw_output, error}   # NEW
run_zap_baseline(target, port=80, use_https=False)
  -> {findings: [{rule_id, name, status, severity}], raw_output, error}   # NEW, passive/baseline only

lookup_cves(product, version=None, target="nvd", limit=10)
  -> {cves: [{cve_id, product, version, description, cvss_score, cvss_severity,
              cvss_version, published_date, references: [{url, source, tags}]}], error}
  # error=None + empty cves == "NVD knows nothing"; error set == "lookup itself broke"

score_finding(finding) -> shallow copy of finding + {severity: CRITICAL|HIGH|MEDIUM|LOW,
              severity_source: "cvss"|"heuristic", cvss}
  # 4 tiers only, no INFO — informational findings floor to LOW
  # now also grades: nmap_script (by keyword in script output), technology_fingerprint (whatweb)

get_remediation(finding) -> copy of finding + {remediation: str}
  # prefers NVD Patch/Vendor-Advisory refs over Exploit/Mailing-List
  # now has dedicated text for: nmap_script, nuclei_finding, zap_finding, sslyze_finding,
  # wpscan_finding, sqlmap_finding, weak_credentials (hydra), smb_share/smb_user (enum4linux)

build_summary(scan_id, top_n=10)
  -> {scan_id, scan_metadata, total_findings, by_severity, findings, top_findings, error}
  # worst-first; TRUSTS stored `severity` column (unchanged), but description/remediation now
  # prefer the STORED columns over re-derived text (see §6.4) — only pre-migration rows
  # (those columns NULL) fall back to the old _describe()/remediation_text() derivation
summary_stats(summary) -> dict shaped for display.print_summary()

generate_txt_report(scan_id, output_path=None) -> path str | None   # never raises
generate_pdf_report(scan_id, output_path=None) -> path str | None   # WeasyPrint, lazy-imported
```

All five profile orchestrators share this internal skeleton:

```
run_<profile>(target):
    log_scan_start(target, PROFILE_NAME)
    profile_cfg = get_profile(PROFILE_NAME)         # from config.PROFILES
    _warn_unavailable_tools(...)                     # logs+warns per THIS orchestrator's
                                                       # _AVAILABLE_TOOLS set — a wrapper module
                                                       # existing elsewhere doesn't suppress this
    scan_id = insert_scan(target, PROFILE_NAME)
    ... call recon/scanning/web/enrichment modules, wrapped in scan_progress_bar(...) ...
    insert_findings_bulk(scan_id, findings)
    log_scan_end(target, stats)
    report_path = generate_txt_report(scan_id)       # + generate_pdf_report() for deepscan only
    return (scan_id, report_path)                    # deepscan: (scan_id, txt_path, pdf_path)
```

`deepscan.py`'s `_check_conditional_tools()` signature changed:
`_check_conditional_tools(target, flags, context) -> (raw_findings, tool_results)`
(previously `(target, flags) -> None`, pure logging). `context` carries whatever the three new
detector functions produced (`injectable_url`, `login_service`, `wordpress_port`, plus the
unconditional `smb_service_found` check) so the right wrapper gets called with the right
argument, not just a "condition met" log line.

---

## 3. Profile behavior matrix

| Profile | Tools called | Ports | 2nd nmap `-sV` pass? | Enrichment | Report |
|---|---|---|---|---|---|
| `quickscan` (default) | nslookup, nmap, nmap -sV | top ports `-T4 -F` | yes | none (raw persisted, defaults LOW) | TXT |
| `stealthscan` | nslookup, nmap | all 65535, `-T1 -p- --randomize-hosts -Pn` | **no** (avoids doubling probe traffic) | none | TXT |
| `webaudit` | nslookup, nmap, header_check, nikto, gobuster, **dirb, whatweb**, banner grab, **sslyze (only if `use_https`)** | 80/443/8080/8443 | no | web findings + nmap-script/sslyze findings + `Server` banner CVE lookup | TXT |
| `deepscan` | nslookup, subfinder, amass, theharvester, nmap, nmap -sV, banner grab, header_check, nikto, gobuster, **dirb, whatweb, nuclei, ZAP baseline**, + conditional **sqlmap/hydra/wpscan/enum4linux** | all ports; web module on any detected web port | yes | every finding (CVE + severity + remediation) | TXT + PDF |
| `compliance` | nmap, `--script ssl-enum-ciphers,http-headers`, **sslyze** (port sourced from the script's own TLS-port finding, else 443 if open) | script-targeted | no | **yes now** — nmap-script + sslyze findings scored/remediated (previously discarded entirely) | TXT |

`compliance` is the only profile with no DNS step — `"nslookup"` simply isn't in its
`PROFILES['compliance']['tools']` list, and the orchestrator follows that config literally.
`compliance` still does not call `whatweb` even though it's listed in `PROFILES['compliance']`
— deliberate scoping per its own docstring, not an oversight; same pattern as `webaudit` not
calling `zaproxy` and `deepscan` not calling `sslyze`.

`_AVAILABLE_TOOLS` per orchestrator (this is what actually gates a tool, not just being
listed in `PROFILES`):
- `quickscan`/`stealth` (unchanged): `{nslookup, nmap, nikto, gobuster}` — still warns on
  `whatweb`/`nuclei` from `PROFILES['quickscan']['tools']` despite those wrappers now existing.
- `webaudit`: `{nslookup, nmap, nikto, gobuster, dirb, whatweb, sslyze, banner_grab}`.
- `deepscan`: the above plus `{subfinder, amass, theharvester, nuclei, zaproxy, wpscan, sqlmap, hydra, enum4linux}`.
- `compliance`: `{nmap, sslyze}`.

`deepscan`'s `CONDITIONAL_TOOLS` dispatch conditions (all four now live, previously 3 of 4
were unreachable):
- **sqlmap** — `_detect_injectable_candidates()` finds a gobuster/dirb path with a script
  extension (`.php/.asp/.aspx/.jsp/.cgi`) at status 200/301/302, appends `?id=1`.
- **hydra** — `_detect_login_services()` maps an open port's service name
  (ssh/ftp/telnet/ms-wbt-server→rdp) via `_LOGIN_SERVICE_MAP`.
- **wpscan** — gobuster's pre-existing `wordpress_fingerprinted` flag (dispatch is new, flag
  producer is not).
- **enum4linux** — `_detect_smb_services()` sees ports 139/445 open; dispatches unconditionally
  once true.

---

## 4. CLI entry point (`aegis.py`)

```
python3 aegis.py [target] [--profile quickscan|stealthscan|webaudit|deepscan|compliance] [-v] [--version]
```
- `target` and `--profile` are now **optional**. Omitting the target entirely (bare
  `python3 aegis.py`) triggers interactive mode: `_prompt_target()` (validated,
  re-prompting loop) then, if `--profile` was also omitted, `_prompt_profile()` (numbered
  menu of `PROFILES`, accepts number or name, defaults `quickscan`).
- `python3 aegis.py <target>` with no `--profile` is **unchanged** — silently defaults to
  `quickscan`, no menu. The menu only appears when target was *also* omitted.
- `is_valid_target(target)` — RFC-1123 hostname regex or `ipaddress.ip_address()`; rejects
  invalid input before anything runs (used both for CLI validation and inside
  `_prompt_target()`'s re-prompt loop).
- `PROFILE_DISPATCH` dict maps profile name → orchestrator function.
- `_normalize_result(result)` flattens the 2-tuple/3-tuple profile return shapes to
  `(scan_id, [report_paths...])`.
- Flow: (interactive prompts if needed) → validate target → `init_db()` → dispatch →
  `build_summary()` → `summary_stats()` → print final panel + summary table. The outer
  try/except around dispatch is a last-resort net — every module underneath already degrades
  gracefully, so anything caught there is a real bug, not expected tool failure.

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
  description TEXT,     -- NEW, nullable, migrated in via ALTER TABLE
  remediation TEXT,      -- NEW, nullable
  finding_type TEXT,     -- NEW, nullable; defaults to "cve" if a cve_id is present and no type given
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

`init_db()` runs this migration idempotently (checks `PRAGMA table_info(findings)` first,
only `ALTER TABLE ADD COLUMN`s what's missing) — safe on every process start, including
against the already-tracked `database/aegis.db` with pre-existing rows (those rows just have
`NULL` in the three new columns).

CRUD: `init_db()`, `insert_scan(target, profile) -> scan_id`, `insert_finding(scan_id, finding)`,
`insert_findings_bulk(scan_id, findings)`, `get_scan_history(target=None)`,
`get_findings_for_scan(scan_id)`, `get_latest_scan(target)`.

**Schema is no longer CVE-only-shaped** — see §6.4. Non-CVE findings (nikto text, missing
headers, nmap-script output, nuclei/zap/sslyze/wpscan/sqlmap/hydra/enum4linux results) now
carry their own `description`/`remediation`/`finding_type` instead of being squeezed into
`port/service/version/cve_id/cvss/severity` alone.

---

## 6. Known gaps — intentional, do not "fix" without understanding why first

Most of the gaps this file used to list here are now closed. What's left:

1. **`quickscan`/`stealth` weren't updated to use the new wrappers.** Their
   `_AVAILABLE_TOOLS` sets are unchanged; `quickscan`'s `PROFILES` entry lists `whatweb`/
   `nuclei` but the orchestrator still logs them as having "no wrapper module" — true from
   *this orchestrator's* point of view even though the wrapper file now exists under
   `modules/web/`. If asked to fix this, it means adding `whatweb`/`nuclei` calls to
   `quickscan.py`'s pipeline and updating its `_AVAILABLE_TOOLS` — a real, scoped feature
   request, not a bug report.
2. **Some profile/tool pairings are deliberately still unwired**: `compliance` doesn't call
   `whatweb`, `webaudit` doesn't call `zaproxy`, `deepscan` doesn't call `sslyze` — each is a
   documented scoping decision in that profile's own file, not an oversight. Don't "complete"
   these without checking the docstring reasoning first.
3. **`whatweb`'s `cms_detected` flag has no consumer.** Nothing ORs it with gobuster's
   `wordpress_fingerprinted` before the `wpscan` conditional check fires — only gobuster's
   flag currently triggers `wpscan`.
4. **`requirements.txt` no longer lists `python-nmap`** (removed as part of this change,
   confirming it was genuinely unused) — `port_scanner.py`/`service_detect.py` shell out to
   the `nmap` binary and parse XML with the stdlib, unchanged.

Previously-documented gaps now fully closed (do not reintroduce without a reason): dead
`banner.py`, discarded nmap `--script` output, unreachable `CONDITIONAL_TOOLS`, CVE-only
`findings` schema. See git history / BACKEND_STRUCTURE.md §5 if you need the "why" behind how
each was closed.

---

## 7. Config / env keys

| Key | Where | Purpose |
|---|---|---|
| `AEGIS_NVD_API_KEY` (or legacy `NVD_API_KEY`) | `.env` or shell env, overriding `config.example.py`'s shared default | NVD rate limit 5→50 req/30s. `config.example.py` now ships a working shared default key (`_DEFAULT_NVD_API_KEY`) so this is optional — set it only if you want your own quota instead of the shared one. |
| `PROFILES` | `config.py` | per-profile `tools` list + `nmap_args` (+ `nuclei_severity`/`gobuster_wordlist` where relevant). Listing a tool here does **not** make a profile run it — see §0 and §3's `_AVAILABLE_TOOLS` note. |
| `TOOL_TIMEOUTS` | `config.py` | per-tool timeout seconds, `get_timeout(tool_name)` falls back to `"default"` (120s). Gained `"dirb": 300`. |
| `CONDITIONAL_TOOLS` | `config.py` | tool → flag-name mapping (see §3) — all four now have real producers + dispatch, unlike before. |
| `MAX_THREADS` | `config.py` | = 10, not currently referenced by any module found in this map — verify before relying on it |
| `OUTPUT_ROOT` | `config.py` | `"output"`; `output_dir(target)` creates+returns `output/<target>/` |

### 7.1 `.env` auto-loading (new)

`config.example.py` now parses a gitignored `.env` at the repo root automatically at import
time (`_load_dotenv()`), populating `os.environ` for any key not already exported — no extra
dependency, stdlib only. A real shell `export` always takes priority over `.env`. This is why
`setup.py`'s key prompt is now optional/non-blocking: the shared default key means CVE lookups
work even if a user skips the prompt or runs non-interactively.

---

## 8. When asked to implement a change here

- Identify which layer owns it (recon/scanning/web/enrichment/reporting/profiles/utils) and
  match that layer's existing function signature style (target-first, dict-return, no raise).
- If it's a new external tool: add a wrapper module following the `run_tool()` pattern (use
  any of the 9 new wrapper modules — e.g. `modules/web/nuclei_wrap.py` — as a template), add
  its timeout to `TOOL_TIMEOUTS`, add it to the relevant profile's `_AVAILABLE_TOOLS` set so
  `_warn_unavailable_tools()` stops flagging it, and wire the profile orchestrator to call it.
  Remember: adding it to `PROFILES[...]['tools']` alone does nothing.
- If it touches findings persistence: the schema is no longer CVE-only-shaped (§5) —
  `description`/`remediation`/`finding_type` columns exist now. Set them directly on the
  finding dict rather than relying purely on `summary.py`'s derived-text fallback.
- If it's config: update `config.py` **and** `config.example.py` together.
- Don't reintroduce `print()`/raw `subprocess`/raw logging — grep for the existing helper first.
- Before assuming a tool "isn't wired in yet," check the specific profile's own
  `_AVAILABLE_TOOLS` set and docstring — several tool/profile pairings are deliberately
  unwired (see §6.2), not oversights.
