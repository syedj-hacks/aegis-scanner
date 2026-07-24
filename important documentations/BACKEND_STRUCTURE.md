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
  │     ├─ insert_findings_bulk(scan_id, findings)  [database/db.py]
  │     └─ generate_txt_report() / generate_pdf_report()  [modules/reporting/*.py]
  │
  └─ build_summary(scan_id) -> summary_stats() -> print_summary()   [modules/reporting/summary.py]
```

Every profile orchestrator (`modules/profiles/*.py`) follows the same shape: resolve its
config from `PROFILES[name]`, warn about any configured tool with no wrapper *for that
orchestrator* (see §5.7 — a wrapper existing elsewhere in the codebase doesn't automatically
make it "available" to a given profile), call its modules in sequence, insert findings,
generate a report, return `(scan_id, report_path)` (deepscan returns
`(scan_id, txt_path, pdf_path)`).

---

## 2. Shared foundation (`modules/utils/`)

Every other module is built on these four files. Nothing in `modules/` should call
`subprocess` or `print()` directly — it goes through here.

| File | Purpose |
|---|---|
| `error_handler.py` | `run_tool(target, tool_name, command)` — the **only** sanctioned way to shell out to an external CLI tool. Always returns `{success, stdout, stderr, error, duration}`, never raises. `safe_call(func, *args, target=, label=, **kwargs)` — same contract for pure-Python calls (raw sockets, `requests`) instead of subprocess. All 9 newly-added tool wrappers (§3) go through `run_tool()`, no exceptions. |
| `logger.py` | `get_logger(target)` — one logger per target, writing to `output/<target>/scan_errors.log`. Also: `log_tool_start/success/failure`, `log_finding`, `log_scan_start/end`. |
| `display.py` | All terminal output (Rich-based): `print_banner/panel/phase/info/success/warning/error`, `print_table`, `print_tree`, `scan_progress_bar` (context manager yielding an `advance(label)` callback), `print_summary`. |
| `config.py` | Gitignored — holds `NVD_API_KEY`, `PROFILES` dict, `TOOL_TIMEOUTS`, `CONDITIONAL_TOOLS`, `output_dir()`. Mirrored by `config.example.py` (tracked, no *unique* per-user key) so teammates know what keys exist — **keep both in sync when adding a config key**. `config.example.py` now also auto-loads a gitignored `.env` at repo root and ships a shared default `NVD_API_KEY` (see §7) so CVE lookups work immediately after clone + install, with no manual key step. |

**The one rule that matters most:** nothing in this codebase raises an uncaught exception from
a tool call. `run_tool()`/`safe_call()` catch everything and hand back a structured failure.
This is why a scan against a dead host or missing binary still completes.

---

## 3. Module-by-module map

### `modules/recon/` — Phase 3
| File | Entry point | Tool(s) | Returns |
|---|---|---|---|
| `dns.py` | `resolve_dns(target)` | `nslookup`, socket fallback | resolved IP(s) |
| `subdomain.py` | `enumerate_subdomains(target)` | `subfinder`, `amass` | discovered hostnames |
| `osint.py` | `harvest_osint(target, source="crtsh", limit=500)` | `theharvester` | OSINT hits |

### `modules/scanning/` — Phase 4 (+ new conditional tools)
| File | Entry point | Tool(s) | Returns |
|---|---|---|---|
| `port_scanner.py` | `scan_ports(target, profile=None)` | `nmap -oX -` (profile-aware `nmap_args`) | `open_ports: [{port, protocol, service, state}]`, **`scripts: [{port, protocol, script_id, output}]`** (new — see below) |
| `service_detect.py` | `detect_services(target, ports)` | `nmap -sV` on given ports | `services: [{port, service, version, product}]` |
| `banner.py` | `grab_banners(target, ports)` | raw TCP socket via `safe_call()` | `banners: [{port, banner_text}]` — **now wired into `deepscan`/`webaudit`** (no longer dead code, see §5) |
| `enum4linux_wrap.py` **(new)** | `run_enum4linux(target)` | `enum4linux -a` | `{shares: [{name, type, comment}], users: [{user, rid}], os_info, raw_output, error}` — null-session-disabled is an empty result, not an `error` |
| `hydra_wrap.py` **(new)** | `run_hydra(target, service, port=None, userlist=None, passlist=None)` | `hydra -L -P -t 4 -f` | `{credentials_found: [{port, service, login, password}], raw_output, error}` — deliberately small confirmation-pass wordlists, `-f` stops at first hit |

**`port_scanner.py`'s XML parser now parses `<script>`/`<hostscript>` output** via the new
`_parse_nmap_scripts()` — this used to be discarded (see the old §5 gap list; it's now closed).
Host-level script results carry `port: None`; per-port results carry the port they ran
against. `scan_ports()`'s result dict gained a `scripts` key alongside `open_ports`.

### `modules/web/` — Phase 5 (+ six new tool wrappers)
| File | Entry point | Tool(s) | Returns |
|---|---|---|---|
| `header_check.py` | `check_headers(target, port=80, use_https=False)` | `requests` via `safe_call()` | `missing_headers[]`, `present_headers{}`, `server_banner`, `powered_by` |
| `nikto_wrap.py` | `run_nikto(target, port=80, use_https=False)` | `nikto` | `findings: [{description, reference}]` — nikto exits 0 even on connection failure, so failure is detected from report text; `-maxtime` = `TOOL_TIMEOUTS['nikto'] - 30s` |
| `gobuster_wrap.py` | `run_gobuster(target, port=80, use_https=False, wordlist=None)` | `gobuster dir` | `discovered_paths: [{path, status_code}]`, `wordpress_fingerprinted: bool`; auto-retries with `--exclude-length` on SPA wildcard responses |
| `dirb_wrap.py` **(new)** | `run_dirb(target, port=80, use_https=False, wordlist=None)` | `dirb -S -w -r` | `{discovered_paths: [{path, status_code}], raw_output, error}` — supplementary to gobuster (kept as a separate list, not merged); directory hits normalized to `status_code: 301` |
| `whatweb_wrap.py` **(new)** | `run_whatweb(target, port=80, use_https=False)` | `whatweb -a 3` | `{technologies: [{name, value}], cms_detected: str\|None, raw_output, error}` — `cms_detected` is currently informational only; nothing dispatches on it (deepscan's wpscan trigger still only checks gobuster's `wordpress_fingerprinted`) |
| `nuclei_wrap.py` **(new)** | `run_nuclei(target, port=80, use_https=False, severity=None)` | `nuclei -jsonl -silent` | `{findings: [{template_id, name, severity, description, matched_at, reference}], raw_output, error}` — severity filter comes from `PROFILES[profile]['nuclei_severity']`, passed straight to nuclei's own `-severity` flag; parses `-jsonl` line-by-line, skipping malformed lines |
| `sqlmap_wrap.py` **(new)** | `run_sqlmap(target, url)` | `sqlmap --batch --level 1 --risk 1` | `{injectable: bool, findings: [{parameter, method, type, title}], raw_output, error}` — requires a `?`-bearing URL, refuses otherwise; a *confirmation* pass on an already-flagged candidate, not a crawl |
| `sslyze_wrap.py` **(new)** | `run_sslyze(target, port=443)` | `sslyze --json_out=<tmpfile>` | `{findings: [{issue, detail}], raw_output, error}` — sslyze 5.x only writes JSON to a file, so this wrapper uses `tempfile.mkstemp()` + reads/deletes it in a `finally` block |
| `wpscan_wrap.py` **(new)** | `run_wpscan(target, port=80, use_https=False, api_token=None)` | `wpscan --format json` | `{findings: [{component, title, reference}], raw_output, error}` — `component` labeled `"WordPress core"` / `"plugin: <name>"` / `"theme: <name>"` |
| `zap_wrap.py` **(new)** | `run_zap_baseline(target, port=80, use_https=False)` | `zap-baseline.py -t -I` (passive spider only, no active attack payloads) | `{findings: [{rule_id, name, status, severity}], raw_output, error}` — exit code 0/1/2 is a pass/warn/fail *policy* signal, not a run-failure signal, so non-zero exit with parseable stdout is not treated as a tool failure; `FAIL`→`HIGH`, `WARN`→`MEDIUM` |

### `modules/enrichment/` — Phase 6 (+ new finding kinds)
| File | Entry point | Returns |
|---|---|---|
| `cve_lookup.py` | `lookup_cves(product, version=None, target="nvd", limit=10)` | `cves: [{cve_id, product, version, description, cvss_score, cvss_severity, cvss_version, published_date, references[]}]`. NVD REST v2.0 via `requests`/`safe_call()`; key sent in the `apiKey` header and scrubbed from every error string; rate-limited from `NVD_RATE_LIMIT_*`. `error=None` + empty `cves` means "NVD knows nothing"; `error` set means "the lookup itself broke." |
| `severity.py` | `score_finding(finding)` | shallow copy + `severity` (CRITICAL/HIGH/MEDIUM/LOW), `severity_source` (`cvss`\|`heuristic`), `cvss` mirror key. Never emits `INFO` — everything informational floors to `LOW`. Now also grades `nmap_script` findings by keyword (legacy TLS protocols/export ciphers → HIGH, RC4/3DES/weak/CBC → MEDIUM, else LOW) and treats `technology_fingerprint` (whatweb) the same as `banner`/`fingerprint_header`. |
| `remediation.py` | `get_remediation(finding)` | copy + `remediation` string. Prefers NVD Patch/Vendor-Advisory references over Exploit/Mailing-List ones. Now has dedicated branches for every new finding kind: `nmap_script` (keyed by `script_id`, e.g. `ssl-enum-ciphers`/`http-headers`), `nuclei_finding`, `zap_finding`, `sslyze_finding`, `wpscan_finding`, `sqlmap_finding`, `weak_credentials` (hydra), `smb_share`/`smb_user` (enum4linux). |

All take *any* finding shape from scanning/web and never mutate their input. Finding-kind
detection (`_finding_type`/`_finding_kind`) now branches on `script_id` (nmap scripts) among
its other duck-typed checks.

### `modules/reporting/` — Phase 7
| File | Entry point | Notes |
|---|---|---|
| `summary.py` | `build_summary(scan_id, top_n=10)` → `{scan_id, scan_metadata, total_findings, by_severity, findings, top_findings, error}`, worst-first. Also `summary_stats()` adapting it to `display.print_summary`'s expected shape. | **Trusts the stored `severity` column** (only normalises casing) instead of re-running `score_finding()` — unchanged. `description`/`remediation` now prefer the **stored** DB columns (populated at insert time since the schema migration, §5.4) and only fall back to `_describe()`/`remediation_text()` for pre-migration rows where those columns are `NULL`. |
| `report_txt.py` | `generate_txt_report(scan_id, output_path=None)` | Render/preview/write split into three functions; previews via `print_table`/`print_summary`. |
| `report_pdf.py` | `generate_pdf_report(scan_id, output_path=None)` | WeasyPrint, imported lazily (native Pango/Cairo binding can fail at import time even if the package is pip-installed). All interpolated values are HTML-escaped — service/version/banner strings come from the scanned host and are untrusted input. |

Both writers default to `config.output_dir(target)/report.{txt,pdf}` and return the path or
`None` — they never raise.

### `modules/profiles/` — Phase 8 (orchestration layer)
See §4 below for per-profile behavior. All five follow the identical pattern:
`_warn_unavailable_tools()` → `insert_scan()` → progress-bar-wrapped module calls →
`insert_findings_bulk()` → `generate_txt_report()` (+ `generate_pdf_report()` for deepscan).

- **`compliance.py`**: now turns nmap `--script` results into findings (`_findings_from_scripts()`)
  and wires in `sslyze` against whichever port `ssl-enum-ciphers` identified as TLS-speaking
  (falls back to 443 if open, no scripted port found). `whatweb` is still deliberately *not*
  called here even though a wrapper now exists — logged as skipped, per this profile's own
  docstring (its `PROFILES` entry lists `whatweb` but the orchestrator ignores it by design).
- **`deepscan.py`**: largest change of the four. Scanning phase gained a third step
  (`grab_banners()` — `banner.py` is no longer dead code). Web phase per-port steps went from
  3 to 7: header check, nikto, gobuster, **+ dirb, whatweb, nuclei, ZAP baseline**. All four
  `CONDITIONAL_TOOLS` flags are now real and dispatched (§5.3 closed) via three new detector
  functions (`_detect_injectable_candidates`, `_detect_login_services`,
  `_detect_smb_services`) plus the pre-existing `wordpress_fingerprinted` flag. `sslyze` is
  deliberately **not** run here (reserved for compliance/webaudit).
- **`webaudit.py`**: gained `grab_banners()`, `dirb`, `whatweb` unconditionally, and `sslyze`
  conditionally (`if use_https`). `zaproxy` has a wrapper now but is still deliberately not
  called here (too heavy for webaudit's fast-audit scope) — logged as skipped.
- **`quickscan.py`/`stealth.py`**: **not touched by this change.** `quickscan`'s `PROFILES`
  entry lists `whatweb`/`nuclei` and `compliance`'s lists `sslyze`/`whatweb`, but each
  orchestrator's own `_AVAILABLE_TOOLS` set decides what actually runs — quickscan's and
  stealth's `_AVAILABLE_TOOLS` are still `{nslookup, nmap, nikto, gobuster}` (unchanged), so
  quickscan will keep warning "listed in PROFILES but no wrapper module" for whatweb/nuclei
  even though wrapper modules now exist elsewhere in the codebase. See §5.7 — this is the new
  shape of that gap, not a leftover of the old one.

### `database/db.py`
SQLite at `database/aegis.db`. Two tables — `findings` gained three nullable columns:

```sql
scans (id, target, timestamp, profile)
findings (id, scan_id, port, service, version, cve_id, cvss, severity,
          description, remediation, finding_type)
```

`init_db()` runs an idempotent migration (`PRAGMA table_info(findings)` → `ALTER TABLE ...
ADD COLUMN` for any of `description`/`remediation`/`finding_type` not already present) —
safe to call on every process start. `insert_finding()` derives `finding_type` from
`finding.get("type") or finding.get("finding_type")`, defaulting to `"cve"` when a `cve_id`
is present and no type was given. Old CVE-shaped finding dicts (no `description`/
`remediation`/`type` key) still insert cleanly — those columns are just `NULL`.

CRUD: `init_db()`, `insert_scan(target, profile) -> scan_id`, `insert_finding(scan_id, finding)`,
`insert_findings_bulk(scan_id, findings)`, `get_scan_history(target=None)`,
`get_findings_for_scan(scan_id)`, `get_latest_scan(target)`.

**The `findings` schema is no longer CVE-only-shaped** — see §5.4 (this closes what used to
be a known gap).

### `aegis.py` — CLI entry point
`build_parser()` (argparse), `is_valid_target()` (RFC-1123 hostname regex + `ipaddress`
fallback), `PROFILE_DISPATCH` (name → orchestrator function), `_normalize_result()` (flattens
the 2-tuple/3-tuple return shapes from profiles), `main()`. The try/except around
`dispatch(args.target)` is a last-resort net — every module underneath already degrades
gracefully, so this should only ever catch genuinely unexpected bugs.

**Target and `--profile` are now optional.** `target` is `nargs="?", default=None`;
`--profile` defaults to `None` instead of `"quickscan"`. If the target is omitted entirely
(bare `python3 aegis.py`), the CLI drops into interactive mode:
- `_prompt_target()` — loops `rich.prompt.Prompt.ask()`, validating each answer with
  `is_valid_target()` and re-prompting on invalid input; `Ctrl-C`/EOF exits with code 130.
- `_prompt_profile()` — prints a numbered menu of every `PROFILES` key (via `print_panel`),
  accepts a number or a profile name, defaults to `quickscan` on `Ctrl-C`/EOF/empty input.

If a target *is* supplied on the command line but `--profile` isn't, behavior is unchanged
from before: it silently defaults to `quickscan`, no menu shown. The profile menu only
appears when the target itself was also omitted — full backward compatibility for every
other invocation shape (`python3 aegis.py <target>`, `python3 aegis.py <target> --profile X`).

---

## 4. Profile behavior cheat sheet

| Profile | Tools it actually runs | Ports scanned | Second nmap pass? | CVE/severity enrichment | Report |
|---|---|---|---|---|---|
| `quickscan` | nslookup, nmap, nmap -sV | top ports (`-T4 -F`) | yes (`detect_services`) | no (raw port/service persisted, graded LOW by default) | TXT |
| `stealthscan` | nslookup, nmap | all 65535 (`-T1 -p- --randomize-hosts -Pn`) | **no** (deliberately, to avoid doubling probe traffic) | no | TXT |
| `webaudit` | nslookup, nmap, header check, nikto, gobuster, **dirb, whatweb**, banner grab, **sslyze (if https)** | 80/443/8080/8443 only | no | yes — web findings + nmap-script/sslyze findings + `Server` banner CVE lookup | TXT |
| `deepscan` | nslookup, subfinder, amass, theharvester, nmap, nmap -sV, banner grab, header check, nikto, gobuster, **dirb, whatweb, nuclei, ZAP baseline**, + conditionally **sqlmap, hydra, wpscan, enum4linux** | all ports, web module on any detected web port | yes | yes, on every finding | TXT + PDF |
| `compliance` | nmap (`--script ssl-enum-ciphers,http-headers`), **sslyze** (on the port ssl-enum-ciphers identified) | whatever the script targets | no | yes — nmap-script and sslyze findings are now scored/remediated (previously discarded) | TXT |

Note `compliance` is the only profile that skips DNS resolution — it's simply not in
`PROFILES['compliance']['tools']`, and the orchestrator was written to follow that config
literally rather than assume DNS is always wanted.

`deepscan`'s conditional tools now actually fire (previously only `wpscan` had a theoretical
trigger and even that never dispatched — see §5.3):
- **sqlmap** — dispatches when `_detect_injectable_candidates()` finds a gobuster/dirb-discovered
  path with a script extension (`.php/.asp/.aspx/.jsp/.cgi`) and status 200/301/302; appends
  `?id=1` and hands the URL to `run_sqlmap()`.
- **hydra** — dispatches when `_detect_login_services()` maps an open port's nmap service name
  (ssh/ftp/telnet/ms-wbt-server→rdp) via `_LOGIN_SERVICE_MAP`.
- **wpscan** — dispatches when gobuster's `wordpress_fingerprinted` flag is set (producer
  unchanged; only the dispatch is new).
- **enum4linux** — dispatches unconditionally once `_detect_smb_services()` sees ports 139/445 open.

---

## 5. Known gaps (intentional — read before "fixing")

1. ~~`modules/scanning/banner.py` is dead code.~~ **Closed.** `grab_banners()` is now called
   by both `deepscan` and `webaudit` before their web-module loops.

2. ~~nmap `--script` output isn't parsed.~~ **Closed.** `port_scanner.py`'s XML parser now
   walks `<hostscript>`/`<script>` elements via `_parse_nmap_scripts()`; `scan_ports()`
   returns a `scripts` key. `compliance` turns these into scored findings via
   `_findings_from_scripts()`.

3. ~~`CONDITIONAL_TOOLS` is mostly unreachable.~~ **Closed.** All four flags
   (`sqlmap→injectable_param_found`, `hydra→login_service_found`,
   `wpscan→wordpress_fingerprinted`, `enum4linux→smb_service_found`) now have real producers
   in `deepscan.py` and dispatch to a real wrapper module. See §4 for the dispatch conditions.

4. ~~The `findings` table schema is CVE-shaped, not generic.~~ **Closed.** `description`,
   `remediation`, and `finding_type` columns were added via an in-place migration in
   `database/db.py:init_db()`. Web/nmap-script/new-tool findings are no longer squeezed
   losslessly into the old six-column shape — see §3's `database/db.py` entry.
   `summary.py` now prefers the stored `description`/`remediation` (falling back to the
   derived versions only for pre-migration rows where those columns are `NULL`); it still
   trusts the stored `severity` rather than re-running `score_finding()`, unchanged from before.

5. **Profiles configure tools with no wrapper module in *that profile's own orchestrator* —
   redefined, not fully closed.** All eight previously-unwrapped tools (`sqlmap`, `hydra`,
   `wpscan`, `enum4linux`, `nuclei`, `zaproxy`, `sslyze`, `whatweb`) now have wrapper modules
   somewhere in `modules/`. But:
   - `quickscan.py` and `stealth.py` were **not updated** — their `_AVAILABLE_TOOLS` sets are
     unchanged (`{nslookup, nmap, nikto, gobuster}`), so quickscan still warns "no wrapper
     module" for `whatweb`/`nuclei` (listed in its `PROFILES` entry) even though those
     wrappers now exist elsewhere.
   - `compliance.py` still doesn't call `whatweb` (listed in its `PROFILES` entry) — a
     deliberate scoping choice per its own docstring, not an oversight.
   - `webaudit.py` still doesn't call `zaproxy` (listed in its `PROFILES` entry) —
     deliberate, "too heavy for webaudit's fast-audit scope."
   - `deepscan.py` deliberately doesn't call `sslyze` (reserved for compliance/webaudit).

   Net: "wrapper exists somewhere" and "this profile actually runs it" are still two
   different things, and each profile's own `_AVAILABLE_TOOLS`/docstring is the source of
   truth for which — check that file, not just whether `modules/*/*_wrap.py` exists.

6. **`whatweb`'s `cms_detected` flag has no consumer.** `whatweb_wrap.py` detects
   WordPress/Joomla/Drupal independently of gobuster, but nothing branches on it — deepscan's
   `wpscan` dispatch still only checks gobuster's `wordpress_fingerprinted`. Not wired up
   (yet); a future change could OR the two signals together.

---

## 6. Where things live on disk

```
aegis-scanner/
├── aegis.py                    CLI entry point (target/--profile now optional; interactive mode)
├── setup.py                    post-install bootstrap (deps, dirs, config.py bootstrap, .env key prompt)
├── install.sh                  apt tools + venv + requirements.txt + setup.py
├── requirements.txt            rich, requests, scapy, weasyprint (python-nmap line removed — never imported)
├── .env                        gitignored — AEGIS_NVD_API_KEY overrides the shared default (see §7)
├── database/
│   ├── db.py                   SQLite CRUD (+ description/remediation/finding_type migration)
│   └── aegis.db                the actual database file (tracked — scan history persists across clones)
├── modules/
│   ├── utils/                  logger, error_handler, display, config (+ config.example.py, now with .env loading)
│   ├── recon/                  dns, subdomain, osint
│   ├── scanning/                port_scanner (now parses --script output), service_detect,
│   │                            banner (now wired in), enum4linux_wrap, hydra_wrap
│   ├── web/                    header_check, nikto_wrap, gobuster_wrap, dirb_wrap, whatweb_wrap,
│   │                            nuclei_wrap, sqlmap_wrap, sslyze_wrap, wpscan_wrap, zap_wrap
│   ├── enrichment/              cve_lookup, severity, remediation (new finding kinds wired in)
│   ├── reporting/               summary, report_txt, report_pdf
│   └── profiles/                quickscan, stealth, webaudit, deepscan, compliance
└── output/
    └── <target>/                scan_errors.log, report.txt, report.pdf (per target)
```

---

## 7. Config / env notes

`modules/utils/config.example.py` now:
- Loads a gitignored `.env` at the repo root automatically at import time (`_load_dotenv()`,
  stdlib `KEY=value` parsing, comments/`#` and quote-stripped values; a real shell export
  always wins over `.env`).
- Ships `_DEFAULT_NVD_API_KEY`, a real, working, project-shared NVD API key, used unless
  `AEGIS_NVD_API_KEY` or `NVD_API_KEY` is set in the environment/`.env`. This is a deliberate
  policy change from the file's prior "never commit a real key" stance — the intent is CVE
  lookups work immediately after `git clone` + `./install.sh` with zero manual key setup.
  Anyone who'd rather not share the project's rate-limit quota can still set their own key via
  `.env` or shell env, which takes priority.
- `TOOL_TIMEOUTS` gained `"dirb": 300`.

`setup.py` now has `ensure_local_config()` — copies `config.example.py` → `config.py`
automatically on first run (never overwrites an existing file), so the old "every teammate,
once, `cp config.example.py config.py`" manual step is gone. `ensure_env_key()` no longer
treats a missing personal key as a warning state (the shared default covers it); it only
offers an *optional* personal-key override prompt in interactive shells.

\* `requirements.txt`'s `python-nmap` line has been **removed** — it was never imported
(`port_scanner.py`/`service_detect.py` shell out to the `nmap` binary directly and parse its
XML with the stdlib); `setup.py`'s dependency check already omitted it from
`REQUIRED_MODULES` for the same reason (commit `30ea1bb`), this just cleans up the leftover
requirements line.

---

## 8. Conventions to follow when extending this codebase

- New external tool call → wrap it in `run_tool()` (subprocess) or `safe_call()` (pure Python).
  Never call `subprocess` directly. All 9 new wrapper modules follow this without exception —
  use them as the reference shape for the next one.
- New log line → go through `get_logger(target)`, not `print()`.
- New terminal output → add a `print_*` helper to `display.py` if one doesn't already fit;
  don't call Rich directly from a module.
- New config key → add it to **both** `modules/utils/config.py` and
  `modules/utils/config.example.py`, or the next teammate to clone the repo gets an
  `AttributeError` on a key they never knew existed.
- New module's return dict → always a plain dict, never raise, always degrade gracefully on
  tool failure (empty list/None fields, not an exception).
- New profile → follow the existing five as a template: resolve `PROFILES[name]`, warn on
  unavailable tools, wrap steps in `scan_progress_bar()`, `insert_findings_bulk()`, generate a
  report, return `(scan_id, report_path)`.
- New finding kind → give it a stable duck-typed marker key (e.g. `script_id` for nmap
  scripts), branch on it in `_finding_type()`/`_finding_kind()` (severity.py/remediation.py),
  and set `description`/`remediation`/`type` directly on the finding dict at insert time so it
  isn't lost in the (now-generic, but still not infinitely wide) `findings` schema.
- Wiring a tool into `PROFILES[...]['tools']` does **not** make it run — you must also add it
  to that profile orchestrator's own `_AVAILABLE_TOOLS` set and call its wrapper. See §5.5.
