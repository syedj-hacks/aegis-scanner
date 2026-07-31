# CHECKPOINT — feature/commercial-upgrade (2026-07-31)

**Work paused mid-batch at the user's request. This file is the resume point.**

Branch: `feature/commercial-upgrade` (branched from `dev`)
State: **committed, all tests green, nothing broken.** Safe to shut down.

---

## Where the gate stands

| | baseline (start of batch) | now |
|---|---|---|
| assertions | 416 | **497** |
| failures | 0 | **0** |
| db_sweep crashes / ambiguous cells / attribution issues | 0 / 0 / 0 | **0 / 0 / 0** |
| scans rendered | 186/186 | **186/186** |

Re-run the gate on resume before touching anything:

```
python3 tests/db_sweep.py
for t in t_stealth_guard t_cvss t_phase2 t_phase3 t_phase4 t_phase8 t_phase9 t_phase10 t_pty; do
  python3 tests/$t.py; done
```

Two new test files were added this batch: `tests/t_stealth_guard.py` (15) and
`tests/t_cvss.py` (66).

---

## DONE (7 of 10 items complete, verified)

### Item 1 — `--help`, and the Ctrl+C problem — COMPLETE
The user's report was correct, and it turned out to be **two** defects, not one:

1. **The panel text was wrong.** `Ctrl+C` only skips the running tool while
   `run_tool()`/`safe_call()` are actually executing something. Verified live via
   PTY probes: SIGINT during a subprocess → clean skip, scan continues, exit 0.
   SIGINT in the gaps between tools (CVE enrichment, DB writes, report
   generation) → nothing catches it, propagates to `main()`, **exit -2, scan
   over**. The panel promised the first unconditionally. Text now states the
   condition, and lists the skip key first as the reliable control.

2. **A real skip-flag bug in `run_tool()`.** Its `except KeyboardInterrupt`
   branch set `result["error"]` but never `result["skipped"]`, so
   `classify_tool_outcome()` graded a deliberate Ctrl+C skip as a **tool
   FAILURE** — printed as `[Failed] nikto: skipped by user (Ctrl+C)` and counted
   in the summary panel. This is the same skip-flag bug already fixed three times
   in the wrappers (`zap_wrap`, `header_check`, `banner`); `run_tool()` itself,
   the function `is_user_skip()` was written for, still had it. Fixed, re-probed.

`--help` rewritten beginner-first (profile table generated live from `PROFILES`,
worked examples, keybinds). `COMMANDS.txt` §2 updated and now points at
`--help` as authoritative so the two cannot drift.

### Item 2a — parallel per-port web tools — COMPLETE
`_common.run_web_tools()` pools nikto/gobuster/dirb/whatweb(/sslyze) per port.
Order-preserving (`pool.map`) so finding-row order stays stable run to run.
Exceptions isolated per tool.

**Blocker found and fixed first:** the skip-key listener was explicitly built on
"only one tool is ever running at a time" — it saved/restored termios per
`run_tool()` call. Five concurrent listeners would each restore "the old
settings" captured *after* another had already switched to cbreak, leaving the
terminal with echo off after the scan. Rewritten as a **refcounted process-wide
singleton**, and `_skip_requested` (an Event) became `_skip_press_time` (a
timestamp) so a press means "skip the tools running right now" rather than one
arbitrary member of the batch. Verified by PTY probe: single skip works, batch
skip 5/5, `termios-restored=True`.

Left sequential on purpose: nuclei DAST XSS (needs gobuster/dirb paths), ZAP
(one daemon/session), and all four conditional tools (sqlmap/hydra/wpscan/
enum4linux — no two active-injection tools race a target).

### Item 2b — parallel deepscan chunk sweep — COMPLETE
`MAX_CONCURRENT_NMAP_CHUNKS` (default 3). Runs the 32 chunks in **waves**, not
one big pool, to preserve the stop-on-first-failure contract: a failure lets its
wave finish (those results are real and already paid for) then stops. Merge is
in port-range order, never completion order. Set to 1 for the old behaviour.
Verified with a fake-nmap harness: sequential path byte-identical (7 chunks/7
ports), concurrent keeps 9/9, failure message accurate in both.

### Item 3 — testssl.sh — COMPLETE, verified live
`modules/web/testssl_wrap.py`, wired into `compliance` alongside sslyze (not
replacing it — sslyze inventories what is *accepted*, testssl tests what is
*vulnerable*; neither is derivable from the other). Emits sslyze's `{issue,
detail}` shape into the same TLS finding family rather than a new schema.
Added to `install.sh` (**apt has it: `testssl.sh 3.2.2+dfsg-1`, verified** —
plus a `git clone` → `/opt/testssl.sh` fallback), `GLOBAL_AVAILABLE_TOOLS`,
`TOOL_TIMEOUTS` (900s), and `attribution.py`'s producer maps.

Live-verified against `badssl.com:443` → 2 real findings (BREACH, BEAST).
The JSON id vocabulary was **read off a real 3.2.4 run, not guessed** — an early
draft of the parser walked 4 hardcoded section names and silently dropped the
other 7 (including every `cipherTests` result); it now walks every list-valued
section.

### Item 6 — CVSS v3.1 engine — COMPLETE
`modules/enrichment/cvss.py`. Full spec §7.1 implementation incl. CVSS's
`Roundup` (integer arithmetic — Python's `round()` is off by 0.1 on real
vectors). **Validated against 15 published NVD/spec scores** (BlueKeep 9.8,
PwnKit 7.8, Sweet32 5.9, canonical XSS 6.1, …) — all exact.

Wired into `score_finding()` *before* the heuristic, so severity derives from the
score and the vector travels into the report. `cvss_vector` + `compliance_refs`
columns added to `db.py` (ALTER-TABLE migration, matching the existing pattern);
`cvss_display()` now renders `5.3 (source: cvss) [CVSS:3.1/AV:N/...]`.

Two deliberate calibration decisions, both documented in-module:
- **NVD scores are never overwritten** (asserted in tests).
- Templates were tuned to **agree with the existing heuristic** so this adds an
  auditable number, not a silent re-grading. Verified header-by-header (all 7
  match). The only intentional divergences are `sqlmap_finding` and
  `weak_credentials`, which the heuristic graded **LOW** (no keyword branch
  existed) — a confirmed SQLi graded LOW is the one outcome nobody would defend.
  4 + 3 rows affected in the whole DB.
- Pure-informational types (`banner`, `fingerprint_header`,
  `technology_fingerprint`, ordinary `discovered_path`, …) are in
  `UNSCORED_TYPES` and get **no** score: a defensible "version disclosed" vector
  is 5.3 = MEDIUM, which would have promoted **~5,600 rows** from LOW to MEDIUM
  and buried the real findings.

### Item 7 — compliance mapping — COMPLETE
`modules/enrichment/compliance_map.py` — PCI-DSS v4.0 / ISO 27001:2022 /
NIST 800-53 Rev.5, cited to revision. Gated to `profile == "compliance"`;
every other profile leaves the field NULL and its reports are unchanged.
Unmappable types get NONE rather than a loosely-related control. New
`COMPLIANCE CONTROL MAPPING` section in both `report_txt.py` and `report_pdf.py`,
gated the same way. TEXT round-trip handles commas inside control descriptions.

### Item 10 — per-profile rate limits — COMPLETE
`PROFILE_RATE_LIMITS` + `get_rate_limits()`; wired to gobuster `-t`, dirb `-z`,
nikto `-Pause`, nuclei `-rate-limit`. **Every default reproduces today's
behaviour exactly** — verified: gobuster resolves to the identical argv, and the
other three resolve to `None` = flag omitted entirely. Surfaced in `-v`.

---

## PARTIALLY DONE — resume here

### Item 4 — multi-target (`--targets`) — CODE COMPLETE, NOT YET RUN LIVE
`modules/profiles/multi_target.py` + `--targets` / `--max-concurrent-targets`.
CLI validated (rejects a bad target before scanning anything). **Not yet run
against two real hosts** — that is the next task.

Design decisions already made and implemented (don't re-litigate):
- **Threads, not processes.** Processes would inherit the same TTY stdin and
  each start a skip listener fighting over termios. Checked the two pieces of
  real shared state: `display.console` (one Rich Console — solved by
  `set_multi_target_mode()`, swapping live bars for plain lines) and
  `logger._loggers` (now lock-guarded; the same-target race would double every
  log line).
- Skip key disabled during multi-target runs — no single referent.

### Item 5 — auth — CODE COMPLETE, NOT YET RUN LIVE
`modules/utils/auth.py` + `--auth-cookie` / `--auth-header` + `.env` vars.
Threaded into nikto `-id`, gobuster `-c`/`-H`, nuclei `-H`, sqlmap
`--cookie`/`--headers`, ZAP (replacer rules on the daemon session).
whatweb/dirb are named in `UNAUTHENTICATED_TOOLS` and logged explicitly.
Credential values are never logged — only `describe()` (methods only).

**A DVWA container is already up on `localhost:8082`** (`aegis-dvwa-target`) —
that is the intended live auth test.

### Item 8 — diff — CODE COMPLETE + working, ONE KNOWN BUG
`modules/reporting/diff.py` + `--diff A B` [`--diff-verbose`]. Works on real
data: self-diff of scan 178 = 47 unchanged / 0 churn (correct).

> **KNOWN BUG — FIX THIS FIRST ON RESUME.**
> `python3 aegis.py --diff 137 168` reports 1 NEW + 1 FIXED for what is
> obviously the same finding:
> ```
> NEW:   [999990] OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
> FIXED: [999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
> ```
> nikto listed the same four methods in a different order. `nikto_finding` has
> no identity field in `_IDENTITY_FIELDS`, so it falls back to the description,
> and `_VOLATILE` does not normalise list ordering. This is exactly the phantom
> churn the module docstring warns about — the mechanism is right, the fallback
> is too weak.
> **Likely fix:** for `nikto_finding`, key on the leading `[NNNNNN]` nikto test
> id (already present in the text) instead of the whole description; and/or
> sort comma-separated list fragments before hashing the fallback.

### Item 9 — ZAP container — CODE COMPLETE, IMAGE NOT BUILT
`docker/zap/Dockerfile` + `docker-compose.yml` (validated: `docker-compose
config` passes). `zap_wrap.py` takes `ZAP_HOST`/`ZAP_PORT`; unset = today's
local spawn, unchanged.

Two real bugs already handled in the remote path:
- `zap.core.shutdown()` is now **guarded** — it would have killed a shared
  container daemon after the first port of the first scan.
- Auth replacer rules are **removed** on a shared daemon, or the next scan
  would carry this scan's credentials to a different target.

**Note:** this box has `docker` + `docker-compose` (v1) but **not** the
`docker compose` (v2) plugin — use `docker-compose`. A background
`docker-compose build zap` was started and did not finish before the pause;
just re-run it.

---

## NOT STARTED

- **Docs**: `BACKEND_STRUCTURE.md` §4 profile/tool table (needs testssl row),
  `TUTORIAL.md` (cron pattern for item 8, ZAP container recovery for item 9),
  `WRITEUP.md`.
- **`scripts/scheduled_scan.sh`** (item 8's cron half — `diff.latest_two_scans()`
  already exists to support it).
- **`smoke_test/smoke_test11_*.txt`** — the honest final report.
- **The deepscan before/after timing number.** No live deepscan has been run
  either side of the parallelism change yet, so **there is currently no
  measured speedup to report.** Do not state one until it is measured.

---

## Bug found in passing, NOT yet fixed (out of scope, worth raising)

`severity.py`'s `_PATH_KEYWORDS` grading is **dead code**. Every entry starts
with `/` (`"/admin"`, `"/.git"`), and `_keyword_pattern()` wraps keywords in
`\b...\b`. A `\b` before `/` only matches when the preceding character is a word
character, so `\b/admin\b` never matches `"discovered path /admin (http 301)"`.
**All 5,235 `discovered_path` rows grade LOW regardless of what they expose.**

Confirmed by direct test: `/admin`, `/.git` and `/images` all returned LOW.

Item 6 incidentally restores the *intent* for sensitive paths (the CVSS template
matches on `path` with plain substring containment, so `/.git` → 7.5 HIGH,
`/admin` → 5.3 MEDIUM), but **the underlying regex bug is still there** and still
affects anything else routed through `_match_keywords` with a `/`-prefixed
keyword. Worth fixing properly.

---

## Files changed so far

New: `modules/web/testssl_wrap.py`, `modules/enrichment/cvss.py`,
`modules/enrichment/compliance_map.py`, `modules/reporting/diff.py`,
`modules/utils/auth.py`, `modules/profiles/multi_target.py`,
`tests/t_stealth_guard.py`, `tests/t_cvss.py`, `docker/zap/Dockerfile`,
`docker-compose.yml`.

Modified: `aegis.py`, `install.sh`, `database/db.py`,
`modules/utils/{config,config.example,error_handler,display,logger}.py`,
`modules/profiles/{_common,webaudit,deepscan,compliance,quickscan,stealth}.py`,
`modules/web/{gobuster,dirb,nikto,nuclei,sqlmap,zap}_wrap.py`,
`modules/enrichment/severity.py`,
`modules/reporting/{report_txt,report_pdf,summary,attribution}.py`,
`important documentations/COMMANDS.txt`.

**Not committed to `dev`, not pushed** — as instructed.
