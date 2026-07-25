# Aegis Scanner — Project Writeup

**Cyber404 Academy 2026 — team project**
Branch under review: `dev`. This round of work hardened the interrupt/reliability model (a
skip-current-tool keybind, a saner Ctrl+C, chunked full-port nmap sweeps that survive a slow
target, per-port incremental result persistence, wall-clock budgets on the web-audit loops),
closed the last "listed in config but never actually run" gaps in `quickscan`/`compliance`,
root-caused and fixed a handful of live-reproduced bugs (dirb's connection-threshold abort, a
"unknown" fallback in reports, a skip-vs-failure miscount across every tool wrapper, a
substring-match false positive in severity scoring, a same-vendor/wrong-product false positive
in CVE lookups), and rewrote the ZAP wrapper to drive ZAP's own daemon API directly instead of a
bundled script Kali's apt package never actually ships.

---

## 1. What it is

Aegis Scanner is a modular vulnerability-assessment framework for Kali Linux. You give it a
target (hostname or IP, or nothing — you'll be prompted interactively) and a **profile**, and
it runs a pipeline of recon → scanning → web-auditing → conditional exploitation checks →
enrichment → reporting, writing results to a local SQLite database and a TXT/PDF report per
target.

It is not a single tool — it's an orchestration layer over existing Kali tools (`nmap`,
`nikto`, `gobuster`, `dirb`, `whatweb`, `nuclei`, `sqlmap`, `hydra`, `wpscan`, `enum4linux`,
`sslyze`, ZAP, `nslookup`, `subfinder`, `amass`, `theHarvester`) plus a homegrown NVD CVE
lookup, severity grading, and remediation-advice engine.

## 2. Why it's built this way

The project was split across teammates by layer ("Member B — recon layer" appears in
docstrings), so the codebase is organized as strict **phases**, each phase owning one directory
under `modules/`, and each module in a phase following the same shape:

1. Take a target (and sometimes ports/services) as input.
2. Call out to a real CLI tool via `run_tool()` (subprocess wrapper — see
   [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md)), or use `safe_call()` for pure-Python calls
   (raw sockets, `requests`).
3. Parse that tool's raw output into a small, predictable dict shape.
4. Never raise — always return a structured result, even on total failure or a user interrupt.

That "never raise, always degrade" rule is the single most important convention in the
codebase, and it's why a scan against an unreachable host, a target with no open ports, a
machine missing half the Kali toolset, or an operator hitting Ctrl+C mid-scan all still complete
and produce a report instead of crashing.

## 3. What's actually implemented (as of this writeup)

Every phase described in the profile table below is implemented end-to-end and wired into
`aegis.py`. There is no phase left as an empty stub, and every tool named anywhere in a
`PROFILES` entry has a real wrapper module. See
[BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) for the full module-by-module map, including the
handful of gaps that remain by design (mainly: `webaudit` deliberately never calls `zaproxy`,
`deepscan` deliberately never calls `sslyze`, and ZAP's passive-scanner add-on needs a one-time
manual install to produce non-trivial findings).

| Phase | Directory | Status |
|---|---|---|
| Foundation | `modules/utils/` | Done — logger, error handler (Popen-based, timeout + skip-keybind + Ctrl+C handling), config (+ `.env` auto-load), display |
| Tool-availability model | `modules/profiles/_common.py` | Done — shared, codebase-wide "does a wrapper exist / does this profile call it" check, replacing five separate hand-rolled copies |
| Recon | `modules/recon/` | Done — DNS, subdomain enum, OSINT |
| Scanning | `modules/scanning/` | Done — port scan (chunked full-range sweeps, `--script` parsing), service detect (`-sV -sC` combined), banner grabber, enum4linux, hydra |
| Web | `modules/web/` | Done — header audit, Nikto, gobuster, dirb, whatweb, nuclei, sqlmap, sslyze, wpscan, ZAP (now via its own daemon API) |
| Enrichment | `modules/enrichment/` | Done — CVE lookup (NVD, with product-disambiguation), severity scoring (word-boundary keyword matching), remediation text |
| Reporting | `modules/reporting/` | Done — summary builder, TXT report, PDF report; no more "unknown" fallback for CVE-shaped findings with no service field |
| Profiles | `modules/profiles/` | Done — quickscan (now runs whatweb+nuclei), stealthscan (curated port list), webaudit, deepscan, compliance (now runs whatweb too); all persist findings incrementally, all return real tool-run stats |
| CLI | `aegis.py` | Done — argparse entry point (target/profile optional, interactive prompt mode), dispatch table, final summary with real (not always-zero) tool counts |
| Install | `install.sh`, `setup.py` | Done — apt tool install, venv, dependency check, automatic `config.py` bootstrap, `.env` key prompt, nuclei/ZAP fallback checks |

## 4. The five scan profiles

| Profile | What it actually runs | Report |
|---|---|---|
| `quickscan` (default) | DNS resolve → fast top-port nmap (`-T4 -F`) → service detection → whatweb + high-severity nuclei on the first open web port | TXT |
| `stealthscan` | DNS resolve → quiet `-T2` scan of a fixed ~20-port list (web/mail/DB/remote-admin basics) — **no** second service-detect pass, keeps footprint minimal | TXT |
| `webaudit` | DNS resolve → nmap scoped to web ports (80/443/8080/8443) → banner grab on non-web ports → header audit + Nikto + gobuster + dirb + whatweb (+ sslyze on HTTPS ports) on each open web port, wall-clock-bounded to 30 min → CVE lookup on the `Server` banner + nmap-script findings | TXT |
| `deepscan` | Everything: DNS + subdomain enum + OSINT → chunked full-port nmap discovery (no -sV/-sC) + a targeted `-sV -sC` pass (this is also where nmap-script findings come from) + banner grab on non-web ports → web module (header/nikto/gobuster/dirb/whatweb/nuclei/ZAP) on any discovered web port, wall-clock-bounded to 1 hour → conditional sqlmap/hydra/wpscan/enum4linux where their trigger conditions are detected → CVE lookup + severity + remediation on every finding | TXT + PDF |
| `compliance` | nmap with `--script ssl-enum-ciphers,http-headers` (no DNS — not in this profile's tool list) → sslyze + whatweb on the TLS port(s) the script identified; script/sslyze/whatweb results are scored and remediated | TXT |

Full command reference: [COMMANDS.txt](COMMANDS.txt).
Step-by-step walkthrough: [TUTORIAL.md](TUTORIAL.md).
Internals / data flow / known gaps: [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md).

## 5. Design decisions worth knowing about

- **`config.py` is gitignored**, generated automatically by `setup.py` from
  `modules/utils/config.example.py` on first run. That template auto-loads a gitignored `.env`
  and ships a shared, working default NVD API key — CVE lookups work immediately after clone +
  install with zero manual setup. A personal key in `.env`/shell env still overrides it.
- **A profile only runs tools it has explicitly wired in — and now there's one honest,
  shared way to say so.** All five profile orchestrators use
  `modules/profiles/_common.py:warn_unavailable_tools()` instead of five separate, easily-stale
  copies. It distinguishes two genuinely different situations: a tool with a real wrapper
  elsewhere that this profile just doesn't call (an informational note — by design, e.g.
  `webaudit` never calling `zaproxy`) versus a tool with no wrapper anywhere at all (a real
  warning — there currently are none of these left). `quickscan` and `compliance` both picked
  up new tool calls this round (`whatweb`+`nuclei`, and `whatweb` respectively) that used to be
  listed in their config but never actually run.
- **Findings are persisted incrementally, not in one batch at the end.** Every profile inserts
  each scanning phase's or each port's findings into the database as soon as they're final,
  instead of holding everything in memory until the whole scan finishes. A timeout, a skipped
  tool, a wall-clock budget cutoff, or a crash partway through now costs only whatever hadn't
  been found yet — not the entire run's results.
- **`webaudit`/`deepscan`'s per-port web-audit loops are wall-clock-bounded** (30 min / 1 hour).
  A single tool call already had its own timeout, but "6-7 tools per open web port, repeated for
  every open web port" had no ceiling of its own — a target with several open web ports could
  legitimately run for well over an hour even with every individual tool call behaving. Once the
  budget is hit, the loop stops starting new ports and finishes with whatever it already has.
- **A full 65535-port nmap sweep is chunked into 32 sequential sub-scans**, each its own
  complete, independently timed-out invocation. A killed nmap process does not reliably flush a
  partial `-oX` document (verified empirically, not assumed), so a chunk boundary — not
  "wherever the process happened to be" — is the real unit of recoverable work. Only `deepscan`'s
  discovery pass still sweeps the full range; `stealthscan` was redesigned onto a small, fixed
  port list after live measurement showed a full sweep at any quiet timing template is an
  architectural dead end (tens of hours extrapolated), not a tuning problem.
- **A skip-current-tool keybind, and a less trigger-happy Ctrl+C.** Pressing `s` while a tool is
  running kills just that subprocess and moves the scan on — a single Ctrl+C now does the same,
  and only a second Ctrl+C within ~2 seconds aborts the whole scan. Previously any Ctrl+C
  unconditionally killed the entire scan, which was too blunt for "I just want to skip this one
  slow tool." A handful of load-bearing tools (nmap, DNS resolution) refuse the skip since
  everything downstream depends on their output.
- **The `findings` table schema is no longer CVE-only-shaped.** `description`, `remediation`,
  `finding_type`, and (new this round) `product` columns exist, all nullable, migrated in
  idempotently. Web-only findings, nmap-script output, and every tool's findings carry their own
  description/remediation instead of being squeezed into `port/service/version/cve_id/cvss/
  severity` alone.
- **Severity has 4 tiers, never 5.** `CRITICAL / HIGH / MEDIUM / LOW` — no `INFO` tier.
  Keyword-based grading now matches on word boundaries, not plain substring containment — the
  old check let a short keyword like `"rce"` match inside an unrelated word (`"brute-force"`),
  silently inflating an ordinary nikto brute-force finding to CRITICAL.
- **CVE lookups now disambiguate a handful of common vendor tokens.** A bare `"Apache"` banner
  used to return an Apache **Groovy** RCE as a top NVD match — same vendor name, completely
  wrong product. Known tokens (apache, nginx, iis, tomcat, openssh, vsftpd, proftpd, mysql,
  postgresql, lighttpd) now map to a more specific keyword *and* a CPE-product allowlist that
  filters out same-vendor, wrong-product false positives.
- **The CLI can run fully interactively**, and its final summary panel now shows real tool-run/
  failed/skipped counts (previously always zero, because that data only existed inside the
  profile orchestrator and was never passed back up to the panel that displays it).

## 6. Known gaps / honesty notes

- **ZAP's passive-scanner add-on isn't installed by default**, so `deepscan`'s ZAP step, while
  functionally correct end-to-end (it drives ZAP's own daemon over its REST API now, not a
  bundled script Kali's apt package never actually shipped), returns few or no findings until
  that add-on is installed once via ZAP's own desktop GUI. Not a code problem.
- `webaudit` never calls `zaproxy`; `deepscan` never calls `sslyze` — both permanently unwired
  by design (scope decisions documented in each profile's own file), not oversights.
- `whatweb_wrap.py`'s CMS-detection flag (`cms_detected`) has no consumer yet — only gobuster's
  `wordpress_fingerprinted` flag currently triggers the `wpscan` conditional check.
- `deepscan`'s conditional tools (sqlmap/hydra/wpscan/enum4linux) firing has mainly been verified
  against targets purpose-built to trigger them — this project's two default smoke-test targets
  don't meet any of the four trigger conditions on their own, so everyday smoke-test runs don't
  exercise that dispatch path.
- `config.example.py` ships a real, working, project-shared NVD API key as a committed default —
  intentional (see §5), worth knowing if you're used to a stricter "never commit a real key"
  policy.
