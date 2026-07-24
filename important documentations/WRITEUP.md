# Aegis Scanner — Project Writeup

**Cyber404 Academy 2026 — team project**
Branch under review: `dev` (post-integration hardening — closes the CONDITIONAL_TOOLS,
nmap `--script`, and CVE-shaped-schema gaps called out in the original `feature/integration`
writeup, and adds wrapper modules for the eight tools that were previously only *named* in
config with nothing to run them)

---

## 1. What it is

Aegis Scanner is a modular vulnerability-assessment framework for Kali Linux. You give it a
target (hostname or IP, or nothing — you'll be prompted interactively) and a **profile**, and
it runs a pipeline of recon → scanning → web-auditing → conditional exploitation checks →
enrichment → reporting, writing results to a local SQLite database and a TXT/PDF report per
target.

It is not a single tool — it's an orchestration layer over existing Kali tools (`nmap`,
`nikto`, `gobuster`, `dirb`, `whatweb`, `nuclei`, `sqlmap`, `hydra`, `wpscan`, `enum4linux`,
`sslyze`, ZAP baseline, `nslookup`, `subfinder`, `amass`, `theHarvester`) plus a homegrown NVD
CVE lookup, severity grading, and remediation-advice engine.

## 2. Why it's built this way

The project was split across teammates by layer ("Member B — recon layer" appears in
docstrings), so the codebase is organized as strict **phases**, each phase owning one
directory under `modules/`, and each module in a phase following the same shape:

1. Take a target (and sometimes ports/services) as input.
2. Call out to a real CLI tool via `run_tool()` (subprocess wrapper — see
   [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md)), or use `safe_call()` for pure-Python calls
   (raw sockets, `requests`).
3. Parse that tool's raw output into a small, predictable dict shape.
4. Never raise — always return a structured result, even on total failure.

That "never raise, always degrade" rule is the single most important convention in the
codebase, and it's why a scan against an unreachable host, a target with no open ports, or a
machine missing half the Kali toolset still completes and produces a report instead of
crashing.

## 3. What's actually implemented (as of this writeup)

Every phase described in the profile table below is implemented end-to-end and wired into
`aegis.py`. There is no phase left as an empty stub. The `banner.py` module (previously built
but unused) is now called by `deepscan`/`webaudit`, nmap `--script` output is now parsed and
turned into findings, and all four `CONDITIONAL_TOOLS` (sqlmap/hydra/wpscan/enum4linux) now
actually dispatch instead of only logging that a condition was met. See
[BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md) for the full module-by-module map, including the
handful of gaps that remain (mainly: `quickscan`/`stealthscan` weren't updated to call the
newly-wrapped `whatweb`/`nuclei` tools their own `PROFILES` entries mention).

| Phase | Directory | Status |
|---|---|---|
| Foundation | `modules/utils/` | Done — logger, error handler, config (+ `.env` auto-load), display |
| Recon | `modules/recon/` | Done — DNS, subdomain enum, OSINT |
| Scanning | `modules/scanning/` | Done — port scan (+ nmap `--script` parsing), service detect, banner grabber (now wired in), enum4linux, hydra |
| Web | `modules/web/` | Done — header audit, Nikto, gobuster, dirb, whatweb, nuclei, sqlmap, sslyze, wpscan, ZAP baseline |
| Enrichment | `modules/enrichment/` | Done — CVE lookup (NVD), severity scoring, remediation text — covers every new finding kind above |
| Reporting | `modules/reporting/` | Done — summary builder, TXT report, PDF report; findings schema is no longer CVE-only |
| Profiles | `modules/profiles/` | Done — quickscan, stealthscan, webaudit, deepscan, compliance; conditional-tool dispatch now live in deepscan |
| CLI | `aegis.py` | Done — argparse entry point (target/profile now optional, interactive prompt mode), dispatch table, final summary |
| Install | `install.sh`, `setup.py` | Done — apt tool install (8 new packages), venv, dependency check, automatic `config.py` bootstrap, `.env` key prompt |

## 4. The five scan profiles

| Profile | What it actually runs | Report |
|---|---|---|
| `quickscan` (default) | DNS resolve → fast top-port nmap (`-T4 -F`) → service detection on open ports | TXT |
| `stealthscan` | DNS resolve → slow full-port nmap sweep (`-T1 -p- --randomize-hosts -Pn`), **no** second service-detect pass (keeps footprint minimal) | TXT |
| `webaudit` | DNS resolve → nmap scoped to web ports (80/443/8080/8443) → banner grab → header audit + Nikto + gobuster + dirb + whatweb (+ sslyze on HTTPS ports) on each open web port → CVE lookup on the `Server` banner + nmap-script/sslyze findings | TXT |
| `deepscan` | Everything: DNS + subdomain enum + OSINT → full-port nmap + service detect + banner grab → web module (header/nikto/gobuster/dirb/whatweb/nuclei/ZAP baseline) on any discovered web port → conditional sqlmap/hydra/wpscan/enum4linux where their trigger conditions are detected → CVE lookup + severity + remediation on every finding | TXT + PDF |
| `compliance` | nmap with `--script ssl-enum-ciphers,http-headers` + sslyze on the TLS port the script identified (no DNS — not in this profile's tool list); script/sslyze results are now scored and remediated, not discarded | TXT |

Full command reference: [COMMANDS.txt](COMMANDS.txt).
Step-by-step walkthrough: [TUTORIAL.md](TUTORIAL.md).
Internals / data flow / known gaps: [BACKEND_STRUCTURE.md](BACKEND_STRUCTURE.md).

## 5. Design decisions worth knowing about

- **`config.py` is gitignored.** It holds `NVD_API_KEY` and is generated automatically by
  `setup.py` from `modules/utils/config.example.py` on first run. `config.example.py` itself
  now auto-loads a gitignored `.env` at the repo root and ships a shared, working default NVD
  API key — a deliberate reversal of the previous "never commit a real key" rule, made so CVE
  lookups work immediately after clone + install with zero manual setup. A personal key in
  `.env` (`AEGIS_NVD_API_KEY`) or the shell environment still overrides the shared default.
- **A profile only runs tools it has a wrapper for *and* has explicitly wired in.** All eight
  tools that used to have no wrapper anywhere (`sqlmap`, `hydra`, `wpscan`, `enum4linux`,
  `nuclei`, `zaproxy`, `sslyze`, `whatweb`) now have one — but each profile orchestrator still
  decides for itself which of its configured tools it actually calls, via its own
  `_AVAILABLE_TOOLS` set. `quickscan`/`stealthscan` weren't updated in this round, so they
  still warn "no wrapper module" for `whatweb`/`nuclei` even though the wrapper files now
  exist under `modules/web/`. Some pairings are permanently, deliberately unwired regardless
  of wrapper availability (e.g. `compliance` never calls `whatweb`, `webaudit` never calls
  `zaproxy`, `deepscan` never calls `sslyze`) — every orchestrator logs a warning rather than
  silently skipping or faking a result.
- **The `findings` table schema is no longer CVE-only-shaped.** `database/db.py` migrated in
  `description`, `remediation`, and `finding_type` columns (nullable, backward compatible with
  pre-migration rows). Web-only findings (missing headers, discovered paths, Nikto findings,
  nmap-script output, and every new tool's findings) now carry their own description/
  remediation instead of being squeezed into `port/service/version/cve_id/cvss/severity` alone.
- **Severity has 4 tiers, never 5.** `CRITICAL / HIGH / MEDIUM / LOW` — there is no `INFO`
  tier; anything informational is floored to `LOW` so it still counts in the final summary
  instead of vanishing. nmap-script and whatweb findings now feed this same grading logic.
- **The CLI can now run fully interactively.** `python3 aegis.py` with no arguments prompts
  for a target (re-prompting on invalid input) and, if `--profile` was also omitted, a
  numbered profile menu. Supplying a target on the command line still behaves exactly as
  before (silently defaults to `quickscan` if `--profile` is omitted) — this is additive, not
  a breaking change to the non-interactive path.

## 6. Known gaps / honesty notes

Most of the gaps this writeup used to list are now closed — `banner.py` is wired in, nmap
`--script` output is parsed and scored, and all four `CONDITIONAL_TOOLS` dispatch for real.
What's intentionally left, or still worth knowing about:

- `quickscan.py`/`stealth.py` weren't touched in this round of work — their
  `_AVAILABLE_TOOLS` sets don't include `whatweb`/`nuclei`, so those profiles still log a
  "no wrapper module" warning for tools listed in their own `PROFILES` config, even though
  wrapper modules for both now exist elsewhere in the codebase.
- Several profile/tool pairings are permanently unwired by design, not oversight:
  `compliance` never calls `whatweb`; `webaudit` never calls `zaproxy` (too heavy for its
  fast-audit scope); `deepscan` never calls `sslyze` (reserved for compliance/webaudit).
- `whatweb_wrap.py`'s CMS-detection flag (`cms_detected`) has no consumer yet — only
  gobuster's `wordpress_fingerprinted` flag currently triggers the `wpscan` conditional check.
- `config.example.py` now ships a real, working, project-shared NVD API key as a committed
  default. This is intentional (see §5) but worth knowing if you're used to the prior
  "never commit a real key" policy this same file used to state.
