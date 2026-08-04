# Aegis Scanner — Project Writeup

**Cyber404 Academy 2026 — team project**
Branch under review: `dev`. Earlier rounds hardened the interrupt/reliability model (a
skip-current-tool keybind, a saner Ctrl+C, chunked full-port nmap sweeps that survive a slow
target, per-port incremental result persistence, wall-clock budgets on the web-audit loops),
closed the last "listed in config but never actually run" gaps in `quickscan`/`compliance`,
root-caused and fixed a handful of live-reproduced bugs (dirb's connection-threshold abort, a
"unknown" fallback in reports, a skip-vs-failure miscount across every tool wrapper, a
substring-match false positive in severity scoring, a same-vendor/wrong-product and a
wrong-version false positive in CVE lookups), and rewrote the ZAP wrapper to drive ZAP's own daemon API directly instead of a
bundled script Kali's apt package never actually ships.

The rounds since then have been about **making the output trustworthy**, which turned out to be a
different problem from making the scan work:

- **Injection & scripting became first-class.** A dedicated XSS wrapper (nuclei in DAST mode,
  `-dast -tags xss`) and read-only sqlmap enumeration now produce findings that carry the exact
  payload, the parameter it went into, and a response snippet proving the reflection — rendered in
  their own report section instead of being one more line of prose.
- **Every report is kept, named and capped.** Reports were being silently overwritten (this
  destroyed one for real), so they are now named per scan and the history is capped per
  profile+target.
- **Findings say who found them, and that claim is now checked.** Every report field distinguishes
  "not applicable to this kind of finding" from "this tool should have filled this in and didn't",
  and a mechanical audit re-checks every row of every scan in the database for whether the tool a
  finding is credited to actually ran on that scan.
- **The database now records which tools actually ran**, per scan, per port, with their outcome —
  so that audit can ask "did this tool run on *this* scan", not just "does this profile wire it in".

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

Every profile writes both a plain-text and a PDF report, named per scan
(`report_<profile>_<target>_<scan_id>.txt` / `.pdf`) so nothing is overwritten, with the history
capped per profile+target.

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
handful of gaps that remain by design (mainly: `webaudit` deliberately never calls `zaproxy`, and
`deepscan` deliberately never calls `sslyze`).

| Phase | Directory | Status |
|---|---|---|
| Foundation | `modules/utils/` | Done — logger, error handler (Popen-based, timeout + skip-keybind + Ctrl+C handling), config (+ `.env` auto-load), display |
| Shared profile layer | `modules/profiles/_common.py` | Done — codebase-wide "does a wrapper exist / does this profile call it" check (replacing five hand-rolled copies), the one ran/skipped/failed predicate, the tools-run record, XSS candidate discovery, and the shared end-of-scan report sequence |
| Recon | `modules/recon/` | Done — DNS, subdomain enum, OSINT, **certificate transparency (crt.sh)**, **cloud bucket discovery (cloud_enum)**, **breach check (HIBP)** |
| Scanning | `modules/scanning/` | Done — port scan (chunked full-range sweeps, `--script` parsing), service detect (`-sV -sC` combined), banner grabber, enum4linux, hydra |
| Web | `modules/web/` | Done — header audit, Nikto, gobuster, dirb, whatweb, nuclei, sqlmap (read-only enumeration), **XSS (nuclei DAST)**, sslyze, wpscan, ZAP (via its own daemon API) |
| Enrichment | `modules/enrichment/` | Done — CVE lookup (NVD, with product-disambiguation), severity scoring (word-boundary keyword matching), remediation text |
| Reporting | `modules/reporting/` | Done — summary builder (the shared report vocabulary), TXT report, PDF report (severity donut cover), **self-contained HTML report**, **live browser dashboard**, **scan diffing**, capped report history, end-of-scan banner, attribution audit |
| Profiles | `modules/profiles/` | Done — quickscan (runs whatweb+nuclei), stealthscan (curated port list + whatweb), webaudit, deepscan, compliance (runs whatweb too), **recon (passive attack-surface mapper)**; all persist findings incrementally, all record which tools ran, all produce TXT + PDF + HTML |
| CLI | `aegis.py` | Done — argparse entry point (target/profile optional, interactive prompt mode, `--non-interactive`), **a three-way mode menu for a bare invocation**, `--recon`, `--live`, `--diff`, dispatch table, final summary with real (not always-zero) tool counts, and a one-line attack-surface delta after every scan |
| Install | `install.sh`, `setup.py` | Done — apt tool install, venv, dependency check (incl. the ZAP client), automatic `config.py` bootstrap, `.env` key prompt, nuclei fallback, one-time ZAP passive-rules bootstrap |
| Verification | `tests/`, `smoke_test/` | Done — per-pass assertion scripts, real captured tool fixtures, a PTY test for the skip keybind, and a whole-database audit gate; each pass's evidence and open items written up in `smoke_test/` |

## 4. The six scan profiles

All six write a TXT, a PDF **and** a self-contained HTML report.

| Profile | What it actually runs |
|---|---|
| `quickscan` (default) | DNS resolve → fast top-port nmap (`-T4 -F`) → service detection → whatweb + high-severity nuclei on the first open web port |
| `stealthscan` | DNS resolve → quiet `-T2` scan of a fixed ~20-port list (web/mail/DB/remote-admin basics) — **no** second service-detect pass — then a single `whatweb` fingerprint on the first open web port. Deliberately no nuclei; see §5 |
| `webaudit` | DNS resolve → nmap scoped to web ports (80/443/8080/8443) → banner grab on non-web ports → header audit + Nikto + gobuster + dirb + whatweb (+ sslyze on HTTPS ports) on each open web port, wall-clock-bounded to 30 min → an XSS fuzzing pass over the parameterised URLs built from gobuster/dirb's discovered paths → CVE lookup on the `Server` banner + nmap-script findings |
| `deepscan` | Everything: DNS + subdomain enum + OSINT → chunked full-port nmap discovery (no -sV/-sC) + a targeted `-sV -sC` pass (this is also where nmap-script findings come from) + banner grab on non-web ports → web module (header/nikto/gobuster/dirb/whatweb/nuclei/XSS/ZAP) on any discovered web port, wall-clock-bounded to 1 hour → conditional sqlmap/hydra/wpscan/enum4linux where their trigger conditions are detected → CVE lookup + severity + remediation on every finding |
| `compliance` | nmap with `--script ssl-enum-ciphers,http-headers` (no DNS — not in this profile's tool list) → sslyze + whatweb on the TLS port(s) the script identified; script/sslyze/whatweb results are scored and remediated |
| `recon` | **Sends nothing to the target.** crt.sh certificate transparency → subfinder + amass → theHarvester → cloud_enum bucket discovery → HIBP breach check on any harvested addresses. Accepts a **company name** as well as a domain |

`recon` is the odd one out and deliberately so: it is the only profile that sends no packet to the
target, which is what makes it safe to point at a name you do not yet have written authorisation
to scan, and the only one that accepts a company name rather than a hostname. Given a bare name
there is no domain, so DNS, certificate transparency and subdomain enumeration are reported *not
applicable* instead of being run and failing.

`webaudit` is the one profile whose report carries a **scope note**, because the honest statement
about it is subtle: it runs nuclei in DAST/XSS mode but *not* the severity template pass, so a
quickscan or deepscan of the same host can surface findings a webaudit report does not. Writing
"webaudit does not run nuclei" would have been false, and saying nothing left a real gap
unexplained — a webaudit of a host once reported 0 CVEs where a quickscan of the same host found
2 CRITICAL, with nothing in the report saying why.

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
  `finding_type`, `product`, the injection-evidence group (`parameter`/`payload`/`evidence`/
  `endpoint`) and `reference` all exist, nullable, migrated in idempotently. Web-only findings,
  nmap-script output, and every tool's findings carry their own description/remediation instead of
  being squeezed into `port/service/version/cve_id/cvss/severity` alone.
- **Adding a column broke a classifier, and that's why there's now an audit.** `reference` was
  added so nikto/ZAP/wpscan citations had somewhere to go. But the report's classifier sniffed
  nikto findings by `"reference" in finding` — and SQLite rows carry *every* column, so overnight
  every stored untyped finding was reclassified as nikto's: a stealthscan open-port finding was
  told to "review this nikto finding", naming a tool that never ran in that profile. 317 unit
  assertions and a whole-database render sweep all passed it; a human reading one report caught
  it. Two things came out of that: findings are now typed at the source instead of classified by
  shape, and `modules/reporting/attribution.py` re-asks "is this finding credited to a tool that
  actually ran, and does its declared type still fit the columns it carries?" for every row of
  every scan. **That third check is specifically aimed at the next shared column.**
- **The database records which tools actually ran.** A `scan_tools_run` table stores one row per
  (tool, port) with a `ran`/`skipped`/`failed` outcome, classified by the same single predicate
  the on-screen "Tools run/failed/skipped" counts use — so the record cannot drift from what the
  operator saw. It lets the attribution audit ask the sharper question: not "does this profile
  wire in the tool this finding is credited to", but "did that tool run on *this* scan". Collected
  going forward only; historical scans keep the profile-level answer rather than being backfilled
  with a record that was never captured.
- **Reports are never silently overwritten, and never accumulate forever.** They used to be one
  fixed `report.txt` per target, which destroyed evidence for real (one scan's report was gone an
  hour later, overwritten by the next, with nothing warning). Reports are now named per scan and
  capped at 5 **per profile+target** — a per-target cap would let a burst of quickscans evict the
  one deepscan report of that host, which is exactly the loss being prevented. Interactive runs
  are asked what to drop; scripted runs drop the oldest and log it.
- **XSS is a first-class check rather than an incidental one.** nuclei's real XSS coverage only
  fires in DAST mode against a URL that actually has a parameter to mutate — run without either,
  the templates never fire and *the scan looks clean*. So the wrapper refuses a URL with no query
  string rather than run a scan that can only report nothing, and the profiles build fuzzable URLs
  from the paths gobuster/dirb already found. Candidate ordering turned out to matter for both the
  XSS and the sqlmap pass (they share one ranked candidate builder): without it, the whole budget
  went to `/index.php` and the genuinely interesting endpoints (`/xss.php`, `/info.php`) were never
  reached — the ranker puts likely-parameterised names ahead of site roots, and sqlmap now probes
  the ranked list until one confirms rather than stopping at the first `.php`.
- **sqlmap enumerates, and only enumerates.** A confirmed injection is followed by three read-only
  metadata requests (`--banner --current-db --dbs`) so the finding carries real evidence instead
  of a bare `vulnerable: true`. It never requests `--dump`, `--os-shell`, `--sql-shell` or file
  read/write — that line is deliberate and is documented where the flags are built.
- **A blank field in a report is never left ambiguous.** "Nothing found" and "never looked" read
  identically as an empty cell, so a field that is inapplicable by nature to a finding type prints
  why ("TLS configuration finding"), and one that should have been filled names the tool that
  didn't fill it ("not determined by nuclei"). Both writers read that wording from one module, so
  the TXT and the PDF cannot describe the same row differently.
- **Duplicates are fixed where they're produced, not where they're displayed.** deepscan enriches
  CVEs down two independent paths and on some hosts both named the same CVE. The fix is a shared
  `(cve_id, port)` set across both call sites — keyed on the CVE id because the two paths name the
  product differently ("Apache httpd" vs "Apache"), and per port so the same CVE on two ports
  still counts twice. The second lookup is still made: it returned two CVEs the first one missed.
- **Severity has 4 tiers, never 5.** `CRITICAL / HIGH / MEDIUM / LOW` — no `INFO` tier.
  Keyword-based grading now matches on word boundaries, not plain substring containment — the
  old check let a short keyword like `"rce"` match inside an unrelated word (`"brute-force"`),
  silently inflating an ordinary nikto brute-force finding to CRITICAL.
- **CVE lookups now disambiguate a handful of common vendor tokens.** A bare `"Apache"` banner
  used to return an Apache **Groovy** RCE as a top NVD match — same vendor name, completely
  wrong product. Known tokens (apache, nginx, iis, tomcat, openssh, vsftpd, proftpd, mysql,
  postgresql, lighttpd) now map to a more specific keyword *and* a CPE-product allowlist that
  filters out same-vendor, wrong-product false positives.
- **...and they check the version range, not just the product.** Right product is only half the
  question. NVD's `keywordSearch` is an AND-of-words match, so a CVE whose description says
  "before 10.3" is returned for a host running *exactly* 10.3 — the release that **fixed** it.
  The 2026-07-29 verification pass caught 7 of these (5 on an OpenSSH 10.3 host, 2 on Apache
  2.4.25). The lookup now reads the vulnerable CPE ranges NVD attaches to each CVE and drops one
  only when the detected version is *definitively* outside all of them. Anything ambiguous — no
  CPE data, a version wildcard, a detected version too coarse to place (a bare `"4"` against a
  `"before 4.1.22"` bound), or no version detected at all — is **kept**. The rule is the same one
  the product filter uses: *cannot verify is not the same as does not match*, so the filter can
  over-report but never silently hide a real CVE.
- **The CLI can run fully interactively**, and its final summary panel now shows real tool-run/
  failed/skipped counts (previously always zero, because that data only existed inside the
  profile orchestrator and was never passed back up to the panel that displays it).

### 5.x The commercial-upgrade batch (2026-07-31)

Ten items added on `feature/commercial-upgrade`. The design decisions worth
carrying forward:

- **Concurrency is two independent layers that MULTIPLY.** Within a scan,
  independent per-port web tools run in a pool; across scans, whole targets run
  in a pool. The real outbound rate is roughly their product, so both defaults
  are small and `PROFILE_RATE_LIMITS` exists to throttle further. What is *not*
  parallel is deliberate: nuclei DAST (consumes gobuster/dirb's paths), ZAP (one
  session), and the four active-injection conditional tools. `stealthscan` is
  excluded from all of it and a regression test enforces that.

- **Two latent bugs had to be fixed before concurrency was safe**, and both are
  the kind that only appear under load: the skip-key listener saved/restored the
  terminal per-tool (fine for one tool, corrupts the terminal for five), and
  `get_logger()` could attach two file handlers to one target's logger from two
  threads. Called out because they are the sort of thing a future "add more
  concurrency" change can reintroduce.

- **CVSS was added as EXPLANATION, not re-grading.** Every non-CVE finding now
  carries a v3.1 vector and score, but the templates were calibrated to land in
  the same severity band the existing heuristic already assigned — the value is
  the auditable vector next to the number, not a reshuffle. Informational
  findings are left deliberately unscored, because a defensible "version
  disclosed" score is MEDIUM and applying it would have promoted thousands of
  LOW rows and buried the real findings. NVD scores are never overwritten.

- **Compliance mapping and testssl are compliance-profile-only**, and gated so
  every other profile's output is byte-identical. testssl COMPLEMENTS sslyze
  (accepts-vs-vulnerable) rather than replacing it.

- **Two invisible-failure bugs were found and fixed DURING this batch's own live
  verification**, both the same shape as the historical scan-97 zero-ports bug —
  a tool that could not reach its target writing a clean-looking "nothing found"
  result. testssl.sh writes a valid JSON report with a `scanProblem`/`FATAL`
  entry on a refused connection; ZAP reports a complete spider and zero alerts
  when its (possibly containerised) daemon cannot route to the target. Both now
  classify as tool failures. The ZAP one matters more precisely because
  `ZAP_HOST` now exists: a remote daemon has its own network view, so "the
  scanner can reach it" no longer implies "ZAP can".

- **A NameError in deepscan's sqlmap dispatch shipped in the checkpoint commit
  and was caught by live A/B testing**, not by the test suite — the conditional
  path only fires against a target whose content produces an injectable
  candidate, which the finding-sparse smoke targets never did. A reminder that
  "the tests pass" and "the conditional tools were exercised" are different
  claims, exactly as the note below already says.

- **Scheduling is cron + a shell script, not a daemon.** `--non-interactive`
  plus `--diff` plus `scripts/scheduled_scan.sh` (which exits non-zero only on a
  delta, so cron mails you only when something changed) does the whole job
  without a process to supervise.

### 5.y The recon / dashboard batch (2026-08-05)

Three features — a passive recon mapper, a self-contained HTML report with a live browser
dashboard, and a fuller scan diff — plus a set of bug fixes. What is worth recording is not the
feature list but **the shape of the four bugs found building it**, because all four were the same
bug wearing different clothes: *an implementation that succeeds and produces nothing.*

- **`pip install cloud-enum` installs an empty package.** The PyPI name is a placeholder whose own
  description reads "Reserved name placeholder. No functionality." It exits 0. Anyone following
  the obvious install instruction would have a tool that appears installed while the wrapper logs
  "binary not found on PATH" for ever. `install.sh` uses apt or the upstream git repo and explains
  why in a comment, because the next person to touch it will otherwise reach for pip.
- **HIBP has required a paid API key since 2019.** The natural implementation — treat HTTP 200 as
  "breached" and anything else as "not breached" — turns the resulting 401 into *every address is
  clean*. That is a false all-clear on a security tool, which is the single worst output it can
  produce: it is the one a reader acts on by doing nothing. The check now carries an explicit
  `available` flag, only a genuine 404 from an authenticated request counts as clean, and the
  summary prints **NOT CHECKED**.
- **A `file://` page cannot poll for data.** Browsers block `fetch()` against file origins, so the
  natural "write two files and open the HTML" dashboard design renders its shell and then waits
  for data for ever, with the reason visible only in the devtools console. It is served from
  `127.0.0.1` instead.
- **A dedup key of `(port, finding_type, cve_id)` deletes real findings.** Every CVE-less finding
  on a port collapses into one row: on this database that is 6,580 `discovered_path` rows becoming
  a handful. Deduplication that deletes findings is worse than the duplicates it removes, so the
  filter reuses the identity key `diff.py` already worked out. Relatedly, the "empty ghost rows"
  that needed removing carry *no* `finding_type` at all rather than a particular one — a filter
  keyed on a type string would have matched nothing.

Two other things this batch is worth remembering for:

- **The whole-database attribution sweep earned its keep on a bug introduced two hours earlier.**
  `ran_producer_set()` never lowercased tool names, so `theHarvester` — the binary's own
  capitalisation, and what `osint.py` stamps on its result — never matched the producer name
  `theharvester`. It had been latent for months and could stay latent, because theharvester sat in
  `NON_FINDING_TOOLS` for every profile. The moment `recon` made it a real producer of a persisted
  finding type, the sweep failed. An audit that only ever passes is not evidence of anything.
- **Volume assumptions had to change.** A passive subdomain sweep of `example.com` returned 23,330
  names. Persisting one finding each produces a report whose signal sits at row 12,000 — which is
  to say, no signal. Findings are capped at 100 plus a summary row stating the true total, ordered
  so names several sources corroborate survive the cap first; the full list stays in
  `recon_subdomains`. A cap that hides the total would have been the wrong fix.

## 6. Known gaps / honesty notes

- **ZAP's passive-scanner add-on** (`pscanrules` — without it ZAP scans complete cleanly and
  return nothing, forever) is now bootstrapped automatically by `install.sh`, once, on a fresh
  `~/.ZAP`. If it ever goes missing on a machine that skipped that step, the recovery is to delete
  `~/.ZAP` and re-run the bootstrap — **not** `zap.sh -addonupdate`, which is the leading suspect
  for how it got uninstalled during development in the first place.
- **ZAP is not reliably interruptible mid-scan.** Two attempts to skip it with a real interrupt
  did not skip it; its phase is dominated by daemon startup/shutdown, so the signal can land
  outside the wrapper's poll loop. A property of ZAP, not of the skip machinery.
- `webaudit` never calls `zaproxy`; `deepscan` never calls `sslyze` — both permanently unwired
  by design (scope decisions documented in each profile's own file), not oversights.
- `whatweb_wrap.py`'s `cms_detected` **is now consumed**: `deepscan` ORs it with gobuster's
  `wordpress_fingerprinted`, so either signal triggers `wpscan`, and the report names which one
  fired. The two catch different sites — gobuster only fires when `/wp-admin`-style paths sit at
  guessable locations, whereas whatweb reads the generator tag and asset paths out of the
  response.
- `deepscan`'s conditional tools (sqlmap/hydra/wpscan/enum4linux) have all four been verified
  firing live end-to-end with real evidence and **zero tool failures**, against the local
  intentionally-vulnerable lab in `test-targets/` (WordPress → wpscan, DVWA → sqlmap CRITICAL SQLi
  with DB enumeration, openssh → hydra `admin:admin`, samba → enum4linux shares/users). This
  project's two default *internet* smoke-test targets don't meet any of the four trigger
  conditions on their own, so everyday smoke-test runs against those don't exercise the dispatch
  path — bring up the lab (`cd test-targets && docker-compose up -d`) to see it.
- **The tools-run record has live coverage on deepscan, quickscan, webaudit and compliance.**
  The 2026-07-31 pass ran webaudit and compliance live as well; `stealthscan` is still verified
  by its regression guard and structure, not a fresh timed run in that pass.
- **The deepscan concurrency speedup was measured against the LOCAL LAB, not an internet host.**
  The first attempt against scanme.nmap.org was discarded: the host degraded between the two
  halves (it stopped answering entirely), so the "after" run lost findings from the sequential
  tools and the number measured target decay as much as concurrency. The clean figure comes from
  the DVWA container — see smoke_test11 for both the number and why the first one was thrown out.
- **`cloud_enum` has never actually run on the development machine** (`sudo` needs a password
  there), so the recon profile's bucket-discovery half is code-complete and unit-tested against
  captured output but **unverified live** — it has only ever been exercised through its honest
  "binary not found" path. Install it and re-run before claiming that half works.
- **crt.sh returned 502 on every attempt** across two sessions hours apart, so a *successful*
  certificate-transparency lookup has not been observed here either. The wrapper retries and then
  reports a failure; it never renders one as "zero subdomains", which is the difference between a
  known gap and a silent wrong answer. subfinder/amass cover the same ground and are verified
  working (10,925 names on a live badssl.com run).
- **The HIBP breach check has only been exercised through its no-key path**, for the reason in
  §5.y — there is deliberately no bundled key.
- **The live dashboard stops when the command exits.** Its server is a daemon thread; an
  interactive `--live` run holds the process open at the end so the completion banner is
  reachable, and a scripted one is told where the static report is instead.
- **Two historical attribution mismatches are reported and allowlisted, not rewritten.** Old rows
  have not been edited to make the audit quiet. Likewise, the one historical data repair that was
  done (`tools/backfill_nuclei_identity.py`) deliberately restored only values recoverable from
  the logs verbatim and left `port` NULL, because that value was never recorded for those runs —
  writing it in would have inserted an inferred value into a historical record.
- `config.example.py` ships a real, working, project-shared NVD API key as a committed default —
  intentional (see §5), worth knowing if you're used to a stricter "never commit a real key"
  policy.

Each work pass's full evidence — what was run, against what, and what it left open — is written up
in `smoke_test/smoke_test1-10.txt`, and the next pass opens by resolving the previous one's open
items. That is this project's substitute for a bug tracker, and it is the honest place to look for
current state.
