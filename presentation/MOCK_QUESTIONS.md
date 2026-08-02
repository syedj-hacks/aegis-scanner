# Aegis Scanner — Mock Q&A (beginner → expert)

> Practice answers. Each has a short spoken answer I can actually say out loud.
> Grouped by difficulty. The tricky ones are the "why not / can it do X" questions at the end.

---

## LEVEL 1 — Beginner (what it is)

**Q. What does your project do, in one sentence?**
It takes a target host and runs a full security assessment by coordinating many existing hacking tools, then produces one clean report with severity and fixes.

**Q. Is Aegis itself a scanner?**
No — it's an *orchestration layer*. The actual scanning is done by tools like nmap and nikto; Aegis runs them for you, normalises their output, and enriches it.

**Q. What language is it written in?**
Python 3. About 17,000 lines across ~45 modules.

**Q. How do you run it?**
`python3 aegis.py <target> --profile deepscan`. If you run it with no target it asks you interactively.

**Q. What's a "profile"?**
A named bundle of which tools to run and how aggressively. We have five: quickscan, stealthscan, webaudit, deepscan, compliance.

**Q. Where do the results go?**
Two places: a SQLite database (`aegis.db`) for history, and a TXT + PDF report in `output/<target>/`.

**Q. What is `aegis.db`?**
A single SQLite file that stores every scan and every finding, so we keep history over time. Three tables: scans, findings, and which-tools-ran.

**Q. What does `__pycache__` do?**
Nothing we wrote — Python auto-generates it to cache compiled bytecode so imports are faster. It's safe to delete; Python rebuilds it.

**Q. What's `.env` for?**
It holds secrets — mainly the NVD API key — and it's git-ignored so secrets never get committed.

---

## LEVEL 2 — Intermediate (how it's built)

**Q. Why split it into so many modules?**
Each layer (recon, scanning, web, enrichment, reporting) is one directory owned by one teammate. Every module follows the same shape, so the code is predictable and testable.

**Q. What's the single most important design rule?**
Never crash — every module always returns a structured result, even on total failure or a Ctrl+C. That's why a scan of a broken or unreachable host still finishes and produces a report.

**Q. How do you actually run the external tools?**
Through one gateway function, `run_tool()`. No module ever calls `subprocess` directly. That centralises timeout, the skip key, and Ctrl+C handling in one place instead of 18 copies.

**Q. What happens if a tool hangs?**
`run_tool()` is Popen-based, so it can kill the process mid-flight — SIGTERM first (so nmap can flush partial results), then SIGKILL if it ignores us.

**Q. How does the severity grading work?**
It prefers a real CVSS score from the CVE. If there's no CVE, it falls back to keyword matching on the description — using word-boundary matching so "rce" doesn't accidentally match inside "brute-force."

**Q. Where do the CVEs come from?**
We query the NVD (National Vulnerability Database) with the product and version we detected from a service banner.

**Q. Why both TXT and PDF reports?**
TXT is fast and greppable for other tools; the PDF is presentable, with a severity donut on the cover. Both read their wording from one shared file so they can never disagree.

**Q. How is the database schema kept up to date?**
It migrates itself idempotently on every start — it checks which columns exist and only adds the missing ones, so it's safe against the already-committed database.

**Q. What's the difference between quickscan and deepscan?**
Quickscan is a fast top-port overview. Deepscan does everything: full recon, all 65,535 ports, the full web audit, ZAP, and conditional exploit checks. Same engine, much wider scope.

**Q. What does the skip key do?**
Pressing `s` while a tool runs kills just that tool and moves on. Compulsory tools like nmap and DNS refuse the skip because everything downstream depends on them.

---

## LEVEL 3 — Advanced (design decisions)

**Q. Why do you chunk the full-port nmap scan into 32 pieces?**
Because a killed nmap doesn't reliably flush partial results. If one giant scan times out on a slow target, you lose everything. With 32 chunks, a chunk boundary becomes the recovery unit — a slow target still yields partial *real* results.

**Q. Why is sqlmap read-only?**
We run `--banner --current-db --dbs` to *prove* the injection with real evidence, but never `--dump`, `--os-shell`, or file read/write. We demonstrate the vulnerability without exfiltrating data — that's the ethical and legal line.

**Q. Why did you rewrite the ZAP wrapper?**
Kali's apt ZAP package doesn't ship the `zap-baseline.py` script — that's Docker-image only. So instead of shelling out to a script that doesn't exist, we start ZAP's own daemon and drive it over its REST API.

**Q. What's "attribution" and why does it matter?**
Every finding is credited to the tool that produced it. An automated audit re-renders every scan in the database and checks the credited tool actually ran on that scan. It caught a real bug where a stealthscan finding told the user to "review this nikto finding" — but nikto never ran in that profile.

**Q. How do you avoid false-positive CVEs?**
Two filters. Product disambiguation — a bare "Apache" banner won't match an unrelated Apache Groovy RCE. And version-range filtering — a CVE fixed "before 10.3" is dropped for a host running 10.3. But the rule is: "cannot verify" never means "drop" — we over-report before we risk hiding a real one.

**Q. Why save findings incrementally instead of all at the end?**
So an interrupt — timeout, skip, crash, budget cutoff — keeps whatever was already found. Batching everything to the end means one failure loses the whole run.

**Q. How do you test something as messy as tool output?**
`tests/fixtures/` holds real captured output from gobuster, nikto, nuclei, ZAP. Parser changes are tested against what the tools *actually* print, not invented strings. And `db_sweep.py` re-renders every scan in the DB as a gate.

**Q. What's the wall-clock budget?**
webaudit and deepscan cap their per-port loop (30 min / 1 hour). When the budget runs out, they stop starting new work and finish with the partial-but-real findings they already have.

---

## LEVEL 4 — Expert / "gotcha" questions (what can/can't it do)

**Q. Can your scanner find zero-day vulnerabilities?**
No — and no scanner honestly can. We detect *known* vulnerabilities (CVEs) and misconfigurations. A zero-day is by definition not yet in NVD or any tool's template set. What we *can* do is surface the suspicious surface a human would then investigate.

**Q. Can it exploit the vulnerabilities it finds?**
Deliberately not beyond proof. sqlmap confirms an injection and reads metadata, hydra confirms weak credentials — but we never dump data, never drop a shell. It's an *assessment* tool, not an exploitation framework. That's a design and ethics decision, not a limitation we couldn't overcome.

**Q. Why not just use a commercial scanner like Nessus or Burp?**
Those are excellent but closed and expensive. This is a learning project that shows *how* an orchestration layer works, and it's fully open and extensible — adding a new tool is one drop-in wrapper. It's complementary, not a replacement.

**Q. Why SQLite and not a real database like PostgreSQL?**
SQLite needs zero setup, is a single portable file, and travels with the repo so history survives a clone. For a single-user CLI tool that's the right fit. If we moved to a multi-user dashboard, Postgres would make sense — the CRUD is isolated in `db.py`, so swapping it is contained.

**Q. Can it scan multiple targets at once?**
Yes — `--targets a.com,b.com` or a file, each with its own output folder. Web tools and nmap chunks also run concurrently within a scan, and we proved the concurrency is lossless.

**Q. Can it scan authenticated / logged-in areas?**
Yes — `--auth-cookie` or `--auth-header` (or the safer `.env` equivalents). Without auth, a scanner only sees the public surface; behind a login is where a lot of real risk lives.

**Q. How do you know a re-scan actually fixed something?**
`--diff 41 57` compares two scans and shows what's new, fixed, and unchanged. That's the re-test workflow.

**Q. Isn't running 18 tools slow?**
For deepscan, yes — it's the thorough profile, and full-port discovery is inherently target-dependent. That's exactly why we have quickscan and stealthscan, and why heavy work runs concurrently with a wall-clock budget.

**Q. What stops a bug in one tool from corrupting the whole run or the database?**
The "never raise" rule isolates each tool, findings are written incrementally in separate transactions, and every insert opens its own connection. We verified live that killing a scan mid-run left a clean scan row with no orphaned or corrupt data.

**Q. Can it detect vulnerabilities behind a WAF or rate limiter?**
Partly. We have a stealth profile, per-profile rate limits, and randomised timing to stay under thresholds. But a scan returning "no open ports" on a healthy host is usually rate-limiting, not a clean result — we flag that explicitly rather than reporting a false all-clear.

**Q. Why not add a web dashboard / GUI?**
It's on the roadmap. The data is already in SQLite and the reporting logic is isolated, so a dashboard is an additive layer, not a rewrite. We prioritised a correct, trustworthy engine first — a pretty UI over wrong data is worse than a CLI over right data.

**Q. What's the biggest weakness you'd fix first?**
deepscan's runtime on heavily filtered targets, and broadening authenticated-scan flows (form login, OAuth). Both are known and documented, not hidden.

**Q. If a finding's CVE column is blank, is that a bug?**
Not necessarily — that's the point of our "not applicable vs. genuine gap" distinction. A TLS-config finding has no CVE by nature; a service finding with a blank CVE is a real gap and the report says which tool should have filled it. A blank cell is never left ambiguous.

---

## Questions to be ready to turn around on the audience
- "What would you add?" → dashboard, scheduling + alerting on new findings, SARIF export.
- "Where could this break?" → slow/filtered targets, tools not installed (we degrade + warn), rate limiting.
- "Is this legal to run?" → only against systems you own or are authorised to test — same as any security tool. Our test lab is intentionally local and isolated for that reason.
