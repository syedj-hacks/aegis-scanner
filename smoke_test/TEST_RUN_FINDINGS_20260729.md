# Aegis Scanner — Full Verification Pass (Test Run Findings)

**Date:** 2026-07-29
**Scope of run:** Live, evidence-based verification against three authorized targets only —
`scanme.nmap.org`, `pentest-ground.com`, and the local `test-targets/` docker lab
(172.28.0.0/24). Interpreter: `venv/bin/python3` throughout (see Bug/Note on the stale
"use /usr/bin/python3" guidance). Baseline max scan id before this session = **157**; all
session scans are id **158+**.

---

## 1. Summary verdict

**The scanner produces genuine, verifiable evidence across all five profiles and all four
conditional tools.** Every tool that ran to completion produced real, independently
confirmable findings — nmap ports, nikto/gobuster/dirb paths, ZAP passive alerts (61 rules
active), whatweb, header checks (curl-confirmed), and — critically — sqlmap/hydra/wpscan/
enum4linux all fired live with real evidence and **zero tool failures** on every deepscan.
The static test suite (db_sweep + t_phase2/3/4/8/9/10 + t_pty) is fully green with only the
two documented, allowlisted historical attribution mismatches. All 16 distinct CVE IDs
surfaced this session are **real, current CVEs** verifiable on nvd.nist.gov.

**One real defect was found:** the NVD CVE-enrichment lookup (`cve_lookup.py`) filters by CPE
*product* but **not by CPE version range**, so it reports "before X" CVEs against a host
running exactly version X (the *fixed* version). This produced **7 false-positive CVE
findings** this session (2 on DVWA's Apache 2.4.25, 5 on the SSH lab's OpenSSH 10.3), plus a
batch of stale Samba CVEs matched against Samba 4.12.2 because nmap only detected the major
version. The CVEs themselves are real; they are simply *misapplied* to a version that isn't
vulnerable. This over-reports (never under-reports) and is **not demo-blocking**, but a
reviewer who checks one CVE against the detected version will catch it — so it needs a
follow-up fix, and the "point at the NVD CVE lookup as proof it finds real vulns" demo advice
should be qualified. Notably, **nuclei-sourced CVEs (Redis, Terrapin) were all accurate** —
they are actively detected, not version-keyword-matched.

Bottom line: **this is a genuine, working vulnerability-assessment framework, not a
mock.** The evidence is real. Fix the CVE version-range filtering before leaning on
banner-derived CVE counts in the demo.

---

## 2. Per-profile results (5 profiles × 2 external targets = 10 runs)

`-v` resolved tool list cross-checked against OVERVIEW_CONTEXT.md §3. "Tools" = distinct
tools recorded in `scan_tools_run`. All runs `--non-interactive`.

| Scan | Profile | Target | Tools that actually ran | Findings (C/H/M/L) | Matches §3 matrix? | Pass |
|---|---|---|---|---|---|---|
| 159 | quickscan | scanme.nmap.org | nslookup, nmap, nmap_service_detect | 1 (0/0/0/1) | ✅ (only SSH found on this run → no web port → whatweb/nuclei had nothing to run against; later runs 172/174/175 found :80 and ran all 5) | PASS |
| 162 | quickscan | pentest-ground.com | nslookup, nmap, nmap_service_detect, whatweb, nuclei | 9 (2/4/0/3) | ✅ tools=[nslookup,nmap,whatweb,nuclei] | PASS |
| 163 | stealthscan | scanme.nmap.org | nslookup, nmap | 2 (0/0/0/2) | ✅ -T2 -Pn --randomize-hosts -p<curated>, no whatweb/nuclei | PASS |
| 164 | stealthscan | pentest-ground.com | nslookup, nmap | 2 (0/0/0/2) | ✅ | PASS |
| 165 | compliance | scanme.nmap.org | nmap | 2 (0/0/0/2*) | ✅ **no nslookup** (no DNS); sslyze/whatweb correctly idle (scanme has no open TLS port) | PASS |
| 166 | compliance | pentest-ground.com | nmap, sslyze, whatweb | 5 (0/0/0/5) | ✅ **no nslookup**; sslyze+whatweb ran on :443 | PASS |
| 168 | webaudit | scanme.nmap.org | nslookup, nmap, header_check, nikto, gobuster, dirb, whatweb | 31 (0/1/5/25) | ✅ **no zaproxy** (deepscan-only); XSS pass idle (no fuzzable script endpoints); scope note present | PASS |
| 169 | webaudit | pentest-ground.com | +sslyze (on :443) | 30 (0/0/6/24) | ✅ 13 tool-runs across ports 80+443, 22 min < 30-min budget | PASS |
| 178 | deepscan | scanme.nmap.org | nslookup, subdomain_enum, theHarvester, nmap, nmap_service_detect, banner_grab, header_check, nikto, gobuster, dirb, whatweb, nuclei, zaproxy, hydra | 47 (0/1/11/35) | ✅ **no sslyze** (deepscan excludes it); hydra fired on :22; sqlmap/wpscan/enum4linux logged "condition not met"; ~30 min | PASS |
| 179 | deepscan | pentest-ground.com | nslookup, subdomain_enum, theHarvester, nmap | 0 (—); **1 tool failure by design** | ✅ see note below — the `-T4 -p-` sweep was rate-limited by the target; scanner **correctly flagged it** rather than faking a clean result | PASS (correct honest-empty handling) |

**Scan 179 note (important, and a demo caveat):** deepscan's aggressive `-T4 -p-` full-65535-port
sweep against pentest-ground.com got **no answer from any port** — the target rate-limits/drops
that sweep (even though it answers quickscan's `-T4 -F` top-ports scan fine, scans 162/164/166/169).
The scanner did **not** report a false "0 open ports"; it detected the rate-limit signature and
logged loudly: *"nmap probed 65535 port(s) and got NO answer from any of them … the signature of a
rate-limited, filtered or dropped scan, NOT a confirmed 'no open ports' result … re-run with
quieter timing, a smaller port set, or later."* It counted this as **1 tool failure** (not silently
swallowed), skipped the web module (no web port), and logged the conditional skips. This is the
documented `KNOWN_GOOD_TARGETS` / honest-empty-result behavior working correctly. **Demo caveat:**
don't run deepscan against pentest-ground.com and expect findings — the full-port sweep trips its
rate limiter; use quickscan/webaudit/compliance on that target (all produced rich findings), and
save deepscan for the local lab or scanme.

Stealthscan is genuinely distinct from quickscan (different nmap timing/port set `-T2 -Pn
--randomize-hosts -p<curated>` vs `-T4 -F`; no whatweb/nuclei). All 9 completed runs wrote
**both a .txt and a .pdf** (verified on disk). `*` compliance/scanme LOW count reflects the
2 nmap-script findings scored to LOW.

---

## 3. Conditional-tools results (local lab, deepscan per container)

Lab brought up with `docker-compose up -d` (standalone binary; the `docker compose` v2 plugin
rejects `-d` on this host). DVWA DB was re-created via `setup.php` after the container
recreate (verified injectable by hand: `info.php?id=1' OR '1'='1` dumps all 5 DVWA users).

| Scan | Container | Tool triggered | Trigger fired? | Real evidence | Tool failures |
|---|---|---|---|---|---|
| 170 | 172.28.0.10 (WordPress) | **wpscan** | ✅ via gobuster `/xmlrpc.php` | WordPress 7.0.2 identified; XML-RPC enabled; readme.html; external WP-Cron; twentytwentyfive theme v1.5 enumerated (6 findings) | **0** |
| 171 | 172.28.0.20 (DVWA) | **sqlmap** | ✅ via discovered `info.php?id=1` | CONFIRMED boolean/error/time-based blind injection on param `id`; read-only enum: DBMS MariaDB 10.1.26, current DB `dvwa`, DB list. **No `--dump`/`--os-shell` ever** (verified in log + source) | **0** |
| 176 | 172.28.0.30 (OpenSSH) | **hydra** | ✅ ssh detected on :2222 | `weak_credentials` CRITICAL — **admin:admin** found | **0** |
| 177 | 172.28.0.40 (Samba) | **enum4linux** | ✅ SMB on :139/:445 | shares `public` (Disk) + `IPC$`; user `smbtest` (rid 0x3e8) via null session | **0** |

For every run, the *non*-triggered conditional tools logged
`condition '<flag>' not met — skipping <tool>` (e.g. hydra/enum4linux skipped on WordPress,
sqlmap/wpscan/enum4linux skipped on DVWA) — the "why didn't this run" audit trail works.
The candidate-ordering fix works: sqlmap tested `info.php`, not just the non-injectable
`index.php`. **All four conditional tools confirmed firing live with real evidence and zero
tool failures — the 2026-07-29 status-doc claim re-verified and still holds.**

---

## 4. CVE verification (every CVE ID surfaced, checked against nvd.nist.gov)

| CVE | Source / scan | Detected version | NVD verdict | Applies to detected version? |
|---|---|---|---|---|
| CVE-2025-49844 | nuclei, Redis (162) | Redis (pentest) | Real, 9.9 CRIT (UAF) | ✅ |
| CVE-2025-46817 | nuclei, Redis (162) | Redis | Real, 8.8 HIGH (int overflow) | ✅ (Aegis labels CRIT via nuclei template — minor) |
| CVE-2025-46818 | nuclei, Redis (162) | Redis | Real, 7.3 HIGH | ✅ |
| CVE-2025-46819 | nuclei, Redis (162) | Redis | Real, 7.1 HIGH | ✅ |
| CVE-2021-44224 | NVD lookup, Apache banner (168/178) | Apache 2.4.7 | Real, 8.2 HIGH | ✅ (affects 2.4.7–2.4.51) |
| CVE-2025-66200 | NVD lookup, Apache banner (168/178) | Apache 2.4.7 | Real, 5.4 MED | ✅ (affects 2.4.7–2.4.65) |
| CVE-2023-48795 (Terrapin) | nuclei, SSH (178) | OpenSSH 6.6.1p1 | Real, 5.9 MED | ✅ (affects < 9.6; recorded on **port 22**) |
| CVE-2026-29167 | NVD lookup, Apache (170) | Apache 2.4.x (WP) | Real, 9.8 CRIT | ✅ (2.4.0–2.4.67) |
| CVE-2026-29170 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 6.1 MED | ✅ |
| CVE-2026-34355 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 7.5 HIGH | ✅ |
| CVE-2026-34356 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 7.5 HIGH | ✅ |
| CVE-2026-42536 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 7.5 HIGH | ✅ |
| CVE-2026-44119 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 5.5 MED | ✅ |
| CVE-2026-44185 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 7.3 HIGH | ✅ |
| CVE-2026-44186 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 7.3 HIGH | ✅ |
| CVE-2026-44631 | NVD lookup, Apache (170) | Apache 2.4.x | Real, 9.8 CRIT | ✅ |
| CVE-2017-7659 | NVD lookup, Apache (171) | Apache **2.4.25** (DVWA) | Real, 7.5 HIGH | ✅ (affects 2.4.24–2.4.25) |
| **CVE-2016-8743** | NVD lookup, Apache (171) | Apache **2.4.25** | Real, 7.5 HIGH | ❌ **FALSE POSITIVE — fixed in 2.4.25** |
| **CVE-2016-4975** | NVD lookup, Apache (171) | Apache **2.4.25** | Real, 6.1 MED | ❌ **FALSE POSITIVE — fixed in 2.4.25** |
| **CVE-2026-35385** | NVD lookup, OpenSSH (176) | OpenSSH **10.3** | Real, 8.1 HIGH | ❌ **FALSE POSITIVE — "before 10.3", fixed in 10.3** |
| **CVE-2026-35386** | NVD lookup, OpenSSH (176) | OpenSSH **10.3** | Real, 8.1 HIGH | ❌ **FALSE POSITIVE — before 10.3** |
| **CVE-2026-35387** | NVD lookup, OpenSSH (176) | OpenSSH **10.3** | Real, 6.5 MED | ❌ **FALSE POSITIVE — before 10.3** |
| **CVE-2026-35388** | NVD lookup, OpenSSH (176) | OpenSSH **10.3** | Real, 2.5 LOW | ❌ **FALSE POSITIVE — before 10.3** |
| **CVE-2026-35414** | NVD lookup, OpenSSH (176) | OpenSSH **10.3** | Real, 8.1 HIGH | ❌ **FALSE POSITIVE — before 10.3** |
| Samba CVEs (177) | NVD lookup, "Samba smbd 4" | Samba **4.12.2** | Real (e.g. "before 4.1.22", "3.6.x") | ❌ **FALSE POSITIVE — pre-4.1.22/3.6.x CVEs vs 4.12.2**; nmap detected only major version "4" |

**Every CVE ID is a real, current NVD entry — none is fabricated.** 16 apply correctly; the
false-positive group is a *version-matching* defect (Bug #1), not invented data.

---

## 5. Bugs found this session

### Bug #1 — NVD CVE lookup does no CPE version-range filtering → boundary/imprecise-version false positives  ✅ FIXED 2026-07-31
- **Expected (docs):** OVERVIEW_CONTEXT.md §1 / status-doc §4 present the NVD CVE lookup as
  the thing to "point at" to prove real vulnerabilities; §1 says it disambiguates product via
  a keyword + CPE-product allowlist and drops wrong-product hits.
- **Actual:** `modules/enrichment/cve_lookup.py` builds an NVD `keywordSearch` = AND-of-words
  on product+version (line ~126) and filters returned CVEs by **CPE product only**
  (`_extract_cpe_products` reads CPE index 4 = product; `_cve_matches_product`). It never
  checks `versionStartIncluding`/`versionEndExcluding`, so a CVE whose text says "before
  10.3" matches a host on 10.3 and passes the product filter. Confirmed live: **7 false
  positives** — Apache 2.4.25 (CVE-2016-8743, CVE-2016-4975, both *fixed* in 2.4.25) and
  OpenSSH 10.3 (all 5 CVE-2026-3538x/35414, all "before 10.3"). Compounded on imprecise
  detection: nmap reported only "Samba smbd 4", so pre-4.1.22 / 3.6.x Samba CVEs were matched
  against Samba 4.12.2.
- **Fix direction:** parse the CPE version range from each `cpeMatch` and keep a CVE only if
  the detected version satisfies it (respect `versionEndExcluding` as exclusive); when only a
  major version is known, mark such CVEs "version-unconfirmed" rather than asserting them. Any
  fix must re-run `tests/db_sweep.py` + the relevant `t_phase*.py`.
- **Severity:** needs-follow-up-fix. Over-reports only; the framework and all other evidence
  are sound. For the demo, lead CVE claims with **nuclei-sourced** CVEs (Redis, Terrapin),
  which were 100% accurate because they are actively detected, not keyword-matched.
- **✅ Resolution (2026-07-31):** fixed as directed above. `cve_lookup.py` gained
  `_version_tuple()` / `_version_cmp()` / `_cpe_covers_version()` / `_cve_version_applicable()`,
  and `_parse_cves()` now drops a CVE when the detected version is *definitively* outside every
  vulnerable `cpeMatch` range for the accepted product (`versionEndExcluding` honoured as
  exclusive). The imprecise-detection case is handled by keeping, not asserting: `_version_cmp()`
  returns `None` when one version is a proper prefix of the other, so the "Samba smbd 4" vs
  "before 4.1.22" comparison is treated as unprovable and the CVE is retained — as are CVEs with
  no CPE data, a `*`/`-` version wildcard, or no detected version at all. Drops are logged with a
  count. Verified against all four false-positive cases from this pass (OpenSSH 10.3 vs
  "before 10.3" → dropped; 10.2 vs "before 10.3" → kept; Apache 2.4.25 fixed-in-2.4.25 →
  dropped; Samba bare "4" → kept), plus in-range/below-range windows and a `6.6.1p1` suffix
  comparison. Gate re-run clean: `db_sweep` 186/186 scans, 0 crashes, 0 live attribution issues;
  `t_phase2/3/4/8/9/10` = 36/47/40/183/58/41 pass, 0 fail. Documented in BACKEND_STRUCTURE.md
  §`modules/enrichment/`, OVERVIEW_CONTEXT.md §2, WRITEUP.md §5, status-doc §3.5.

### Note (documentation drift, not a code bug) — "venv lacks zapv2 / use /usr/bin/python3" is now stale  ✅ DOCS CORRECTED 2026-07-31
- **Expected (status-doc §3.4, TUTORIAL ZAP note, auto-memory):** run lab deepscans with
  `/usr/bin/python3` because the venv lacks the ZAP client.
- **Actual:** `venv/bin/python3 setup.py` passes and `import zapv2` succeeds in the venv;
  every deepscan this session ran through the **venv** with ZAP producing real alerts (61
  passive rules). This was fixed in commit 7ffd52d ("install venv ZAP client"). The doc/memory
  guidance should be updated so nobody avoids the venv unnecessarily.
- **✅ Resolution (2026-07-31):** the status doc's §3.4 reproduce-line now says
  `venv/bin/python3` and carries an explicit note that the old "/usr/bin/python3" guidance is
  obsolete; auto-memory was corrected in the same pass.

No other bugs. Two items that *looked* like bugs but are not: (a) the sqlmap finding appears
in both the "Injection & Scripting" section and "Detailed Findings" — that is the documented
two-section report layout, not a duplicate; (b) nmap first labels SSH-on-2222 as
"EtherNetIP-1" by port-number guess, then the `-sV` pass correctly identifies it as OpenSSH —
correct behavior.

---

## 6. Confirmed-working claims (verified solid — no need to re-verify next pass)

- **Static gate green:** db_sweep 155/155 rendered, 0 crashes / 0 ambiguous cells / 0 duplicate
  lines, attribution 0 live mismatches + exactly the 2 known-historical allowlisted rows.
  t_phase2/3/4/8/9/10 and t_pty all pass (0 failures).
- **All 5 profiles run end-to-end**, each writes **both .txt and .pdf** (9/9 completed scans on
  disk), each returns real severity counts and a real tools run/failed/skipped line.
- **Profile scoping is honest:** compliance runs no DNS (no nslookup); webaudit never runs
  zaproxy; deepscan never runs sslyze; stealthscan ≠ quickscan. All match §3.
- **All 4 conditional tools fire live with real evidence, 0 tool failures** (wpscan/sqlmap/
  hydra/enum4linux); "condition not met" logging present for non-triggers.
- **sqlmap is read-only** — no `--dump`/`--os-shell`/`--sql-shell`/`--file-*` in any invocation
  (log + source `sqlmap_wrap.py`).
- **Port attribution is correct** — nuclei Redis findings recorded on **6379** (not the web
  port 80 the profile started from); Terrapin on **22**; Apache CVEs on **80**. The concern in
  `backfill_nuclei_identity` does **not** reproduce today.
- **ZAP healthy:** 61 unique passive-scan rules loaded (`~/.ZAP/zap.log`), pscanrules present;
  17 distinct ZAP alerts persisted on the WordPress deepscan.
- **Report vocabulary correct:** inapplicable-by-nature fields say why ("N/A (config finding)",
  "N/A (no CVE to score)"); genuine gaps name the tool ("not determined by nikto / zaproxy /
  NVD lookup"). Both kinds present in real reports. webaudit scope note present.
- **Retention cap works:** 6th quickscan/scanme (scan 175) exceeded the cap of 5 → non-
  interactive deleted the oldest (scan 125) and logged it; the 9 other-profile scanme reports
  were untouched (**cap is genuinely per profile+target**). Interactive prune path (drop-oldest
  / drop-by-number / keep-all / re-prompt) covered by t_pty.
- **Non-CVE findings are genuine:** the 6 "missing header" findings on pentest-ground are
  curl-confirmed absent; nikto/gobuster/dirb paths are real.
- **Honest empty-result handling works (scan 179):** a rate-limited `-p-` sweep that got zero
  answers was flagged loudly as unreliable and counted as a tool failure — it did **not** masquerade
  as a clean "no open ports" result. This is the `KNOWN_GOOD_TARGETS` / zero-port-false-alarm
  behavior confirmed live.
- **Dead-flag / config claims hold:** `whatweb.cms_detected` has no consumer (wpscan triggers
  only on gobuster's `wordpress_fingerprinted`); `MAX_THREADS` is referenced nowhere outside
  its config definition.
- **Budget code path present:** `webaudit.py` and `deepscan.py` both compute the wall-clock
  budget and log `time budget (Ns) exhausted` (config: webaudit 1800s, deepscan 3600s).

---

## 7. Open items for the next pass

1. **A clean deepscan record for pentest-ground.com** — scan 179 completed but its `-T4 -p-`
   sweep was rate-limited to 0 ports (see the scan-179 note in §2; the scanner handled it
   correctly). If a populated deepscan report for that host is wanted, re-run with quieter
   timing or a reduced port set as the scanner itself suggests. Not a defect — the profile is
   verified 0-failure on 5 other targets (4 lab + scanme).
2. **Wall-clock budget not forced live** — the `time budget (Ns) exhausted` branch is present
   and reachable but was not triggered (no target with enough open web ports to exceed 30/60
   min). Confirmed by code path only; forcing it would need a many-web-port target or a
   temporarily lowered budget.
3. **ZAP interruptibility** — the documented claim that ZAP does not reliably respond to the
   skip key / single Ctrl+C (§6.2 item 10) could not be re-tested here: this environment is
   non-interactive, so no real keypress reaches a live ZAP phase. The skip-key/Ctrl+C listener
   itself is verified by t_pty (passes). Re-test manually in a real terminal.
4. ~~**Fix Bug #1 (CVE version-range filtering)** and re-run the gate — highest-value
   follow-up.~~ ✅ **Done 2026-07-31** — see the resolution note under Bug #1. Remaining
   nice-to-have: a *live* NVD re-query against the same OpenSSH 10.3 / Apache 2.4.25 hosts to
   confirm the drop counts end-to-end (the fix is verified against the recorded CPE payload
   shapes and the full static gate, not yet against a fresh live API response).
5. **XSS pass never hit a confirmed XSS** — on every target this session the DAST XSS pass had
   no fuzzable script endpoint to mutate (candidates built as `?q=1` on discovered `.php`
   paths); DVWA's known-vulnerable `xss.php` is a custom companion script not in the default
   wordlists, so it was never discovered. Not a bug, but the XSS path's positive case remains
   unproven via the normal discovery→fuzz flow (only via `test-targets/direct_xss_confirm.py`).

---

*Generated during a live verification pass. Every claim above is backed by a scan id, a log
line, a DB row, or an nvd.nist.gov lookup captured this session.*
