# Phase 6 — Live Smoke Test Results

Run 2026-09-12 against the BlackBox / Aegis docker lab, scanning each
container on its **native port via its docker IP** (the containers publish
on non-standard host ports — DVWA 8082, WordPress 8081, SSH 2222 — but
listen on standard ports internally, so the container IP is what lets nmap
find them normally).

| Container            | Address (scanned) | Reachable |
|----------------------|-------------------|-----------|
| aegis-dvwa-target    | 172.28.0.20:80    | yes       |
| aegis-wordpress-target | 172.28.0.10:80  | yes       |
| aegis-ssh-target     | 172.28.0.30:2222  | yes       |
| aegis-smb-target     | 172.28.0.40:445   | yes       |
| aegis-juice          | 172.17.0.2:3000   | **no** (default-bridge, unroutable from scan host in this run) |
| webgoat              | 172.17.0.3:8080   | **no** (same)  |

## 1. Did it complete without crashing? — YES

Every scan returned exit code 0. The engine full scan across all six
targets (`--targets ... --engine --scan-profile full`) completed with no
crash; unreachable targets (juice/webgoat) produced empty scans, not
failures, and the reachable ones were unaffected — the per-target
isolation held.

## 2. Do plugins load correctly? — YES

`--list-plugins` reports 22 plugins (19 Python + 3 signatures), 0 load
errors. The engine ran discovery → web → service → passive stages against
every target.

## 3. Findings include CVSS + EPSS enrichment? — YES

Enrichment stats for today's engine scans (scan ids 240–246):

| Scan | Target | Findings | with CVSS | with EPSS | Confirmed | Potential |
|------|--------|----------|-----------|-----------|-----------|-----------|
| 240/241 | DVWA (172.28.0.20)   | 50 | 11 | 1  | 49 | 1  |
| 242 | SSH (172.28.0.30)        | 3  | 1  | 0  | 3  | 0  |
| 243 | WordPress (172.28.0.10)  | 80 | 13 | 0  | 75 | 5  |
| 244 | SMB/Samba (172.28.0.40)  | 21 | 16 | **16** | 5 | 16 |
| 245 | Juice (unreachable)      | 0  | 0  | 0  | 0  | 0  |
| 246 | WebGoat (unreachable)    | 0  | 0  | 0  | 0  | 0  |

Example fully-enriched finding (SMB host, from the JSON/SARIF output):

    CVE-2015-0240 (Samba)  CVSS 10.0  EPSS 0.876  combined risk 9.38  confidence: Potential

Environment Risk Score for the SMB host: **66.6 / 100 (High)**.

## 4. PDF / JSON / SARIF all generate? — YES

Every engine scan wrote all four report files, e.g. for the SMB host:

    report_Full_Scan_172.28.0.40_244.txt
    report_Full_Scan_172.28.0.40_244.pdf
    report_Full_Scan_172.28.0.40_244.json
    report_Full_Scan_172.28.0.40_244.sarif

SARIF validated as 2.1.0 (4 rules, 21 results, per-result rank from risk
score, EPSS in properties, stable finding fingerprints). JSON carries the
schema version, environment risk block, top-5 risks and full-fidelity
findings.

## 5. Was any service knocked offline? (throttling safety) — NO

Liveness of every reachable target, before vs after the full run:

| Target            | Before | After |
|-------------------|--------|-------|
| DVWA 172.28.0.20  | 302    | 302   |
| WP 172.28.0.10    | 200    | 200   |
| SSH 172.28.0.30   | OPEN   | OPEN  |
| SMB 172.28.0.40   | OPEN   | OPEN  |

Nothing was taken down. (juice/webgoat read DOWN in *both* the before and
after snapshots — they were unroutable for the entire run, so this is not a
scan-caused outage.)

## Before / After comparison

**Scan time (same target, DVWA, same host):**

| | Legacy `deepscan` | Engine `--scan-profile full` |
|---|---|---|
| Wall time | **601 s** | **400 s** |

The engine is ~33 % faster **while doing more** — it runs the same web
toolset concurrently AND adds the CVSS/EPSS/risk/confidence enrichment the
legacy profile does not.

**Finding count (DVWA):** legacy 55 vs engine 50 — comparable coverage of
the same host (see the known gap below for the difference).

**Detection quality (new):** the engine labels every finding
Confirmed/Potential (legacy sets neither) and attaches EPSS to CVE
findings. Across the engine scans: **181 Confirmed, 23 Potential.** The 23
Potential are version-matched CVEs (Samba on the SMB host, Apache
CVE-2016-8743 on DVWA) — exactly the findings that would be false-positive
risk if reported with the same confidence as an exercised vulnerability.
That is the false-positive discipline the confidence label buys.

## Bugs the smoke test caught (and fixed)

A smoke test earns its keep by finding what unit tests can't. This one did:

1. **CVE findings from the engine were mistyped `plugin_finding`.** The
   Samba host's 16 version-matched CVEs persisted with `finding_type =
   plugin_finding` instead of `cve`, because `Finding.from_legacy` did not
   apply the same "no type but has a cve_id ⇒ cve" inference that
   `db.py.insert_finding` does, and `to_db_dict`'s `plugin_finding` default
   fired first. Fixed in `plugins/base.py`; a re-scan (scan 247) now types
   all 16 as `cve`.
2. **Attribution didn't understand engine tool records.** The engine records
   the *plugin* name (`service_detect`, `port_scan`) in `scan_tools_run`,
   but the attribution model expected *tool* names (`nmap`), so every
   engine `service_version`/`cve` finding was flagged "tool never ran".
   Fixed by aliasing the plugin names to their producers and registering the
   engine YAML profiles + the `signature` producer in
   `modules/reporting/attribution.py`. Scan 247 now attributes with zero
   mismatches.
3. **The active-validation note wasn't persisted.** Added a `validation`
   column so the live banner-corroboration string reaches the reports.

All three are covered by the existing attribution/enrichment suites, which
are green.

## Known gaps (for the README)

1. **The engine has no sqlmap / XSS / nmap-NSE plugin yet.** The legacy
   `deepscan` confirmed one SQL injection on DVWA (a `sqlmap_finding`) and
   ran NSE scripts; the engine full profile did not, because those checks
   are not yet ported to the plugin layer. The engine currently trades
   active injection *confirmation* for speed + enrichment. This is the main
   detection gap between the two paths.
2. **DVWA's flagship application vulns** (stored/reflected XSS, command
   injection, CSRF, insecure file upload) require an authenticated
   low-security session and payloads tailored to the app; neither path
   confirms them without the auth cookie and the injection plugins above.
3. **OWASP Juice Shop & WebGoat were not scanned** in this run — they sat on
   the default docker bridge and were unroutable from the scan host
   (confirmed DOWN before *and* after). Their known CVE-rich stacks are
   therefore absent from these results for an environmental reason, not a
   detection one; re-run with the containers on the reachable
   `172.28.0.0/24` network to include them.
4. **SSH (OpenSSH 10.3)** matched no CVEs — correctly: the container runs a
   current OpenSSH and the version-range guard filtered the candidates
   rather than over-reporting.
