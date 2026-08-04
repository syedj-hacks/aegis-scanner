# Aegis Scanner
Kali Linux vulnerability assessment framework — 

## Setup
```bash
git clone https://github.com/syedj-hacks/aegis-scanner.git
cd aegis-scanner
chmod +x install.sh
./install.sh
source venv/bin/activate
```

## Usage
```bash
python3 aegis.py <target> [--profile PROFILE] [-v]
```

Run it with no arguments for a guided menu:

```
1. Vulnerability scan   pick a profile and scan a host
2. Recon mapper         map what a domain or company name exposes (passive)
3. Scan diff            compare two finished scans
```

Any argument at all skips the menu, so every existing command line behaves
exactly as before.

### Profiles

| Profile | Description |
|---|---|
| `quickscan` (default) | Fast overview — DNS, top-port nmap scan, service detection, quick whatweb + high-severity nuclei check. |
| `stealthscan` | Quiet -T2 scan of common ports — minimal footprint. One whatweb fingerprint; deliberately no nuclei. |
| `webaudit` | Web-focused audit — headers, Nikto, gobuster/dirb, whatweb, sslyze + CVE enrichment on web ports. |
| `deepscan` | Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports. |
| `compliance` | TLS cipher + HTTP header nmap scripts, sslyze and whatweb on TLS ports for a compliance-oriented baseline. |
| `recon` | Passive attack-surface map — certificate transparency, subdomains, OSINT, public cloud buckets, breach check. Sends nothing to the target. |

Example:
```bash
python3 aegis.py 192.168.56.101 --profile deepscan
```

### Recon mapper

The only mode that accepts a **company name** as well as a domain, because
it never contacts the target — everything it reads is public (crt.sh
certificate logs, DNS aggregators, cloud storage namespaces, Have I Been
Pwned).

```bash
python3 aegis.py example.com --recon      # domain mode: full pipeline
python3 aegis.py --recon "Acme Corp"      # company mode: OSINT + buckets only
```

With a bare company name there is no domain to resolve, so DNS, certificate
transparency and subdomain enumeration are reported as *not applicable*
rather than run and failed.

The breach check needs an API key (HIBP has required one since 2019). Set
`AEGIS_HIBP_API_KEY` in `.env` to enable it. **Without a key the check
reports itself as NOT RUN — it does not report accounts as clean**, because
a false all-clear is the one output someone would act on by doing nothing.

### Scan diff

```bash
python3 aegis.py --diff 41 57             # compare two finished scans
python3 aegis.py --diff 41 57 --diff-verbose
```

Every scan also prints a one-line delta against the previous scan of the
same target automatically.

Findings are classified `new` / `fixed` / `escalated` / `unchanged` — and
`unverified`, which is the one that matters: if the tool that would have
found a finding did not run in the later scan, its absence proves nothing
and it is **not** counted as fixed.

### Live dashboard

```bash
python3 aegis.py scanme.nmap.org --live   # or answer the prompt
```

Opens a browser view that fills in as the scan runs — current tool, progress,
and findings appearing newest-first. It is served from `127.0.0.1` on a
random port (a `file://` page cannot poll for data; browsers block it), and
it stops when the command exits.

Every scan writes a self-contained `report.html` alongside the TXT and PDF —
sortable and filterable, no external resources, safe to email or open offline.

Run from the repo root (paths for `output/`, `database/aegis.db`, and `.env`
are all resolved relative to it). Each scan is recorded in
`database/aegis.db`; reports are written to `output/<target>/`.

`aegis.py --help` lists all flags, and `aegis.py --version` prints the
current version.

## Documentation
All project documentation lives in [`important documentations/`](important%20documentations/):

| File | What it covers |
|---|---|
| `TUTORIAL.md` | Start here — install, first scan, reading a report. |
| `COMMANDS.txt` | Every command, flag, and maintenance/one-off tool invocation. |
| `OVERVIEW_CONTEXT.md` | Repo map, module-by-module API surface, data flow. |
| `BACKEND_STRUCTURE.md` | Internals: every wrapper's contract, the shared conventions, known gaps. |
| `WRITEUP.md` | Design decisions and honesty notes — why things work the way they do. |
| `aegis_scanner_status_and_capabilities.txt` | Plain-language status: what is verified live, what isn't, demo guidance. |

`smoke_test/` holds the per-pass live verification write-ups, and
`test-targets/` is a local, isolated docker lab of intentionally vulnerable
services used to exercise the conditional tools (wpscan/sqlmap/hydra/enum4linux).
